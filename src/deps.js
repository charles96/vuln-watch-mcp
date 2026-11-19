import { readFile, stat, readdir } from "node:fs/promises";
import { join, basename, relative, dirname } from "node:path";
import { parse as parseToml } from "smol-toml";
import { resolveLocalPom, parsePomXml } from "./maven.js";
import { parseGradleBuild } from "./gradle.js";

/**
 * Dependency collection across ecosystems.
 * Each dependency: { name, version, ecosystem, dev, direct (true|false|null), source, versionSource, declared? }
 * versionSource:
 *   lockfile  – exact version from a lockfile / resolved graph file
 *   installed – exact version read from installed packages (node_modules)
 *   manifest  – exact pin in a manifest (==, exact version)
 *   resolved  – computed (Maven/Gradle transitive resolution, BOM-managed version)
 *   range     – lower bound of a version range (estimate; may be a false positive)
 */

const SKIP_DIRS = new Set([
  "node_modules", ".git", "vendor", "dist", "build", "out", ".venv", "venv", "env", "target",
  "__pycache__", ".next", ".nuxt", "bin", "obj", ".gradle", ".idea", ".vscode", "coverage", ".tox",
  ".dart_tool", "_build", "deps", ".build", "Pods", "DerivedData", "renv",
]);

async function listFiles(dir, depth) {
  const out = [];
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const e of entries) {
    const p = join(dir, e.name);
    if (e.isFile()) out.push(p);
    else if (e.isDirectory() && depth > 0 && !SKIP_DIRS.has(e.name) && !e.name.startsWith(".")) {
      out.push(...(await listFiles(p, depth - 1)));
    }
  }
  return out;
}

const readText = (f) => readFile(f, "utf8");
const readJson = async (f) => JSON.parse(await readText(f));
const exists = (f) => stat(f).then(() => true, () => false);

/** Is there a file named one of `names` in dir's ancestors (up to root)? */
async function ancestorHas(dir, root, names) {
  let d = dirname(dir);
  while (!relative(root, d).startsWith("..") && d !== dirname(d)) {
    for (const n of names) if (await exists(join(d, n))) return true;
    if (d === root) break;
    d = dirname(d);
  }
  return false;
}

/** Scan a directory (optionally recursive) or a single manifest file. */
export async function collectDependencies(target, { includeDev = false, recursive = false, maxDepth = 4, transitive = true } = {}) {
  const st = await stat(target);
  const root = st.isDirectory() ? target : dirname(target);
  const files = st.isDirectory() ? await listFiles(target, recursive ? maxDepth : 0) : [target];

  const byDir = new Map();
  for (const f of files) {
    const d = dirname(f);
    if (!byDir.has(d)) byDir.set(d, []);
    byDir.get(d).push(f);
  }

  // Maven reactor modules (so internal modules are not looked up on Maven Central)
  const mavenModules = new Set();
  for (const f of files.filter((f) => basename(f) === "pom.xml")) {
    try {
      const r = parsePomXml(await readText(f));
      mavenModules.add(`${r.g || r.parent?.g}:${r.a}`);
    } catch {
      /* ignore */
    }
  }

  const deps = [];
  const manifests = [];
  const notes = [];
  for (const [dir, list] of byDir) {
    const has = (n) => list.find((f) => basename(f) === n);
    const rel = (f) => relative(root, f) || basename(f);
    const run = async (file, fn, label) => {
      try {
        const got = await fn(file);
        const arr = Array.isArray(got) ? got : got.deps;
        arr.forEach((d) => (d.source = rel(file)));
        deps.push(...arr);
        manifests.push(label ? `${rel(file)} (${label})` : rel(file));
        if (got.notes) notes.push(...got.notes.map((n) => `${rel(file)}: ${n}`));
      } catch (err) {
        manifests.push(`${rel(file)} (parse error: ${err.message})`);
      }
    };
    const opts = { includeDev, transitive };

    // ---------- JavaScript ----------
    const pkgJson = has("package.json");
    const directNpm = pkgJson ? await npmDirectSets(pkgJson) : null;
    const npmLock = has("package-lock.json") || has("npm-shrinkwrap.json");
    if (npmLock) await run(npmLock, (f) => parsePackageLock(f, includeDev));
    else if (has("pnpm-lock.yaml")) await run(has("pnpm-lock.yaml"), (f) => parsePnpmLock(f, directNpm, includeDev));
    else if (has("yarn.lock")) await run(has("yarn.lock"), (f) => parseYarnLock(f, directNpm, includeDev));
    else if (has("bun.lock")) await run(has("bun.lock"), (f) => parseBunLock(f, includeDev));
    else if (pkgJson && !(await ancestorHas(dir, root, ["package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock"]))) {
      if (await exists(join(dir, "node_modules"))) await run(pkgJson, () => parseNodeModules(dir, directNpm, includeDev), "installed node_modules");
      else await run(pkgJson, (f) => parsePackageJson(f, includeDev), "no lockfile: versions estimated from ranges");
    }

    // ---------- Python ----------
    const pyLock = ["poetry.lock", "uv.lock", "pdm.lock", "pylock.toml", "Pipfile.lock"].find(has);
    if (has("poetry.lock")) await run(has("poetry.lock"), (f) => parsePoetryLock(f, includeDev));
    if (has("uv.lock")) await run(has("uv.lock"), parseUvLock);
    if (has("pdm.lock")) await run(has("pdm.lock"), parsePdmLock);
    if (has("pylock.toml")) await run(has("pylock.toml"), parsePylock);
    if (has("Pipfile.lock")) await run(has("Pipfile.lock"), (f) => parsePipfileLock(f, includeDev));
    for (const f of list) if (/^requirements.*\.(txt|in)$/i.test(basename(f)) && !(pyLock && /\.in$/.test(f))) await run(f, (x) => parseRequirements(x, new Set()));
    if (!pyLock && has("pyproject.toml") && !list.some((f) => /^requirements.*\.txt$/i.test(basename(f)))) await run(has("pyproject.toml"), (f) => parsePyproject(f, includeDev));

    // ---------- Go ----------
    if (has("go.mod")) await run(has("go.mod"), parseGoMod);

    // ---------- Rust ----------
    if (has("Cargo.lock")) await run(has("Cargo.lock"), parseCargoLock);
    else if (has("Cargo.toml") && !(await ancestorHas(dir, root, ["Cargo.lock"]))) await run(has("Cargo.toml"), (f) => parseCargoToml(f, includeDev), "no lockfile: versions estimated");

    // ---------- PHP ----------
    if (has("composer.lock")) await run(has("composer.lock"), (f) => parseComposerLock(f, includeDev));
    else if (has("composer.json")) await run(has("composer.json"), (f) => parseComposerJson(f, includeDev), "no lockfile: versions estimated");

    // ---------- Ruby ----------
    if (has("Gemfile.lock")) await run(has("Gemfile.lock"), parseGemfileLock);
    else if (has("Gemfile")) await run(has("Gemfile"), (f) => parseGemfile(f, includeDev), "no lockfile: versions estimated");

    // ---------- Java / Kotlin ----------
    if (has("gradle.lockfile")) await run(has("gradle.lockfile"), (f) => parseGradleLockfile(f, includeDev));
    else {
      for (const n of ["build.gradle", "build.gradle.kts"]) {
        if (has(n)) {
          await run(has(n), async (f) => {
            const r = await parseGradleBuild(f, root, opts);
            const notesG = [];
            if (r.boms.length) notesG.push(`BOMs: ${r.boms.map((b) => `${b.g}:${b.a}:${b.v}`).join(", ")}`);
            if (r.unresolved.length) notesG.push(`versions not resolvable (skipped): ${r.unresolved.slice(0, 15).join(", ")}${r.unresolved.length > 15 ? ", …" : ""}`);
            return { deps: r.deps, notes: notesG };
          }, transitive ? "resolved incl. transitive via Maven Central" : null);
        }
      }
    }
    if (has("pom.xml")) {
      await run(has("pom.xml"), async (f) => {
        const r = await resolveLocalPom(f, { ...opts, modules: mavenModules });
        const notesM = r.unresolved.length ? [`versions not resolvable (skipped): ${r.unresolved.slice(0, 15).join(", ")}`] : [];
        return {
          deps: r.deps.map((x) => ({ name: `${x.g}:${x.a}`, version: x.v, ecosystem: "maven", dev: Boolean(x.dev), direct: x.depth === 0, versionSource: x.depth === 0 ? "manifest" : "resolved" })),
          notes: notesM,
        };
      }, transitive ? "parent/BOM + transitive resolved via Maven Central" : "parent/BOM resolved");
    }

    // ---------- .NET ----------
    const assets = join(dir, "obj", "project.assets.json");
    if (has("packages.lock.json")) await run(has("packages.lock.json"), parseNugetLock);
    else if (list.some((f) => /\.(cs|fs|vb)proj$/i.test(f)) && (await exists(assets))) await run(assets, (f) => parseProjectAssets(f), "restored graph");
    else {
      const cpm = await centralPackageVersions(dir);
      for (const f of list) if (/\.(cs|fs|vb)proj$/i.test(f)) await run(f, (x) => parseMsbuild(x, cpm), cpm.size ? "central package management" : null);
      if (has("packages.config")) await run(has("packages.config"), (f) => parsePackagesConfig(f, includeDev));
    }

    // ---------- Dart / Flutter ----------
    if (has("pubspec.lock")) await run(has("pubspec.lock"), (f) => parsePubspecLock(f, includeDev));

    // ---------- Elixir ----------
    if (has("mix.lock")) await run(has("mix.lock"), parseMixLock);

    // ---------- Swift ----------
    if (has("Package.resolved")) await run(has("Package.resolved"), parsePackageResolved);

    // ---------- R ----------
    if (has("renv.lock")) await run(has("renv.lock"), parseRenvLock);
  }

  // de-duplicate (prefer exact sources; keep "direct" if any occurrence is direct)
  const rank = { lockfile: 0, installed: 1, manifest: 2, resolved: 3, range: 4 };
  const map = new Map();
  for (const d of deps) {
    if (!d.version || (d.dev && !includeDev)) continue;
    d.versionSource ||= "lockfile";
    const k = `${d.ecosystem}:${d.name.toLowerCase()}@${d.version}`;
    const prev = map.get(k);
    if (!prev) map.set(k, d);
    else {
      if (d.direct === true) prev.direct = true;
      if (!d.dev) prev.dev = false;
      if ((rank[d.versionSource] ?? 9) < (rank[prev.versionSource] ?? 9)) prev.versionSource = d.versionSource;
    }
  }
  return { deps: [...map.values()], manifests, notes };
}

// ---------------- helpers ----------------

/** Lower bound of a version range/spec, or null (git/path/url/wildcard). */
export function lowerBound(v) {
  if (!v || typeof v !== "string") return null;
  if (/^(file|link|git|github|http|https|workspace|npm|portal|patch|path):/.test(v) || /^[*x]$|latest|^\s*$/.test(v)) return null;
  const m = v.match(/\d+(\.\d+){0,3}([-.][0-9A-Za-z.]+)?/);
  return m ? m[0] : null;
}
const isExact = (v) => /^\s*(==|=)?\s*v?\d+(\.\d+)*([-.+][0-9A-Za-z.]+)?\s*$/.test(v || "");
const verSrc = (spec) => (isExact(spec) ? "manifest" : "range");

// ---------------- npm ----------------

async function npmDirectSets(pkgFile) {
  try {
    const j = await readJson(pkgFile);
    return {
      prod: new Set(Object.keys({ ...j.dependencies, ...j.optionalDependencies, ...j.peerDependencies })),
      dev: new Set(Object.keys(j.devDependencies || {})),
    };
  } catch {
    return null;
  }
}

async function parsePackageJson(file, includeDev) {
  const j = await readJson(file);
  const out = [];
  const add = (obj, dev) => {
    for (const [name, range] of Object.entries(obj || {})) {
      const version = lowerBound(range);
      if (version) out.push({ name, version, ecosystem: "npm", dev, direct: true, declared: range, versionSource: verSrc(range) });
    }
  };
  add(j.dependencies, false);
  add(j.optionalDependencies, false);
  if (includeDev) add(j.devDependencies, true);
  return out;
}

/** Installed packages in node_modules (used when no lockfile exists). */
async function parseNodeModules(dir, direct, includeDev) {
  const out = [];
  const walk = async (nm, depth) => {
    if (depth > 6 || out.length > 5000) return;
    let entries;
    try {
      entries = await readdir(nm, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      if (!e.isDirectory() && !e.isSymbolicLink()) continue;
      if (e.name.startsWith(".")) continue;
      const dirs = e.name.startsWith("@") ? (await readdir(join(nm, e.name)).catch(() => [])).map((s) => join(e.name, s)) : [e.name];
      for (const n of dirs) {
        const pj = await readJson(join(nm, n, "package.json")).catch(() => null);
        if (!pj?.version) continue;
        const name = pj.name || n.replace(/\\/g, "/");
        const f = npmDirectFlag(name, direct, includeDev);
        const isTop = depth === 0;
        if (isTop && f.skip) continue;
        out.push({ name, version: pj.version, ecosystem: "npm", dev: isTop ? f.dev : false, direct: isTop ? f.direct : false, versionSource: "installed" });
        await walk(join(nm, n, "node_modules"), depth + 1);
      }
    }
  };
  await walk(join(dir, "node_modules"), 0);
  return out;
}

async function parsePackageLock(file, includeDev) {
  const lock = await readJson(file);
  const out = [];
  if (lock.packages) {
    const root = lock.packages[""] || {};
    const direct = new Set(Object.keys({ ...root.dependencies, ...root.optionalDependencies, ...root.devDependencies, ...root.peerDependencies }));
    for (const [path, info] of Object.entries(lock.packages)) {
      if (!path.includes("node_modules/") || !info.version || info.link) continue;
      const name = info.name || path.slice(path.lastIndexOf("node_modules/") + 13);
      if (info.dev && !includeDev) continue;
      out.push({ name, version: info.version, ecosystem: "npm", dev: Boolean(info.dev), direct: path === `node_modules/${name}` && direct.has(name) });
    }
  } else if (lock.dependencies) {
    const walk = (deps, depth) => {
      for (const [name, info] of Object.entries(deps || {})) {
        if (info.dev && !includeDev) continue;
        out.push({ name, version: info.version, ecosystem: "npm", dev: Boolean(info.dev), direct: depth === 0 ? null : false });
        walk(info.dependencies, depth + 1);
      }
    };
    walk(lock.dependencies, 0);
  }
  return out;
}

function npmDirectFlag(name, direct, includeDev) {
  if (!direct) return { direct: null, dev: false, skip: false };
  if (direct.prod.has(name)) return { direct: true, dev: false, skip: false };
  if (direct.dev.has(name)) return { direct: true, dev: true, skip: !includeDev };
  return { direct: false, dev: false, skip: false };
}

/** yarn.lock v1 (classic) and v2+ (berry). */
async function parseYarnLock(file, direct, includeDev) {
  const text = await readText(file);
  const out = [];
  for (const block of text.split(/\r?\n(?=\S)/)) {
    const [header, ...body] = block.split(/\r?\n/);
    if (!header || header.startsWith("#") || header.startsWith("__metadata")) continue;
    const firstSpec = header.replace(/:$/, "").split(",")[0].trim().replace(/^"|"$/g, "");
    const at = firstSpec.indexOf("@", 1);
    if (at < 0) continue;
    const name = firstSpec.slice(0, at);
    const range = firstSpec.slice(at + 1);
    if (/^(workspace|link|portal|file|patch):/.test(range)) continue;
    const vLine = body.find((l) => /^\s+version:?\s/.test(l));
    if (!vLine) continue;
    const version = vLine.replace(/^\s+version:?\s+/, "").replace(/"/g, "").trim();
    const f = npmDirectFlag(name, direct, includeDev);
    if (f.skip) continue;
    out.push({ name, version, ecosystem: "npm", dev: f.dev, direct: f.direct });
  }
  return out;
}

/** pnpm-lock.yaml v5 – v9 (line based). */
async function parsePnpmLock(file, direct, includeDev) {
  const lines = (await readText(file)).split(/\r?\n/);
  const out = [];
  let inPackages = false;
  let current = null;
  for (const line of lines) {
    if (/^\S/.test(line)) {
      inPackages = /^(packages|snapshots):/.test(line);
      current = null;
      continue;
    }
    if (!inPackages) continue;
    const key = line.match(/^ {2}['"]?([^'"\s].*?)['"]?:\s*$/);
    if (key) {
      let k = key[1].replace(/\(.*\)$/, "");
      let name, version;
      const v5 = k.match(/^\/((?:@[^/]+\/)?[^/@]+)\/([^/_]+)/);
      if (v5 && !k.includes("@", k.startsWith("/@") ? 2 : 1)) [, name, version] = v5;
      else {
        k = k.replace(/^\//, "");
        const at = k.lastIndexOf("@");
        if (at <= 0) continue;
        name = k.slice(0, at);
        version = k.slice(at + 1).replace(/_.*/, "");
      }
      const f = npmDirectFlag(name, direct, includeDev);
      if (f.skip) {
        current = null;
        continue;
      }
      current = { name, version, ecosystem: "npm", dev: f.dev, direct: f.direct };
      out.push(current);
      continue;
    }
    if (current && /^\s+dev: true/.test(line)) {
      current.dev = true;
      if (!includeDev) out.pop(), (current = null);
    }
  }
  return out.filter((d) => /^\d/.test(d.version));
}

/** bun.lock (text, JSONC) */
async function parseBunLock(file, includeDev) {
  const j = JSON.parse((await readText(file)).replace(/,(\s*[}\]])/g, "$1"));
  const ws = j.workspaces?.[""] || {};
  const prod = new Set(Object.keys({ ...ws.dependencies, ...ws.optionalDependencies, ...ws.peerDependencies }));
  const dev = new Set(Object.keys(ws.devDependencies || {}));
  const out = [];
  for (const [key, entry] of Object.entries(j.packages || {})) {
    const spec = Array.isArray(entry) ? entry[0] : null;
    if (!spec || /@(workspace|link|file|git|github):/.test(spec)) continue;
    const at = spec.lastIndexOf("@");
    if (at <= 0) continue;
    const name = spec.slice(0, at);
    const version = spec.slice(at + 1);
    const isTop = !key.includes("/") || (key.startsWith("@") && key.split("/").length === 2);
    const isDev = isTop && dev.has(name) && !prod.has(name);
    if (isDev && !includeDev) continue;
    out.push({ name, version, ecosystem: "npm", dev: isDev, direct: isTop && (prod.has(name) || dev.has(name)) });
  }
  return out;
}

// ---------------- Python ----------------

const normPy = (n) => n.toLowerCase().replace(/[-_.]+/g, "-");

async function parsePoetryLock(file, includeDev) {
  const t = parseToml(await readText(file));
  return (t.package || [])
    .filter((p) => p.name && p.version && (includeDev || p.category !== "dev"))
    .map((p) => ({ name: normPy(p.name), version: p.version, ecosystem: "pypi", dev: p.category === "dev", direct: null }));
}

async function parseUvLock(file) {
  const t = parseToml(await readText(file));
  return (t.package || [])
    .filter((p) => p.name && p.version && !(p.source && (p.source.editable || p.source.virtual || p.source.directory || p.source.path || p.source.git)))
    .map((p) => ({ name: normPy(p.name), version: p.version, ecosystem: "pypi", dev: false, direct: null }));
}

async function parsePdmLock(file) {
  const t = parseToml(await readText(file));
  return (t.package || []).filter((p) => p.name && p.version).map((p) => ({ name: normPy(p.name), version: p.version, ecosystem: "pypi", dev: false, direct: null }));
}

/** PEP 751 pylock.toml */
async function parsePylock(file) {
  const t = parseToml(await readText(file));
  return (t.packages || []).filter((p) => p.name && p.version && !p.directory && !p.vcs).map((p) => ({ name: normPy(p.name), version: p.version, ecosystem: "pypi", dev: false, direct: null }));
}

async function parsePipfileLock(file, includeDev) {
  const j = await readJson(file);
  const out = [];
  const add = (obj, dev) => {
    for (const [name, info] of Object.entries(obj || {})) {
      const v = (info.version || "").replace(/^==/, "");
      if (v) out.push({ name: normPy(name), version: v, ecosystem: "pypi", dev, direct: null });
    }
  };
  add(j.default, false);
  if (includeDev) add(j.develop, true);
  return out;
}

const PEP508 = /^\s*([A-Za-z0-9][A-Za-z0-9._\-]*)\s*(\[[^\]]*\])?\s*(\(?\s*(===|==|>=|~=|>|<=|<|!=)\s*([0-9][^\s,;)]*)[^;]*\)?)?/;

function pep508(spec, extra = {}) {
  const m = spec.match(PEP508);
  if (!m || !m[5] || ["<", "<=", "!="].includes(m[4])) return null;
  const exact = m[4] === "==" || m[4] === "===";
  return { name: normPy(m[1]), version: m[5].replace(/\.\*$/, ".0"), ecosystem: "pypi", dev: false, direct: true, declared: spec.trim(), versionSource: exact ? "manifest" : "range", ...extra };
}

async function parseRequirements(file, seen) {
  if (seen.has(file)) return [];
  seen.add(file);
  const out = [];
  for (const raw of (await readText(file)).split(/\r?\n/)) {
    const line = raw.replace(/\s#.*/, "").replace(/^#.*/, "").trim();
    if (!line) continue;
    const inc = line.match(/^-(?:r|-requirement)\s+(\S+)/);
    if (inc) {
      out.push(...(await parseRequirements(join(dirname(file), inc[1]), seen).catch(() => [])));
      continue;
    }
    if (line.startsWith("-")) continue;
    const d = pep508(line);
    if (d) out.push(d);
  }
  return out;
}

/** pyproject.toml: PEP 621 [project], PEP 735 [dependency-groups], Poetry [tool.poetry] */
async function parsePyproject(file, includeDev) {
  const t = parseToml(await readText(file));
  const out = [];
  for (const s of t.project?.dependencies || []) { const d = pep508(s); if (d) out.push(d); }
  if (includeDev) {
    for (const list of Object.values(t.project?.["optional-dependencies"] || {})) for (const s of list) { const d = pep508(s, { dev: true }); if (d) out.push(d); }
    for (const list of Object.values(t["dependency-groups"] || {})) for (const s of list) if (typeof s === "string") { const d = pep508(s, { dev: true }); if (d) out.push(d); }
  }
  const poetry = t.tool?.poetry;
  const addPoetry = (obj, dev) => {
    for (const [name, spec] of Object.entries(obj || {})) {
      if (name.toLowerCase() === "python") continue;
      const s = typeof spec === "string" ? spec : spec?.version;
      const v = lowerBound(s);
      if (v) out.push({ name: normPy(name), version: v, ecosystem: "pypi", dev, direct: true, declared: s, versionSource: verSrc(s) });
    }
  };
  addPoetry(poetry?.dependencies, false);
  if (includeDev) {
    addPoetry(poetry?.["dev-dependencies"], true);
    for (const g of Object.values(poetry?.group || {})) addPoetry(g.dependencies, true);
  }
  return out;
}

// ---------------- Go ----------------

async function parseGoMod(file) {
  const text = (await readText(file)).replace(/\/\/(?!\s*indirect).*$/gm, "");
  const lines = [];
  for (const block of text.matchAll(/^require\s*\(([\s\S]*?)^\)/gm)) lines.push(...block[1].split(/\r?\n/));
  for (const m of text.matchAll(/^require\s+([^\s(]+\s+v\S+.*)$/gm)) lines.push(m[1]);
  // replace directives
  const replaces = new Map();
  const repLines = [];
  for (const block of text.matchAll(/^replace\s*\(([\s\S]*?)^\)/gm)) repLines.push(...block[1].split(/\r?\n/));
  for (const m of text.matchAll(/^replace\s+([^(\n].*)$/gm)) repLines.push(m[1]);
  for (const l of repLines) {
    const m = l.trim().match(/^(\S+)(?:\s+v\S+)?\s*=>\s*(\S+)(?:\s+(v\S+))?/);
    if (m) replaces.set(m[1], { to: m[2], v: m[3] });
  }
  const out = [];
  for (const l of lines) {
    const m = l.trim().match(/^(\S+)\s+(v\S+)(\s*\/\/\s*indirect)?/);
    if (!m) continue;
    let [, name, ver] = m;
    const rep = replaces.get(name);
    if (rep) {
      if (!rep.v) continue; // local path replacement → not a published module
      name = rep.to;
      ver = rep.v;
    }
    out.push({ name, version: ver.replace(/^v/, "").replace(/\+incompatible$/, ""), ecosystem: "go", dev: false, direct: !m[3], versionSource: "lockfile" });
  }
  // Go standard library: only when the toolchain is pinned explicitly
  const tc = text.match(/^toolchain\s+go(\d+\.\d+(?:\.\d+)?)/m)?.[1];
  const notes = [];
  if (tc) out.push({ name: "stdlib", version: tc, ecosystem: "go", dev: false, direct: true, versionSource: "manifest", declared: `toolchain go${tc}` });
  else notes.push("Go standard library not checked (no `toolchain` directive; pass check_package name=stdlib ecosystem=go version=<go version> to check your toolchain)");
  return { deps: out, notes };
}

// ---------------- Rust ----------------

async function parseCargoLock(file) {
  const t = parseToml(await readText(file));
  return (t.package || [])
    .filter((p) => p.name && p.version && String(p.source || "").startsWith("registry+"))
    .map((p) => ({ name: p.name, version: p.version, ecosystem: "cargo", dev: false, direct: null }));
}

async function parseCargoToml(file, includeDev) {
  const t = parseToml(await readText(file));
  const out = [];
  const add = (obj, dev) => {
    for (const [name, spec] of Object.entries(obj || {})) {
      if (typeof spec === "object" && (spec.path || spec.git || spec.workspace)) continue;
      const s = typeof spec === "string" ? spec : spec?.version;
      const v = lowerBound(s);
      if (v) out.push({ name: typeof spec === "object" && spec.package ? spec.package : name, version: v, ecosystem: "cargo", dev, direct: true, declared: s, versionSource: s?.startsWith("=") ? "manifest" : "range" });
    }
  };
  add(t.dependencies, false);
  add(t.workspace?.dependencies, false);
  if (includeDev) add(t["dev-dependencies"], true);
  return out;
}

// ---------------- PHP ----------------

async function parseComposerLock(file, includeDev) {
  const j = await readJson(file);
  const out = [];
  const add = (arr, dev) => {
    for (const p of arr || []) {
      const v = String(p.version || "").replace(/^v/, "");
      if (/^\d/.test(v)) out.push({ name: p.name.toLowerCase(), version: v, ecosystem: "composer", dev, direct: null });
    }
  };
  add(j.packages, false);
  if (includeDev) add(j["packages-dev"], true);
  return out;
}

async function parseComposerJson(file, includeDev) {
  const j = await readJson(file);
  const out = [];
  const add = (obj, dev) => {
    for (const [name, spec] of Object.entries(obj || {})) {
      if (!name.includes("/") || /^(php|ext-|lib-)/.test(name)) continue;
      const v = lowerBound(spec);
      if (v) out.push({ name: name.toLowerCase(), version: v, ecosystem: "composer", dev, direct: true, declared: spec, versionSource: verSrc(spec) });
    }
  };
  add(j.require, false);
  if (includeDev) add(j["require-dev"], true);
  return out;
}

// ---------------- Ruby ----------------

async function parseGemfileLock(file) {
  const text = await readText(file);
  const direct = new Set();
  const depSection = text.match(/^DEPENDENCIES\r?\n((?: {2}.*\r?\n?)*)/m);
  if (depSection) for (const l of depSection[1].split(/\r?\n/)) { const n = l.trim().split(/[\s!(]/)[0]; if (n) direct.add(n); }
  const out = [];
  for (const sec of text.matchAll(/^GEM\r?\n[\s\S]*?^ {2}specs:\r?\n((?: {4}.*\r?\n?)*)/gm)) {
    for (const l of sec[1].split(/\r?\n/)) {
      const m = l.match(/^ {4}([^\s(]+) \(([^)\s]+)\)/);
      if (m) out.push({ name: m[1], version: m[2].replace(/-(x86|arm|java|universal|aarch|x64).*$/, ""), ecosystem: "rubygems", dev: false, direct: direct.has(m[1]) });
    }
  }
  return out;
}

async function parseGemfile(file, includeDev) {
  const text = await readText(file);
  const out = [];
  let groupDev = false;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/#.*/, "");
    if (/^\s*group\s+.*:(development|test)/.test(line)) groupDev = true;
    else if (/^\s*end\b/.test(line)) groupDev = false;
    const m = line.match(/^\s*gem\s+["']([^"']+)["']\s*,\s*["']([^"']+)["']/);
    if (!m) continue;
    const dev = groupDev || /group:\s*\[?\s*:(development|test)/.test(line);
    if (dev && !includeDev) continue;
    const v = lowerBound(m[2]);
    if (v) out.push({ name: m[1], version: v, ecosystem: "rubygems", dev, direct: true, declared: m[2], versionSource: verSrc(m[2]) });
  }
  return out;
}

// ---------------- Java (lockfile) ----------------

async function parseGradleLockfile(file, includeDev) {
  const out = [];
  for (const l of (await readText(file)).split(/\r?\n/)) {
    const m = l.match(/^([\w.\-]+):([\w.\-]+):([^=\s]+)=(.*)$/);
    if (!m) continue;
    const dev = /test/i.test(m[4]) && !/runtime|compile/i.test(m[4]);
    if (dev && !includeDev) continue;
    out.push({ name: `${m[1]}:${m[2]}`, version: m[3], ecosystem: "maven", dev, direct: null });
  }
  return out;
}

// ---------------- .NET ----------------

async function parseNugetLock(file) {
  const j = await readJson(file);
  const out = [];
  for (const fw of Object.values(j.dependencies || {})) {
    for (const [name, info] of Object.entries(fw)) {
      if (info.type === "Project" || !info.resolved) continue;
      out.push({ name, version: info.resolved, ecosystem: "nuget", dev: false, direct: info.type === "Direct" || info.type === "CentralTransitive" ? info.type === "Direct" : false });
    }
  }
  return out;
}

/** obj/project.assets.json (written by `dotnet restore`): full resolved graph */
async function parseProjectAssets(file) {
  const j = await readJson(file);
  const direct = new Set();
  for (const fw of Object.values(j.project?.frameworks || {})) for (const n of Object.keys(fw.dependencies || {})) direct.add(n.toLowerCase());
  const out = [];
  for (const [key, lib] of Object.entries(j.libraries || {})) {
    if (lib.type !== "package") continue;
    const [name, version] = key.split("/");
    out.push({ name, version, ecosystem: "nuget", dev: false, direct: direct.has(name.toLowerCase()) });
  }
  return out;
}

/** Directory.Packages.props (central package management): nearest one up the tree, like MSBuild (max 8 levels). */
async function centralPackageVersions(dir) {
  const map = new Map();
  let d = dir;
  for (let i = 0; i < 8; i++) {
    const t = await readText(join(d, "Directory.Packages.props")).catch(() => null);
    if (t) {
      for (const m of t.matchAll(/<PackageVersion\s+[^>]*?Include="([^"]+)"[^>]*?Version="([^"]+)"/gi)) if (!map.has(m[1].toLowerCase())) map.set(m[1].toLowerCase(), m[2]);
      break;
    }
    if (dirname(d) === d) break;
    d = dirname(d);
  }
  return map;
}

async function parseMsbuild(file, cpm = new Map()) {
  const xml = (await readText(file)).replace(/<!--[\s\S]*?-->/g, "");
  const out = [];
  for (const m of xml.matchAll(/<PackageReference\b([^>]*?)(\/>|>([\s\S]*?)<\/PackageReference>)/gi)) {
    const attrs = m[1];
    const name = attrs.match(/\bInclude="([^"]+)"/i)?.[1] || attrs.match(/\bUpdate="([^"]+)"/i)?.[1];
    if (!name) continue;
    const spec = attrs.match(/\bVersionOverride="([^"]+)"/i)?.[1] || attrs.match(/\bVersion="([^"]+)"/i)?.[1] || m[3]?.match(/<Version>([^<]+)<\/Version>/i)?.[1] || cpm.get(name.toLowerCase());
    const v = lowerBound(spec);
    const dev = /PrivateAssets="all"/i.test(attrs) || /<PrivateAssets>all<\/PrivateAssets>/i.test(m[3] || "");
    if (v) out.push({ name, version: v, ecosystem: "nuget", dev, direct: true, declared: spec, versionSource: /^\[?\d[^,]*\]?$/.test(spec) ? "manifest" : "range" });
  }
  return out;
}

/** packages.config (.NET Framework) */
async function parsePackagesConfig(file, includeDev) {
  const xml = await readText(file);
  const out = [];
  for (const m of xml.matchAll(/<package\s+([^>]*?)\/?>/gi)) {
    const id = m[1].match(/\bid="([^"]+)"/i)?.[1];
    const v = m[1].match(/\bversion="([^"]+)"/i)?.[1];
    const dev = /developmentDependency="true"/i.test(m[1]);
    if (!id || !v || (dev && !includeDev)) continue;
    out.push({ name: id, version: v, ecosystem: "nuget", dev, direct: null });
  }
  return out;
}

// ---------------- Dart / Flutter ----------------

async function parsePubspecLock(file, includeDev) {
  const lines = (await readText(file)).split(/\r?\n/);
  const out = [];
  let cur = null;
  let inPackages = false;
  const flush = () => {
    if (cur && cur.version && cur.source === "hosted") {
      const dev = /dev/.test(cur.dependency || "");
      if (!dev || includeDev) out.push({ name: cur.name, version: cur.version, ecosystem: "pub", dev, direct: /direct/.test(cur.dependency || ""), versionSource: "lockfile" });
    }
    cur = null;
  };
  for (const line of lines) {
    if (/^\S/.test(line)) {
      flush();
      inPackages = /^packages:/.test(line);
      continue;
    }
    if (!inPackages) continue;
    const pk = line.match(/^ {2}([\w.\-]+):\s*$/);
    if (pk) {
      flush();
      cur = { name: pk[1] };
      continue;
    }
    const kv = line.match(/^ {4}(dependency|source|version):\s*"?([^"]+?)"?\s*$/);
    if (cur && kv) cur[kv[1]] = kv[2];
  }
  flush();
  return out;
}

// ---------------- Elixir ----------------

async function parseMixLock(file) {
  const out = [];
  for (const m of (await readText(file)).matchAll(/^\s*"[^"]+":\s*\{:hex,\s*:([\w]+),\s*"([^"]+)"/gm)) {
    out.push({ name: m[1], version: m[2], ecosystem: "hex", dev: false, direct: null, versionSource: "lockfile" });
  }
  return out;
}

// ---------------- Swift ----------------

export function swiftPackageName(url) {
  return String(url).replace(/^(https?:\/\/|git@|ssh:\/\/git@)/, "").replace(/^([^/:]+):/, "$1/").replace(/\.git$/, "").replace(/\/$/, "");
}

async function parsePackageResolved(file) {
  const j = await readJson(file);
  const pins = j.pins || j.object?.pins || [];
  return pins
    .filter((p) => p.state?.version)
    .map((p) => ({ name: swiftPackageName(p.location || p.repositoryURL), version: p.state.version.replace(/^v/, ""), ecosystem: "swift", dev: false, direct: null, versionSource: "lockfile" }));
}

// ---------------- R ----------------

async function parseRenvLock(file) {
  const j = await readJson(file);
  return Object.values(j.Packages || {})
    .filter((p) => p.Version && (!p.Source || /Repository|CRAN/i.test(p.Source)) && (!p.Repository || /CRAN|RSPM|P3M/i.test(p.Repository)))
    .map((p) => ({ name: p.Package, version: p.Version, ecosystem: "cran", dev: false, direct: null, versionSource: "lockfile" }));
}

// ---------------- CPE helpers (for NVD matching) ----------------

/** Map package name to probable CPE product name candidates. */
export function cpeProductCandidates(dep) {
  let n = dep.name.toLowerCase();
  if (dep.ecosystem === "npm" && n.startsWith("@")) n = n.split("/")[1];
  if (dep.ecosystem === "go" || dep.ecosystem === "swift") {
    const parts = n.split("/").filter((p) => !/^v\d+$/.test(p));
    n = parts[parts.length - 1];
  }
  if (dep.ecosystem === "maven") n = n.split(":")[1] || n;
  if (dep.ecosystem === "composer") n = n.split("/")[1] || n;
  const set = new Set([n]);
  if (dep.ecosystem === "pypi") set.add(n.replace(/-/g, "_"));
  return [...set];
}

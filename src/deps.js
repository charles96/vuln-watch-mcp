import { readFile, stat, readdir } from "node:fs/promises";
import { join, basename, relative, dirname } from "node:path";

/**
 * Dependency collection across ecosystems.
 * Each dependency: { name, version, ecosystem, dev, direct (true|false|null), source }
 */

const SKIP_DIRS = new Set([
  "node_modules", ".git", "vendor", "dist", "build", "out", ".venv", "venv", "env", "target",
  "__pycache__", ".next", ".nuxt", "bin", "obj", ".gradle", ".idea", ".vscode", "coverage", ".tox",
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

/** Scan a directory (optionally recursive) or a single manifest file. */
export async function collectDependencies(target, { includeDev = false, recursive = false, maxDepth = 4 } = {}) {
  const st = await stat(target);
  const root = st.isDirectory() ? target : dirname(target);
  const files = st.isDirectory() ? await listFiles(target, recursive ? maxDepth : 0) : [target];

  // group by directory so that lockfiles win over manifests in the same folder
  const byDir = new Map();
  for (const f of files) {
    const d = dirname(f);
    if (!byDir.has(d)) byDir.set(d, []);
    byDir.get(d).push(f);
  }

  const deps = [];
  const manifests = [];
  for (const [dir, list] of byDir) {
    const has = (n) => list.find((f) => basename(f) === n);
    const rel = (f) => relative(root, f) || basename(f);
    const run = async (file, fn) => {
      try {
        const got = await fn(file);
        got.forEach((d) => (d.source = rel(file)));
        deps.push(...got);
        manifests.push(rel(file));
      } catch (err) {
        manifests.push(`${rel(file)} (parse error: ${err.message})`);
      }
    };
    const pkgJson = has("package.json");
    const directNpm = pkgJson ? await npmDirectSets(pkgJson) : null;

    // --- npm / yarn / pnpm
    const npmLock = has("package-lock.json") || has("npm-shrinkwrap.json");
    if (npmLock) await run(npmLock, (f) => parsePackageLock(f, includeDev));
    else if (has("yarn.lock")) await run(has("yarn.lock"), (f) => parseYarnLock(f, directNpm, includeDev));
    else if (has("pnpm-lock.yaml")) await run(has("pnpm-lock.yaml"), (f) => parsePnpmLock(f, directNpm, includeDev));
    else if (pkgJson) await run(pkgJson, (f) => parsePackageJson(f, includeDev));

    // --- Python
    if (has("poetry.lock")) await run(has("poetry.lock"), (f) => parsePoetryLock(f, includeDev));
    if (has("uv.lock")) await run(has("uv.lock"), parseUvLock);
    if (has("Pipfile.lock")) await run(has("Pipfile.lock"), (f) => parsePipfileLock(f, includeDev));
    for (const f of list) if (/^requirements.*\.txt$/i.test(basename(f))) await run(f, parseRequirements);

    // --- Go
    if (has("go.mod")) await run(has("go.mod"), parseGoMod);

    // --- Rust
    if (has("Cargo.lock")) await run(has("Cargo.lock"), parseCargoLock);

    // --- PHP
    if (has("composer.lock")) await run(has("composer.lock"), (f) => parseComposerLock(f, includeDev));

    // --- Ruby
    if (has("Gemfile.lock")) await run(has("Gemfile.lock"), parseGemfileLock);

    // --- Java
    if (has("gradle.lockfile")) await run(has("gradle.lockfile"), parseGradleLockfile);
    if (has("pom.xml")) await run(has("pom.xml"), (f) => parsePom(f, includeDev));
    for (const n of ["build.gradle", "build.gradle.kts"]) if (has(n)) await run(has(n), parseGradleBuild);

    // --- .NET
    if (has("packages.lock.json")) await run(has("packages.lock.json"), parseNugetLock);
    else {
      for (const f of list) if (/\.(cs|fs|vb)proj$/i.test(f) || basename(f) === "Directory.Packages.props") await run(f, parseMsbuild);
    }
  }

  // de-duplicate (keep "direct" if any occurrence is direct)
  const map = new Map();
  for (const d of deps) {
    if (!d.version || (d.dev && !includeDev)) continue;
    const k = `${d.ecosystem}:${d.name.toLowerCase()}@${d.version}`;
    const prev = map.get(k);
    if (!prev) map.set(k, d);
    else {
      if (d.direct === true) prev.direct = true;
      if (!d.dev) prev.dev = false;
    }
  }
  return { deps: [...map.values()], manifests };
}

// ---------------- npm ----------------

function cleanRange(v) {
  if (!v || typeof v !== "string") return null;
  if (/^(file|link|git|github|http|https|workspace|npm|portal|patch):/.test(v) || v === "*" || v === "latest") return null;
  const m = v.match(/\d+(\.\d+){0,3}([-.][0-9A-Za-z.]+)?/);
  return m ? m[0] : null;
}

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
      const version = cleanRange(range);
      if (version) out.push({ name, version, ecosystem: "npm", dev, direct: true, declared: range });
    }
  };
  add(j.dependencies, false);
  add(j.optionalDependencies, false);
  if (includeDev) add(j.devDependencies, true);
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
  const blocks = text.split(/\r?\n(?=\S)/);
  for (const block of blocks) {
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

/** pnpm-lock.yaml v5 – v9 (line based, no YAML dependency). */
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
      let k = key[1].replace(/\(.*\)$/, ""); // drop peer suffix
      let name, version;
      const v5 = k.match(/^\/((?:@[^/]+\/)?[^/@]+)\/([^/_]+)/); // /name/1.2.3
      if (v5 && !k.includes("@", k.startsWith("/@") ? 2 : 1)) [, name, version] = v5;
      else {
        k = k.replace(/^\//, "");
        const at = k.lastIndexOf("@");
        if (at <= 0) continue;
        name = k.slice(0, at);
        version = k.slice(at + 1).replace(/_.*/, "");
      }
      current = { name, version, ecosystem: "npm", dev: false, direct: null };
      const f = npmDirectFlag(name, direct, includeDev);
      if (f.skip) {
        current = null;
        continue;
      }
      Object.assign(current, { direct: f.direct, dev: f.dev });
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

// ---------------- Python ----------------

const normPy = (n) => n.toLowerCase().replace(/[-_.]+/g, "-");

function tomlPackages(text) {
  // split [[package]] tables of poetry.lock / uv.lock / Cargo.lock
  return text
    .split(/^\[\[package\]\]\s*$/m)
    .slice(1)
    .map((chunk) => {
      const body = chunk.split(/^\[(?!\[package\]\])/m)[0];
      const get = (k) => body.match(new RegExp(`^${k}\\s*=\\s*"([^"]*)"`, "m"))?.[1];
      return { name: get("name"), version: get("version"), category: get("category"), body };
    });
}

async function parsePoetryLock(file, includeDev) {
  return tomlPackages(await readText(file))
    .filter((p) => p.name && p.version && (includeDev || p.category !== "dev"))
    .map((p) => ({ name: normPy(p.name), version: p.version, ecosystem: "pypi", dev: p.category === "dev", direct: null }));
}

async function parseUvLock(file) {
  return tomlPackages(await readText(file))
    .filter((p) => p.name && p.version && !/source\s*=\s*\{\s*(editable|virtual|directory|path)\s*=/.test(p.body))
    .map((p) => ({ name: normPy(p.name), version: p.version, ecosystem: "pypi", dev: false, direct: null }));
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

async function parseRequirements(file) {
  const out = [];
  for (const raw of (await readText(file)).split(/\r?\n/)) {
    const line = raw.replace(/\s#.*/, "").replace(/^#.*/, "").trim();
    if (!line || line.startsWith("-")) continue;
    const m = line.match(/^([A-Za-z0-9_.\-]+)(\[[^\]]*\])?\s*(===|==|>=|~=)\s*([0-9][^\s,;]*)/);
    if (m) out.push({ name: normPy(m[1]), version: m[4], ecosystem: "pypi", dev: false, direct: true, declared: line });
  }
  return out;
}

// ---------------- Go ----------------

async function parseGoMod(file) {
  const out = [];
  const text = await readText(file);
  const lines = [];
  for (const block of text.matchAll(/^require\s*\(([\s\S]*?)^\)/gm)) lines.push(...block[1].split(/\r?\n/));
  for (const m of text.matchAll(/^require\s+([^\s(]+\s+v\S+.*)$/gm)) lines.push(m[1]);
  for (const l of lines) {
    const m = l.trim().match(/^(\S+)\s+(v\S+)(\s*\/\/\s*indirect)?/);
    if (m) out.push({ name: m[1], version: m[2].replace(/^v/, "").replace(/\+incompatible$/, ""), ecosystem: "go", dev: false, direct: !m[3] });
  }
  return out;
}

// ---------------- Rust ----------------

async function parseCargoLock(file) {
  return tomlPackages(await readText(file))
    .filter((p) => p.name && p.version && /^source\s*=\s*"registry\+/m.test(p.body))
    .map((p) => ({ name: p.name, version: p.version, ecosystem: "cargo", dev: false, direct: null }));
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

// ---------------- Java ----------------

async function parseGradleLockfile(file) {
  const out = [];
  for (const l of (await readText(file)).split(/\r?\n/)) {
    const m = l.match(/^([\w.\-]+):([\w.\-]+):([^=\s]+)=(.*)$/);
    if (m) out.push({ name: `${m[1]}:${m[2]}`, version: m[3], ecosystem: "maven", dev: /test/i.test(m[4]) && !/runtime|compile/i.test(m[4]), direct: null });
  }
  return out;
}

async function parsePom(file, includeDev) {
  const xml = (await readText(file)).replace(/<!--[\s\S]*?-->/g, "");
  const props = {};
  const propsBlock = xml.match(/<properties>([\s\S]*?)<\/properties>/);
  if (propsBlock) for (const m of propsBlock[1].matchAll(/<([\w.\-]+)>([^<]*)<\/\1>/g)) props[m[1]] = m[2].trim();
  const pv = xml.replace(/<parent>[\s\S]*?<\/parent>/, "").match(/<version>([^<]+)<\/version>/);
  if (pv) props["project.version"] = pv[1].trim();
  const resolveProp = (v) => v?.replace(/\$\{([^}]+)\}/g, (_, k) => props[k] ?? `\${${k}}`);
  const out = [];
  for (const m of xml.matchAll(/<dependency>([\s\S]*?)<\/dependency>/g)) {
    const get = (t) => m[1].match(new RegExp(`<${t}>([^<]+)</${t}>`))?.[1]?.trim();
    const g = resolveProp(get("groupId"));
    const a = resolveProp(get("artifactId"));
    const v = resolveProp(get("version"));
    const scope = get("scope");
    if (!g || !a || !v || v.includes("${") || /^\[|\(/.test(v)) continue;
    if (scope === "test" && !includeDev) continue;
    out.push({ name: `${g}:${a}`, version: v, ecosystem: "maven", dev: scope === "test", direct: true });
  }
  return out;
}

async function parseGradleBuild(file) {
  const text = await readText(file);
  const out = [];
  for (const m of text.matchAll(/(\w+)\s*\(?\s*['"]([\w.\-]+):([\w.\-]+):([\w.\-]+)(?::[\w]+)?['"]/g)) {
    const conf = m[1];
    if (/^(classpath|id|plugin)$/i.test(conf)) continue;
    out.push({ name: `${m[2]}:${m[3]}`, version: m[4], ecosystem: "maven", dev: /^test/i.test(conf), direct: true });
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
      out.push({ name, version: info.resolved, ecosystem: "nuget", dev: false, direct: info.type === "Direct" });
    }
  }
  return out;
}

async function parseMsbuild(file) {
  const xml = await readText(file);
  const out = [];
  for (const m of xml.matchAll(/<Package(?:Reference|Version)\s+[^>]*?Include="([^"]+)"[^>]*?Version="([^"]+)"/gi)) {
    const v = cleanRange(m[2]);
    if (v) out.push({ name: m[1], version: v, ecosystem: "nuget", dev: false, direct: true });
  }
  for (const m of xml.matchAll(/<PackageReference\s+[^>]*?Include="([^"]+)"[^>]*?>\s*<Version>([^<]+)<\/Version>/gi)) {
    const v = cleanRange(m[2]);
    if (v) out.push({ name: m[1], version: v, ecosystem: "nuget", dev: false, direct: true });
  }
  return out;
}

// ---------------- CPE helpers (for NVD matching) ----------------

/** Map package name to probable CPE product name candidates (+ optional vendor hint). */
export function cpeProductCandidates(dep) {
  let n = dep.name.toLowerCase();
  if (dep.ecosystem === "npm" && n.startsWith("@")) n = n.split("/")[1];
  if (dep.ecosystem === "go") {
    const parts = n.split("/").filter((p) => !/^v\d+$/.test(p));
    n = parts[parts.length - 1];
  }
  if (dep.ecosystem === "maven") n = n.split(":")[1] || n;
  if (dep.ecosystem === "composer") n = n.split("/")[1] || n;
  const set = new Set([n]);
  if (dep.ecosystem === "pypi") set.add(n.replace(/-/g, "_"));
  return [...set];
}

import { readFile, stat, readdir } from "node:fs/promises";
import { join, basename } from "node:path";

/**
 * Parse dependency manifests in a file or directory.
 * Returns [{ name, version, ecosystem, dev, source }]
 */
export async function collectDependencies(target, { includeDev = false } = {}) {
  const st = await stat(target);
  let files;
  if (st.isDirectory()) {
    const entries = await readdir(target);
    files = entries.map((e) => join(target, e));
  } else {
    files = [target];
  }
  const byName = (n) => files.find((f) => basename(f) === n);
  const deps = [];

  // npm: prefer lockfile (exact versions), fall back to package.json ranges
  const lock = byName("package-lock.json");
  const pkg = byName("package.json");
  if (lock) deps.push(...(await parsePackageLock(lock, pkg, includeDev)));
  else if (pkg) deps.push(...(await parsePackageJson(pkg, includeDev)));

  for (const f of files) {
    const b = basename(f);
    if (/^requirements.*\.txt$/.test(b)) deps.push(...(await parseRequirements(f)));
    if (b === "go.mod") deps.push(...(await parseGoMod(f)));
  }
  // de-duplicate
  const seen = new Set();
  return deps.filter((d) => {
    const k = `${d.ecosystem}:${d.name}@${d.version}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

function cleanRange(v) {
  if (!v || typeof v !== "string") return null;
  if (/^(file|link|git|github|http|workspace|npm):/.test(v)) return null;
  const m = v.match(/\d+(\.\d+){0,3}([-.][0-9A-Za-z.]+)?/);
  return m ? m[0] : null;
}

async function parsePackageJson(file, includeDev) {
  const j = JSON.parse(await readFile(file, "utf8"));
  const out = [];
  const add = (obj, dev) => {
    for (const [name, range] of Object.entries(obj || {})) {
      const version = cleanRange(range);
      if (version) out.push({ name, version, ecosystem: "npm", dev, source: "package.json", declared: range });
    }
  };
  add(j.dependencies, false);
  if (includeDev) add(j.devDependencies, true);
  return out;
}

async function parsePackageLock(lockFile, pkgFile, includeDev) {
  const lock = JSON.parse(await readFile(lockFile, "utf8"));
  const out = [];
  if (lock.packages) {
    const root = lock.packages[""] || {};
    const direct = new Set(Object.keys({ ...root.dependencies, ...root.optionalDependencies }));
    const directDev = new Set(Object.keys(root.devDependencies || {}));
    for (const [path, info] of Object.entries(lock.packages)) {
      if (!path.startsWith("node_modules/") || !info.version) continue;
      const name = info.name || path.slice(path.lastIndexOf("node_modules/") + 13);
      if (info.dev && !includeDev) continue;
      const isDirect = path === `node_modules/${name}` && (direct.has(name) || directDev.has(name));
      out.push({
        name,
        version: info.version,
        ecosystem: "npm",
        dev: Boolean(info.dev),
        direct: isDirect,
        source: "package-lock.json",
      });
    }
  } else if (lock.dependencies) {
    // lockfile v1
    const walk = (deps) => {
      for (const [name, info] of Object.entries(deps || {})) {
        if (info.dev && !includeDev) continue;
        out.push({ name, version: info.version, ecosystem: "npm", dev: Boolean(info.dev), source: "package-lock.json" });
        walk(info.dependencies);
      }
    };
    walk(lock.dependencies);
  } else if (pkgFile) {
    return parsePackageJson(pkgFile, includeDev);
  }
  return out;
}

async function parseRequirements(file) {
  const out = [];
  for (const raw of (await readFile(file, "utf8")).split(/\r?\n/)) {
    const line = raw.replace(/#.*/, "").trim();
    if (!line || line.startsWith("-")) continue;
    const m = line.match(/^([A-Za-z0-9_.\-]+)(\[[^\]]*\])?\s*(==|>=|~=|===)\s*([0-9][^\s,;]*)/);
    if (m) out.push({ name: m[1], version: m[4], ecosystem: "pypi", dev: false, source: basename(file), declared: line });
  }
  return out;
}

async function parseGoMod(file) {
  const out = [];
  const text = await readFile(file, "utf8");
  const lines = [];
  for (const block of text.matchAll(/require\s*\(([\s\S]*?)\)/g)) lines.push(...block[1].split(/\r?\n/));
  for (const m of text.matchAll(/^require\s+([^\s(]+\s+v[^\s]+)/gm)) lines.push(m[1]);
  for (const l of lines) {
    const m = l.trim().match(/^([^\s]+)\s+(v[^\s]+)(\s*\/\/\s*indirect)?/);
    if (m) out.push({ name: m[1], version: m[2].replace(/^v/, "").replace(/\+incompatible$/, ""), ecosystem: "go", dev: false, direct: !m[3], source: "go.mod" });
  }
  return out;
}

/** Map package name to probable CPE product name candidates. */
export function cpeProductCandidates(dep) {
  let n = dep.name.toLowerCase();
  if (dep.ecosystem === "npm" && n.startsWith("@")) n = n.split("/")[1];
  if (dep.ecosystem === "go") {
    const parts = n.split("/").filter((p) => !/^v\d+$/.test(p));
    n = parts[parts.length - 1];
  }
  const set = new Set([n]);
  if (dep.ecosystem === "pypi") {
    set.add(n.replace(/-/g, "_"));
  }
  return [...set];
}

export const ECOSYSTEM_TARGET_SW = {
  npm: ["node.js", "nodejs", "node"],
  pypi: ["python"],
  go: ["go", "golang"],
};

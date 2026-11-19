import { readFile, writeFile, stat } from "node:fs/promises";
import { dirname, join, relative, resolve, sep } from "node:path";

/**
 * Project-level false-positive handling via `.vulnwatch.json`:
 * {
 *   "ignore": [
 *     { "id": "CVE-2021-23337", "package": "lodash", "version": "4.17.15", "ecosystem": "npm",
 *       "reason": "template() is never called", "expires": "2027-03-01", "added": "2026-11-19",
 *       "allowHighRisk": false }
 *   ],
 *   "ignorePaths": ["examples/**", "test/fixtures/**"]
 * }
 * - An entry needs `reason` and at least one of `id` / `package`.
 * - `id` matches the finding id or any alias (CVE, GHSA, PYSEC, ...). Without `id` every finding of the package is ignored.
 * - `version` (optional) pins the suppression to one version, so it re-surfaces after an upgrade/downgrade.
 * - Expired entries are not applied (and are reported).
 * - Malicious packages and CISA KEV findings stay visible unless the entry sets allowHighRisk: true.
 */

export const IGNORE_FILE = ".vulnwatch.json";

const isDir = (p) => stat(p).then((s) => s.isDirectory(), () => false);
const exists = (p) => stat(p).then(() => true, () => false);
export const today = () => new Date().toISOString().slice(0, 10);

/** Find the nearest .vulnwatch.json from `start` upwards (stops at a .git directory or filesystem root). */
export async function findIgnoreFile(start) {
  let d = (await isDir(start)) ? resolve(start) : dirname(resolve(start));
  for (let i = 0; i < 20; i++) {
    const f = join(d, IGNORE_FILE);
    if (await exists(f)) return f;
    if (await exists(join(d, ".git"))) return null;
    const up = dirname(d);
    if (up === d) return null;
    d = up;
  }
  return null;
}

export async function readIgnoreFile(file) {
  const raw = JSON.parse(await readFile(file, "utf8"));
  return {
    file,
    dir: dirname(file),
    ignore: Array.isArray(raw.ignore) ? raw.ignore : [],
    ignorePaths: Array.isArray(raw.ignorePaths) ? raw.ignorePaths : [],
    raw,
  };
}

/** Load the config that applies to `start` (or null). Invalid JSON throws with a clear message. */
export async function loadIgnoreConfig(start) {
  const file = await findIgnoreFile(start);
  if (!file) return null;
  try {
    return await readIgnoreFile(file);
  } catch (err) {
    throw new Error(`${file} is not valid JSON: ${err.message}`);
  }
}

// ---------- matching ----------

const up = (s) => String(s || "").toUpperCase();
const low = (s) => String(s || "").toLowerCase();

function packageMatches(entryPkg, name) {
  if (!entryPkg) return true;
  const e = low(entryPkg);
  const n = low(name);
  return e === n || n.split(/[:/]/).pop() === e; // maven "g:a" ↔ "a", go/swift path ↔ last segment
}

export function entryStatus(e, now = today()) {
  if (!e.reason || (!e.id && !e.package)) return "invalid";
  if (e.expires && e.expires !== "never" && e.expires < now) return "expired";
  return "active";
}

export function entryMatches(e, f) {
  if (e.id) {
    const ids = [f.id, ...(f.aliases || [])].map(up);
    if (!ids.includes(up(e.id))) return false;
  }
  if (e.package || e.version || e.ecosystem) {
    if (!f.package) return false;
    if (!packageMatches(e.package, f.package.name)) return false;
    if (e.version && e.version !== f.package.version) return false;
    if (e.ecosystem && low(e.ecosystem) !== low(f.package.ecosystem)) return false;
  }
  return true;
}

function globToRegex(glob) {
  let re = "";
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === "*" && glob[i + 1] === "*") {
      re += glob[i + 2] === "/" ? "(?:.*/)?" : ".*";
      i += glob[i + 2] === "/" ? 2 : 1;
    } else if (c === "*") re += "[^/]*";
    else if (c === "?") re += "[^/]";
    else re += c.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  }
  return new RegExp(`^${re}$`);
}

/** Does a manifest path (relative to the ignore file's dir) match ignorePaths? */
export function pathIgnored(cfg, absManifest) {
  if (!cfg?.ignorePaths?.length) return null;
  const rel = relative(cfg.dir, absManifest).split(sep).join("/");
  if (rel.startsWith("..")) return null;
  for (const p of cfg.ignorePaths) {
    const pat = String(p).replace(/^\.\//, "").replace(/\/$/, "");
    if (/[*?]/.test(pat)) {
      if (globToRegex(pat).test(rel) || globToRegex(`${pat}/**`).test(rel)) return p;
    } else if (rel === pat || rel.startsWith(`${pat}/`)) return p;
  }
  return null;
}

/**
 * Apply suppressions to findings.
 * Returns { kept, suppressed: [{finding, entry}], highRiskKept: [{finding, entry}], expired: [entry], invalid: [entry], unused: [entry] }
 */
export function applyIgnores(findings, cfg) {
  const res = { kept: [], suppressed: [], highRiskKept: [], expired: [], invalid: [], unused: [] };
  if (!cfg?.ignore?.length) {
    res.kept = findings;
    return res;
  }
  const now = today();
  const active = [];
  for (const e of cfg.ignore) {
    const st = entryStatus(e, now);
    if (st === "active") active.push(e);
    else res[st].push(e);
  }
  const used = new Set();
  for (const f of findings) {
    const e = active.find((x) => entryMatches(x, f));
    if (!e) {
      res.kept.push(f);
      continue;
    }
    used.add(e);
    const highRisk = f.malicious || f.kev;
    if (highRisk && !e.allowHighRisk) {
      f.suppressionOverridden = { reason: e.reason, why: f.malicious ? "malicious package" : "actively exploited (CISA KEV)" };
      res.kept.push(f);
      res.highRiskKept.push({ finding: f, entry: e });
    } else {
      res.suppressed.push({ finding: f, entry: e });
    }
  }
  res.unused = active.filter((e) => !used.has(e));
  return res;
}

// ---------- editing ----------

function normalizeEntry(e) {
  const out = {};
  for (const k of ["id", "package", "version", "ecosystem", "reason", "expires", "added", "allowHighRisk"]) {
    if (e[k] !== undefined && e[k] !== null && e[k] !== "" && e[k] !== false) out[k] = e[k];
  }
  if (out.id) out.id = /^(CVE|GHSA|PYSEC|GO|RUSTSEC|MAL|OSV)-/i.test(out.id) ? out.id.replace(/^[a-z]+/i, (m) => m.toUpperCase()) : out.id;
  return out;
}

const sameTarget = (a, b) => up(a.id) === up(b.id) && low(a.package) === low(b.package) && (a.version || "") === (b.version || "") && low(a.ecosystem) === low(b.ecosystem);

/** Add or update an entry in `<dir>/.vulnwatch.json` (or the nearest existing one). Returns { file, entry, updated }. */
export async function addIgnoreEntry(projectPath, entry) {
  const existing = await findIgnoreFile(projectPath);
  const file = existing || join((await isDir(projectPath)) ? resolve(projectPath) : dirname(resolve(projectPath)), IGNORE_FILE);
  const raw = existing ? JSON.parse(await readFile(file, "utf8")) : { ignore: [] };
  if (!Array.isArray(raw.ignore)) raw.ignore = [];
  const e = normalizeEntry({ added: today(), ...entry });
  const idx = raw.ignore.findIndex((x) => sameTarget(x, e));
  if (idx >= 0) raw.ignore[idx] = { ...raw.ignore[idx], ...e };
  else raw.ignore.push(e);
  await writeFile(file, JSON.stringify(raw, null, 2) + "\n");
  return { file, entry: e, updated: idx >= 0 };
}

/** Remove entries matching id/package(/version). Returns { file, removed: [] }. */
export async function removeIgnoreEntries(projectPath, { id, package: pkg, version }) {
  const file = await findIgnoreFile(projectPath);
  if (!file) return { file: null, removed: [] };
  const raw = JSON.parse(await readFile(file, "utf8"));
  const removed = [];
  raw.ignore = (raw.ignore || []).filter((e) => {
    const hit = (!id || up(e.id) === up(id)) && (!pkg || packageMatches(pkg, e.package || "")) && (!version || e.version === version);
    if (hit) removed.push(e);
    return !hit;
  });
  if (removed.length) await writeFile(file, JSON.stringify(raw, null, 2) + "\n");
  return { file, removed };
}

export function describeEntry(e) {
  const target = [e.id || "all advisories", e.package ? `in ${e.package}${e.version ? `@${e.version}` : ""}${e.ecosystem ? ` [${e.ecosystem}]` : ""}` : ""].filter(Boolean).join(" ");
  return `${target} — "${e.reason}"${e.expires ? ` (expires ${e.expires})` : " (no expiry)"}${e.allowHighRisk ? " [allowHighRisk]" : ""}`;
}

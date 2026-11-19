import { cacheGet, cacheSet } from "./cache.js";

// OSV.dev: package-native advisories (GitHub Advisory DB, PyPA, Go, RustSec, malicious packages, ...)
const OSV_API = "https://api.osv.dev/v1";
const TTL = Number(process.env.OSV_TTL_HOURS || 6) * 3600_000;

export const OSV_ECOSYSTEM = {
  npm: "npm",
  pypi: "PyPI",
  go: "Go",
  maven: "Maven",
  composer: "Packagist",
  rubygems: "RubyGems",
  cargo: "crates.io",
  nuget: "NuGet",
};

async function post(path, body) {
  const res = await fetch(`${OSV_API}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "User-Agent": "vuln-watch-mcp" },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(60_000),
  });
  if (!res.ok) throw new Error(`OSV HTTP ${res.status}`);
  return res.json();
}

/** Fetch a full OSV record (cached). Returns null if not found. */
export async function getOsvVuln(id) {
  const key = `osv:${id}`;
  const hit = await cacheGet(key, TTL);
  if (hit !== undefined) return hit;
  const res = await fetch(`${OSV_API}/vulns/${encodeURIComponent(id)}`, {
    headers: { "User-Agent": "vuln-watch-mcp" },
    signal: AbortSignal.timeout(30_000),
  });
  if (res.status === 404) {
    await cacheSet(key, null);
    return null;
  }
  if (!res.ok) throw new Error(`OSV HTTP ${res.status}`);
  const v = await res.json();
  await cacheSet(key, v);
  return v;
}

async function mapLimit(items, limit, fn) {
  const out = new Array(items.length);
  let i = 0;
  await Promise.all(
    Array.from({ length: Math.min(limit, items.length) }, async () => {
      while (i < items.length) {
        const idx = i++;
        out[idx] = await fn(items[idx], idx);
      }
    })
  );
  return out;
}
export { mapLimit };

/**
 * Query OSV for many packages at once.
 * @param deps [{name, version, ecosystem}]
 * @returns Array (same order as deps) of arrays of full OSV records
 */
export async function osvQueryDeps(deps) {
  const supported = deps.map((d) => (OSV_ECOSYSTEM[d.ecosystem] ? d : null));
  const queries = [];
  const index = [];
  supported.forEach((d, i) => {
    if (!d) return;
    queries.push({ package: { name: d.name, ecosystem: OSV_ECOSYSTEM[d.ecosystem] }, version: d.version });
    index.push(i);
  });
  const idsPerDep = deps.map(() => []);
  for (let start = 0; start < queries.length; start += 1000) {
    const chunk = queries.slice(start, start + 1000);
    const cacheKey = `osvbatch:${JSON.stringify(chunk)}`;
    let data = await cacheGet(cacheKey, TTL);
    if (!data) {
      data = await post("/querybatch", { queries: chunk });
      await cacheSet(cacheKey, data);
    }
    (data.results || []).forEach((r, j) => {
      idsPerDep[index[start + j]] = (r.vulns || []).map((v) => v.id);
    });
  }
  const allIds = [...new Set(idsPerDep.flat())];
  const records = new Map();
  await mapLimit(allIds, 8, async (id) => {
    try {
      const v = await getOsvVuln(id);
      if (v && !v.withdrawn) records.set(id, v);
    } catch {
      /* skip */
    }
  });
  return idsPerDep.map((ids) => ids.map((id) => records.get(id)).filter(Boolean));
}

/** Group duplicate advisories (GHSA / PYSEC / GO / RUSTSEC describing the same CVE). */
export function dedupeOsv(records) {
  const rank = (id) => (id.startsWith("MAL-") ? 0 : id.startsWith("GHSA-") ? 1 : id.startsWith("CVE-") ? 3 : 2);
  const groups = new Map();
  const keyOf = new Map();
  for (const r of [...records].sort((a, b) => rank(a.id) - rank(b.id))) {
    const ids = [r.id, ...(r.aliases || [])];
    const existing = ids.map((x) => keyOf.get(x)).find(Boolean);
    const key = existing || r.id;
    if (!groups.has(key)) groups.set(key, { primary: r, others: [] });
    else groups.get(key).others.push(r);
    ids.forEach((x) => keyOf.set(x, key));
  }
  return [...groups.values()];
}

import { cacheGet, cacheSet } from "./cache.js";

// FIRST.org EPSS: probability that a CVE is exploited in the next 30 days.
const EPSS_URL = "https://api.first.org/data/v1/epss";
const TTL = 24 * 3600_000;

/** Returns Map<CVE, {epss:number, percentile:number, date:string}> (missing CVEs are omitted). */
export async function getEpss(cveIds) {
  const ids = [...new Set(cveIds.filter((c) => /^CVE-\d{4}-\d+$/i.test(c)).map((c) => c.toUpperCase()))];
  const out = new Map();
  const todo = [];
  for (const id of ids) {
    const hit = await cacheGet(`epss:${id}`, TTL);
    if (hit !== undefined) {
      if (hit) out.set(id, hit);
    } else todo.push(id);
  }
  for (let i = 0; i < todo.length; i += 80) {
    const chunk = todo.slice(i, i + 80);
    try {
      const res = await fetch(`${EPSS_URL}?cve=${chunk.join(",")}&limit=${chunk.length}`, {
        headers: { "User-Agent": "vuln-watch-mcp" },
        signal: AbortSignal.timeout(30_000),
      });
      if (!res.ok) continue;
      const data = await res.json();
      const got = new Map(
        (data.data || []).map((d) => [d.cve.toUpperCase(), { epss: Number(d.epss), percentile: Number(d.percentile), date: d.date }])
      );
      for (const id of chunk) {
        const v = got.get(id) || null;
        await cacheSet(`epss:${id}`, v);
        if (v) out.set(id, v);
      }
    } catch {
      /* EPSS is enrichment only */
    }
  }
  return out;
}

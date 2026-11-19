import { cacheGet, cacheGetStale, cacheSet } from "./cache.js";

export const KEV_URL =
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const TTL = Number(process.env.KEV_TTL_HOURS || 6) * 3600_000;

let index = null; // { catalog, byId: Map }

async function fetchCatalog() {
  const res = await fetch(KEV_URL, {
    headers: { "User-Agent": "vuln-watch-mcp/0.1" },
    signal: AbortSignal.timeout(60_000),
  });
  if (!res.ok) throw new Error(`KEV feed HTTP ${res.status}`);
  return res.json();
}

/** Loads the CISA KEV catalog (cached). Falls back to stale cache if offline. */
export async function loadKev() {
  if (index && Date.now() - index.loadedAt < TTL) return index;
  let catalog = await cacheGet(KEV_URL, TTL);
  if (!catalog) {
    try {
      catalog = await fetchCatalog();
      await cacheSet(KEV_URL, catalog);
    } catch (err) {
      catalog = await cacheGetStale(KEV_URL);
      if (!catalog) throw err;
    }
  }
  const byId = new Map(catalog.vulnerabilities.map((v) => [v.cveID.toUpperCase(), v]));
  index = { catalog, byId, loadedAt: Date.now() };
  return index;
}

export async function getKevEntry(cveId) {
  const { byId } = await loadKev();
  return byId.get(cveId.toUpperCase()) || null;
}

const norm = (s) => String(s || "").toLowerCase();

/**
 * Search KEV catalog.
 * @param {{query?:string, vendor?:string, product?:string, days?:number, ransomwareOnly?:boolean, limit?:number}} opts
 */
export async function searchKev(opts = {}) {
  const { catalog } = await loadKev();
  const q = norm(opts.query);
  const vendor = norm(opts.vendor);
  const product = norm(opts.product);
  const since = opts.days ? Date.now() - opts.days * 86400_000 : null;

  let rows = catalog.vulnerabilities.filter((v) => {
    if (vendor && !norm(v.vendorProject).includes(vendor)) return false;
    if (product && !norm(v.product).includes(product)) return false;
    if (since && new Date(v.dateAdded).getTime() < since) return false;
    if (opts.ransomwareOnly && v.knownRansomwareCampaignUse !== "Known") return false;
    if (q) {
      const hay = norm(
        [v.cveID, v.vendorProject, v.product, v.vulnerabilityName, v.shortDescription, v.notes].join(" ")
      );
      if (!q.split(/\s+/).every((t) => hay.includes(t))) return false;
    }
    return true;
  });
  rows.sort((a, b) => b.dateAdded.localeCompare(a.dateAdded));
  const total = rows.length;
  if (opts.limit) rows = rows.slice(0, opts.limit);
  return { total, rows, catalogVersion: catalog.catalogVersion, dateReleased: catalog.dateReleased };
}

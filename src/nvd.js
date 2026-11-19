import { cacheGet, cacheSet } from "./cache.js";

export const NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const API_KEY = process.env.NVD_API_KEY || "";
const TTL = Number(process.env.NVD_TTL_HOURS || 12) * 3600_000;
// NVD public rate limits: 5 req / 30s without key, 50 req / 30s with key.
const MIN_INTERVAL_MS = API_KEY ? 700 : 6500;

let queue = Promise.resolve();
let lastRequestAt = 0;

function throttle() {
  const run = queue.then(async () => {
    const wait = lastRequestAt + MIN_INTERVAL_MS - Date.now();
    if (wait > 0) await new Promise((r) => setTimeout(r, wait));
    lastRequestAt = Date.now();
  });
  queue = run.catch(() => {});
  return run;
}

export function hasApiKey() {
  return Boolean(API_KEY);
}

/** Raw NVD CVE API 2.0 query with throttling, retries and caching. */
export async function nvdQuery(params) {
  const usp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === false) continue;
    // boolean flags like hasKev / noRejected are sent without a value
    if (v === true) usp.append(k, "");
    else usp.append(k, String(v));
  }
  const qs = usp.toString().replace(/=(&|$)/g, "$1");
  const url = `${NVD_URL}?${qs}`;

  const cached = await cacheGet(url, TTL);
  if (cached) return cached;

  let lastErr;
  for (let attempt = 0; attempt < 4; attempt++) {
    await throttle();
    try {
      const res = await fetch(url, {
        headers: {
          "User-Agent": "vuln-watch-mcp/0.1",
          ...(API_KEY ? { apiKey: API_KEY } : {}),
        },
        signal: AbortSignal.timeout(60_000),
      });
      if (res.ok) {
        const data = await res.json();
        await cacheSet(url, data);
        return data;
      }
      if (res.status === 404) return { totalResults: 0, vulnerabilities: [] };
      const msg = res.headers.get("message") || "";
      lastErr = new Error(`NVD HTTP ${res.status} ${msg}`.trim());
      if (![403, 429, 500, 502, 503, 504].includes(res.status)) break;
    } catch (err) {
      lastErr = err;
    }
    await new Promise((r) => setTimeout(r, 2000 * 2 ** attempt));
  }
  throw lastErr;
}

/** Fetch a single CVE by ID. */
export async function getCve(cveId) {
  const data = await nvdQuery({ cveId: cveId.toUpperCase() });
  return data.vulnerabilities?.[0]?.cve || null;
}

/**
 * Query returning the most recent `limit` results (NVD returns oldest first,
 * so we jump to the last page).
 */
export async function nvdQueryLatest(params, limit) {
  const first = await nvdQuery({ ...params, resultsPerPage: limit, startIndex: 0 });
  const total = first.totalResults || 0;
  if (total <= limit) return { total, cves: (first.vulnerabilities || []).map((v) => v.cve) };
  const last = await nvdQuery({ ...params, resultsPerPage: limit, startIndex: total - limit });
  return { total, cves: (last.vulnerabilities || []).map((v) => v.cve) };
}

/** Query all pages (bounded) – used for component/version matching. */
export async function nvdQueryAll(params, maxResults = 200) {
  const out = [];
  let startIndex = 0;
  let total = 0;
  do {
    const data = await nvdQuery({ ...params, resultsPerPage: Math.min(2000, maxResults), startIndex });
    total = data.totalResults || 0;
    out.push(...(data.vulnerabilities || []).map((v) => v.cve));
    startIndex += data.resultsPerPage || data.vulnerabilities?.length || 0;
    if (!data.vulnerabilities?.length) break;
  } while (startIndex < total && out.length < maxResults);
  return { total, cves: out };
}

// ---------- Parsing helpers ----------

const SEV_RANK = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, NONE: 0 };
export const severityRank = (s) => SEV_RANK[String(s || "").toUpperCase()] ?? -1;

export function bestMetric(cve) {
  const m = cve.metrics || {};
  const pick = (arr) => (arr || []).find((x) => x.type === "Primary") || (arr || [])[0];
  for (const [key, ver] of [
    ["cvssMetricV40", "4.0"],
    ["cvssMetricV31", "3.1"],
    ["cvssMetricV30", "3.0"],
  ]) {
    const x = pick(m[key]);
    if (x) {
      return {
        version: ver,
        score: x.cvssData.baseScore,
        severity: x.cvssData.baseSeverity,
        vector: x.cvssData.vectorString,
        source: x.source,
      };
    }
  }
  const v2 = pick(m.cvssMetricV2);
  if (v2) {
    return {
      version: "2.0",
      score: v2.cvssData.baseScore,
      severity: v2.baseSeverity,
      vector: v2.cvssData.vectorString,
      source: v2.source,
    };
  }
  return null;
}

export function description(cve) {
  return (cve.descriptions || []).find((d) => d.lang === "en")?.value || "";
}

export function cwes(cve) {
  const set = new Set();
  for (const w of cve.weaknesses || []) {
    for (const d of w.description || []) if (/^CWE-\d+$/.test(d.value)) set.add(d.value);
  }
  return [...set];
}

/** Parse a CPE 2.3 string into named parts. */
export function parseCpe(cpe) {
  const p = cpe.split(":");
  return {
    part: p[2],
    vendor: p[3],
    product: p[4],
    version: p[5],
    update: p[6],
    targetSw: p[10],
  };
}

/** Flatten vulnerable CPE match ranges out of configurations. */
export function affectedRanges(cve) {
  const out = [];
  for (const conf of cve.configurations || []) {
    for (const node of conf.nodes || []) {
      for (const m of node.cpeMatch || []) {
        if (!m.vulnerable) continue;
        const c = parseCpe(m.criteria);
        out.push({
          criteria: m.criteria,
          vendor: c.vendor,
          product: c.product,
          targetSw: c.targetSw,
          exactVersion:
            c.version !== "*" && c.version !== "-"
              ? c.version + (c.update && c.update !== "*" && c.update !== "-" ? `-${c.update}` : "")
              : null,
          versionStartIncluding: m.versionStartIncluding,
          versionStartExcluding: m.versionStartExcluding,
          versionEndExcluding: m.versionEndExcluding,
          versionEndIncluding: m.versionEndIncluding,
        });
      }
    }
  }
  return out;
}

export function references(cve) {
  return (cve.references || []).map((r) => ({ url: r.url, tags: r.tags || [] }));
}

// ---------- Version helpers ----------

function tokens(v) {
  return String(v)
    .replace(/^v/i, "")
    .split(/[.\-+_]/)
    .map((t) => (/^\d+$/.test(t) ? Number(t) : t.toLowerCase()));
}

/** Loose version compare (works for semver, pep440-ish, dotted versions). */
export function compareVersions(a, b) {
  const ta = tokens(a);
  const tb = tokens(b);
  const n = Math.max(ta.length, tb.length);
  for (let i = 0; i < n; i++) {
    const x = ta[i];
    const y = tb[i];
    if (x === undefined) return typeof y === "number" ? (y === 0 ? 0 : -1) : 1; // 1.0 < 1.0.1, 1.0 > 1.0-rc
    if (y === undefined) return typeof x === "number" ? (x === 0 ? 0 : 1) : -1;
    if (x === y) continue;
    if (typeof x === "number" && typeof y === "number") return x < y ? -1 : 1;
    if (typeof x === "number") return 1;
    if (typeof y === "number") return -1;
    return x < y ? -1 : 1;
  }
  return 0;
}

export function versionInRange(version, r) {
  if (!version) return false;
  if (r.exactVersion) return compareVersions(version, r.exactVersion) === 0;
  if (r.versionStartIncluding && compareVersions(version, r.versionStartIncluding) < 0) return false;
  if (r.versionStartExcluding && compareVersions(version, r.versionStartExcluding) <= 0) return false;
  if (r.versionEndExcluding && compareVersions(version, r.versionEndExcluding) >= 0) return false;
  if (r.versionEndIncluding && compareVersions(version, r.versionEndIncluding) > 0) return false;
  return Boolean(
    r.versionStartIncluding || r.versionStartExcluding || r.versionEndExcluding || r.versionEndIncluding
  );
}

/**
 * Derive remediation guidance (minimum safe version) for a given product/version
 * from the CVE's configuration ranges.
 */
export function fixGuidance(cve, product, version) {
  const prod = product ? product.toLowerCase() : null;
  const ranges = affectedRanges(cve).filter((r) => !prod || r.product?.toLowerCase() === prod);
  const matching = version ? ranges.filter((r) => versionInRange(version, r)) : ranges;
  const pool = matching.length ? matching : ranges;
  const fixed = [];
  const notes = [];
  for (const r of pool) {
    if (r.versionEndExcluding) fixed.push(r.versionEndExcluding);
    else if (r.versionEndIncluding) notes.push(`> ${r.versionEndIncluding} (last vulnerable: ${r.versionEndIncluding})`);
    else if (r.exactVersion) notes.push(`not ${r.exactVersion}`);
  }
  fixed.sort(compareVersions);
  return {
    matchedRanges: matching.length,
    // version falls inside these ranges → smallest end-of-range is the nearest fixed release
    minimumFixedVersion: matching.length && fixed.length ? fixed[0] : null,
    allFixedVersions: [...new Set(fixed)],
    notes: [...new Set(notes)],
    ranges: pool,
  };
}

import { cacheGet, cacheSet } from "./cache.js";
import { compareVersions } from "./nvd.js";

// Package registry metadata: latest version, deprecation/yank status, last release date.
const TTL = 6 * 3600_000;
const UA = { "User-Agent": "vuln-watch-mcp (https://github.com/charles96/vuln-watch-mcp)" };

async function getJson(url, headers = {}) {
  const res = await fetch(url, { headers: { ...UA, ...headers }, signal: AbortSignal.timeout(20_000) });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

const isStable = (v) => !/[-.]?(alpha|beta|rc|pre|dev|preview|snapshot|canary|next|milestone)|[-.](a|b|m|cr)\d/i.test(String(v).replace(/^\d+(\.\d+)*/, (m) => m + "|").split("|")[1] || "");
const goEscape = (p) => p.replace(/[A-Z]/g, (c) => "!" + c.toLowerCase());

const FETCHERS = {
  async npm(name, version) {
    const j = await getJson(`https://registry.npmjs.org/${name.replace("/", "%2F")}`, { Accept: "application/vnd.npm.install-v1+json" });
    if (!j) return null;
    const latest = j["dist-tags"]?.latest;
    return {
      latest,
      versions: Object.keys(j.versions || {}),
      deprecated: /-security$/.test(latest || "")
        ? "npm replaced this package with a security placeholder (the package was removed for being malicious) — remove it"
        : j.versions?.[latest]?.deprecated || null,
      currentDeprecated: j.versions?.[version]?.deprecated || null,
      lastModified: j.modified?.slice(0, 10),
      url: `https://www.npmjs.com/package/${name}`,
    };
  },
  async pypi(name, version) {
    const j = await getJson(`https://pypi.org/pypi/${encodeURIComponent(name)}/json`);
    if (!j) return null;
    const latest = j.info?.version;
    const rel = (v) => j.releases?.[v] || [];
    const cur = rel(version);
    return {
      latest,
      versions: Object.keys(j.releases || {}).filter((v) => rel(v).length),
      latestReleased: rel(latest)[0]?.upload_time?.slice(0, 10),
      currentYanked: cur.length > 0 && cur.every((f) => f.yanked) ? cur[0].yanked_reason || "yanked" : null,
      deprecated: /inactive|deprecated|unmaintained/i.test((j.info?.classifiers || []).join(" ")) ? "marked inactive/deprecated in classifiers" : null,
      url: `https://pypi.org/project/${name}/`,
    };
  },
  async go(name) {
    const j = await getJson(`https://proxy.golang.org/${goEscape(name)}/@latest`);
    if (!j) return null;
    return { latest: j.Version?.replace(/^v/, ""), latestReleased: j.Time?.slice(0, 10), url: `https://pkg.go.dev/${name}` };
  },
  async cargo(name, version) {
    const j = await getJson(`https://crates.io/api/v1/crates/${name}`);
    if (!j) return null;
    const cur = (j.versions || []).find((v) => v.num === version);
    return {
      latest: j.crate?.max_stable_version || j.crate?.newest_version,
      versions: (j.versions || []).filter((v) => !v.yanked).map((v) => v.num),
      latestReleased: j.crate?.updated_at?.slice(0, 10),
      currentYanked: cur?.yanked ? "yanked" : null,
      url: `https://crates.io/crates/${name}`,
    };
  },
  async rubygems(name) {
    const j = await getJson(`https://rubygems.org/api/v1/gems/${name}.json`);
    if (!j) return null;
    return { latest: j.version, latestReleased: j.version_created_at?.slice(0, 10), url: j.project_uri };
  },
  async composer(name) {
    const j = await getJson(`https://repo.packagist.org/p2/${name}.json`);
    const list = j?.packages?.[name];
    if (!list?.length) return null;
    const stable = list.find((p) => isStable(p.version)) || list[0];
    return {
      latest: stable.version.replace(/^v/, ""),
      versions: list.map((p) => p.version.replace(/^v/, "")),
      latestReleased: stable.time?.slice(0, 10),
      deprecated: stable.abandoned ? `abandoned${typeof stable.abandoned === "string" ? ` → use ${stable.abandoned}` : ""}` : null,
      url: `https://packagist.org/packages/${name}`,
    };
  },
  async nuget(name) {
    const j = await getJson(`https://api.nuget.org/v3-flatcontainer/${name.toLowerCase()}/index.json`);
    if (!j?.versions?.length) return null;
    const stable = j.versions.filter(isStable).sort(compareVersions);
    return { latest: (stable.length ? stable : j.versions).at(-1), versions: j.versions, url: `https://www.nuget.org/packages/${name}` };
  },
  async pub(name, version) {
    const j = await getJson(`https://pub.dev/api/packages/${name}`);
    if (!j?.latest) return null;
    const cur = (j.versions || []).find((v) => v.version === version);
    return {
      latest: j.latest.version,
      versions: (j.versions || []).map((v) => v.version),
      latestReleased: j.latest.published?.slice(0, 10),
      currentYanked: cur?.retracted ? "retracted" : null,
      deprecated: j.isDiscontinued ? `discontinued${j.replacedBy ? ` → use ${j.replacedBy}` : ""}` : null,
      url: `https://pub.dev/packages/${name}`,
    };
  },
  async hex(name, version) {
    const j = await getJson(`https://hex.pm/api/packages/${name}`);
    if (!j) return null;
    const ret = j.retirements?.[version];
    const releases = j.releases || [];
    return {
      latest: j.latest_stable_version || j.latest_version,
      versions: releases.map((r) => r.version),
      latestReleased: releases.find((r) => r.version === (j.latest_stable_version || j.latest_version))?.inserted_at?.slice(0, 10),
      currentYanked: ret ? `retired: ${ret.reason}${ret.message ? ` — ${ret.message}` : ""}` : null,
      url: j.html_url || `https://hex.pm/packages/${name}`,
    };
  },
  async cran(name) {
    const j = await getJson(`https://crandb.r-pkg.org/${name}`);
    if (!j?.Version) return null;
    return { latest: j.Version, latestReleased: (j["Date/Publication"] || "").slice(0, 10) || undefined, url: `https://cran.r-project.org/package=${name}` };
  },
  async maven(name) {
    const [g, a] = name.split(":");
    const res = await fetch(`https://repo1.maven.org/maven2/${g.replace(/\./g, "/")}/${a}/maven-metadata.xml`, { headers: UA, signal: AbortSignal.timeout(20_000) });
    if (!res.ok) return null;
    const xml = await res.text();
    const versions = [...xml.matchAll(/<version>([^<]+)<\/version>/g)].map((m) => m[1]);
    const stable = versions.filter(isStable).sort(compareVersions);
    const release = xml.match(/<release>([^<]+)<\/release>/)?.[1];
    const latest = release && isStable(release) ? release : stable.at(-1) || versions.at(-1);
    const lu = xml.match(/<lastUpdated>(\d{8})/)?.[1];
    return {
      latest,
      versions,
      latestReleased: lu ? `${lu.slice(0, 4)}-${lu.slice(4, 6)}-${lu.slice(6, 8)}` : undefined,
      url: `https://central.sonatype.com/artifact/${g}/${a}`,
    };
  },
};

/** Registry info for a package; null when unsupported/unavailable. */
export async function getRegistryInfo(dep) {
  const fn = FETCHERS[dep.ecosystem];
  if (!fn || (dep.ecosystem === "go" && dep.name === "stdlib")) return null;
  const key = `reg:${dep.ecosystem}:${dep.name}@${dep.version}`;
  const hit = await cacheGet(key, TTL);
  if (hit !== undefined) return hit;
  let info = null;
  try {
    info = await fn(dep.name, dep.version);
  } catch {
    return null;
  }
  if (info) {
    const ref = info.latestReleased || info.lastModified;
    if (info.latestReleased) {
      const ageDays = (Date.now() - new Date(info.latestReleased).getTime()) / 86400_000;
      if (ageDays > 730) info.stale = `no release for ${Math.floor(ageDays / 365)}+ years (last ${info.latestReleased})`;
    }
    info.referenceDate = ref;
  }
  await cacheSet(key, info);
  return info;
}

/**
 * Smallest published version >= target on the same major line as `target`
 * (falls back to target when version list is unknown).
 */
export function nearestPublished(info, target) {
  if (!info?.versions?.length) return target;
  const major = String(target).split(".")[0];
  const cands = info.versions
    .filter((v) => isStable(v) && compareVersions(v, target) >= 0 && String(v).split(".")[0] === major)
    .sort(compareVersions);
  return cands[0] || target;
}

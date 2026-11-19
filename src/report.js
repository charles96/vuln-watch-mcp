import { bestMetric, cwes, description, fixGuidance, references, severityRank, affectedRanges, compareVersions } from "./nvd.js";
import { cweGuidance } from "./remediation.js";
import { ECOSYSTEMS } from "./ecosystems.js";
import { OSV_ECOSYSTEM } from "./osv.js";
import { cvss3Score, severityFromScore } from "./cvss.js";

const REF_PRIORITY = ["Patch", "FIX", "Vendor Advisory", "ADVISORY", "Mitigation", "Release Notes", "PACKAGE", "Third Party Advisory", "Exploit", "Issue Tracking", "REPORT", "WEB", "ARTICLE"];

/** Extract "fixed in / update to version X" hints from the CVE description. */
export function descriptionFixVersions(desc) {
  const out = new Set();
  const re = /(?:fixed in|patched in|resolved in|addressed in|update to|upgrade to|updating to|upgrading to|fix(?:ed)? (?:is )?available in|latest available version)[^.]*?(?=\d+\.\d+)((?:[^.]|\.(?=\d))*)/gi;
  for (const m of desc.matchAll(re)) {
    for (const v of m[1].matchAll(/\bv?(\d+\.\d+(?:\.\d+)*(?:-[0-9A-Za-z]+)?)/g)) out.add(v[1]);
  }
  return [...out];
}

function rankRefs(refs, max) {
  const seen = new Set();
  refs = refs.filter((r) => (seen.has(r.url) ? false : seen.add(r.url)));
  const score = (r) => {
    const i = Math.min(...r.tags.map((t) => { const x = REF_PRIORITY.indexOf(t); return x < 0 ? 99 : x; }), 99);
    const gh = /github\.com\/.+\/(commit|pull|security\/advisories)|GHSA-/.test(r.url) ? -0.5 : 0;
    return i + gh;
  };
  return [...refs].sort((a, b) => score(a) - score(b)).slice(0, max);
}

function rangeText(r) {
  if (r.exactVersion) return `= ${r.exactVersion}`;
  const parts = [];
  if (r.versionStartIncluding) parts.push(`>= ${r.versionStartIncluding}`);
  if (r.versionStartExcluding) parts.push(`> ${r.versionStartExcluding}`);
  if (r.versionEndExcluding) parts.push(`< ${r.versionEndExcluding}`);
  if (r.versionEndIncluding) parts.push(`<= ${r.versionEndIncluding}`);
  return parts.join(", ") || "all versions";
}

function kevInfo(kev) {
  return kev
    ? {
        dateAdded: kev.dateAdded,
        dueDate: kev.dueDate,
        name: kev.vulnerabilityName,
        requiredAction: kev.requiredAction,
        ransomware: kev.knownRansomwareCampaignUse,
        notes: kev.notes,
      }
    : null;
}

function upgradeFor(pkg, version) {
  const eco = pkg?.ecosystem && ECOSYSTEMS[pkg.ecosystem];
  if (!version || !eco) return null;
  let cmd = eco.upgrade(pkg.name, version);
  if (pkg.direct === false && eco.transitiveHint) cmd += `\n    ${eco.transitiveHint(pkg.name, version)}`;
  return cmd;
}

const pkgInfo = (pkg) =>
  pkg
    ? { name: pkg.name, version: pkg.version, ecosystem: pkg.ecosystem, direct: pkg.direct ?? null, confidence: pkg.confidence || "high", source: pkg.source, versionSource: pkg.versionSource, declared: pkg.declared }
    : null;

/** Human hint about how reliable the package version is. */
export function versionNote(p) {
  if (!p) return null;
  if (p.versionSource === "range")
    return `⚠️ Version estimated from the declared range \`${p.declared ?? p.version}\` (no lockfile / installed packages found) — if a newer version is actually installed this may be a false positive. Add a lockfile for exact results.`;
  if (p.versionSource === "resolved")
    return `ℹ️ Version computed by resolving the Maven/Gradle graph (parent POM / BOM / transitive) — verify with \`mvn dependency:tree\` or \`gradle dependencies\` if in doubt.`;
  return null;
}

/**
 * Build a normalised, agent-friendly finding from an NVD CVE (+ optional KEV entry + package context).
 * pkg: { name, version, ecosystem, direct, product }
 */
export function buildFinding(cve, kev, pkg = null, { maxRefs = 6 } = {}) {
  const metric = bestMetric(cve);
  const weaknesses = cwes(cve);
  const fix = pkg ? fixGuidance(cve, pkg.product, pkg.version) : null;
  const descText = description(cve).replace(/\s*\n\s*/g, " ").trim();
  const descFixes = descriptionFixVersions(descText);
  // Recommended version: NVD range end; raise it if the description names a later fix on the same major line,
  // and fall back to the description when NVD has no end-exclusive bound.
  let recommended = fix?.minimumFixedVersion || null;
  let recommendedSource = recommended ? "NVD" : null;
  if (pkg) {
    const major = (v) => String(v).split(".")[0];
    const candidates = descFixes.filter((v) => !pkg.version || compareVersions(v, pkg.version) > 0);
    if (recommended) {
      const later = candidates.filter((v) => major(v) === major(recommended) && compareVersions(v, recommended) > 0).sort(compareVersions);
      if (later.length) { recommended = later[later.length - 1]; recommendedSource = "description (NVD range says " + fix.minimumFixedVersion + ")"; }
    } else if (candidates.length && fix?.matchedRanges) {
      recommended = candidates.sort(compareVersions)[0];
      recommendedSource = "CVE description";
    }
  }
  const ranges = (fix ? fix.ranges : affectedRanges(cve)).slice(0, 8).map((r) => ({
    cpe: `${r.vendor}:${r.product}${r.targetSw && r.targetSw !== "*" ? ` (${r.targetSw})` : ""}`,
    range: rangeText(r),
  }));
  return {
    id: cve.id,
    aliases: [],
    sources: ["NVD"],
    malicious: false,
    title: null,
    published: cve.published?.slice(0, 10),
    lastModified: cve.lastModified?.slice(0, 10),
    status: cve.vulnStatus,
    severity: metric?.severity || "UNSCORED",
    score: metric?.score ?? null,
    cvss: metric ? `CVSS ${metric.version} ${metric.vector.replace(/\/[A-Z]+:X/g, "")}` : null,
    description: descText,
    cwes: weaknesses,
    codeFixGuidance: cweGuidance(weaknesses),
    affected: ranges,
    package: pkgInfo(pkg),
    fixedVersion: recommended,
    fixedVersionSource: recommendedSource,
    fixVersionsInDescription: descFixes,
    fixedVersionsAll: fix?.allFixedVersions || [],
    fixNotes: fix?.notes || [],
    upgradeCommand: upgradeFor(pkg, recommended),
    kev: kevInfo(kev),
    epss: null,
    references: rankRefs(references(cve), maxRefs),
    nvdUrl: `https://nvd.nist.gov/vuln/detail/${cve.id}`,
    advisoryUrl: null,
  };
}

// ---------------- OSV ----------------

const normName = (eco, n) => (eco === "pypi" ? n.toLowerCase().replace(/[-_.]+/g, "-") : n.toLowerCase());

/** Compute affected intervals + fixed version for `dep` from OSV records. */
export function osvFix(records, dep) {
  const eco = OSV_ECOSYSTEM[dep.ecosystem];
  const want = normName(dep.ecosystem, dep.name);
  const intervals = [];
  let explicit = false;
  for (const r of records) {
    for (const a of r.affected || []) {
      if (a.package?.ecosystem !== eco || normName(dep.ecosystem, a.package.name || "") !== want) continue;
      if ((a.versions || []).includes(dep.version)) explicit = true;
      for (const range of a.ranges || []) {
        if (range.type === "GIT") continue;
        let intro = null;
        for (const ev of range.events || []) {
          if (ev.introduced !== undefined) intro = ev.introduced;
          else if (ev.fixed !== undefined) { intervals.push({ intro, fixed: ev.fixed }); intro = null; }
          else if (ev.last_affected !== undefined) { intervals.push({ intro, lastAffected: ev.last_affected }); intro = null; }
          else if (ev.limit !== undefined) { intervals.push({ intro, limit: ev.limit }); intro = null; }
        }
        if (intro !== null) intervals.push({ intro });
      }
    }
  }
  const inIv = (v, iv) =>
    (iv.intro == null || iv.intro === "0" || compareVersions(v, iv.intro) >= 0) &&
    (iv.fixed ? compareVersions(v, iv.fixed) < 0 : iv.lastAffected ? compareVersions(v, iv.lastAffected) <= 0 : iv.limit ? compareVersions(v, iv.limit) < 0 : true);
  const containing = dep.version ? intervals.filter((iv) => inIv(dep.version, iv)) : [];
  const fixes = containing.filter((iv) => iv.fixed).map((iv) => iv.fixed).sort(compareVersions);
  const ivText = (iv) =>
    [iv.intro && iv.intro !== "0" ? `>= ${iv.intro}` : null, iv.fixed ? `< ${iv.fixed}` : iv.lastAffected ? `<= ${iv.lastAffected}` : iv.limit ? `< ${iv.limit}` : "(no fix yet)"]
      .filter(Boolean)
      .join(", ");
  const notes = [];
  if (containing.some((iv) => iv.lastAffected)) notes.push(`no fixed release recorded; last affected ${containing.find((iv) => iv.lastAffected).lastAffected}`);
  if (containing.length && containing.every((iv) => !iv.fixed && !iv.lastAffected && !iv.limit)) notes.push("no fixed version published yet");
  return {
    matched: containing.length > 0 || explicit,
    fixedVersion: fixes[0] || null,
    allFixed: [...new Set(intervals.filter((iv) => iv.fixed).map((iv) => iv.fixed))].sort(compareVersions),
    ranges: [...new Set(intervals.map(ivText))].slice(0, 8),
    notes,
  };
}

export function osvSeverity(records) {
  for (const r of records) {
    const v3 = (r.severity || []).find((s) => s.type === "CVSS_V3");
    if (v3) {
      const score = cvss3Score(v3.score);
      if (score != null) return { score, severity: severityFromScore(score), cvss: `CVSS ${v3.score.slice(5, 8)} ${v3.score}` };
    }
  }
  for (const r of records) {
    const v4 = (r.severity || []).find((s) => s.type === "CVSS_V4");
    const label = r.database_specific?.severity || r.affected?.find((a) => a.ecosystem_specific?.severity)?.ecosystem_specific?.severity;
    if (label || v4) {
      const sev = String(label || "").toUpperCase().replace("MODERATE", "MEDIUM") || "UNSCORED";
      return { score: null, severity: sev, cvss: v4 ? `CVSS 4.0 ${v4.score}` : null };
    }
  }
  return { score: null, severity: "UNSCORED", cvss: null };
}

/**
 * Build a finding from a group of duplicate OSV records (same CVE) for a package.
 * kevLookup: (cveId) => KEV entry | null
 */
export function buildOsvFinding(group, dep, kevLookup, { maxRefs = 6 } = {}) {
  const all = [group.primary, ...group.others];
  const p = group.primary;
  const ids = [...new Set(all.flatMap((r) => [r.id, ...(r.aliases || [])]))];
  const cve = ids.find((x) => /^CVE-\d{4}-\d+$/.test(x)) || null;
  const malicious = all.some(
    (r) => r.id.startsWith("MAL-") || (r.database_specific?.cwe_ids || []).includes("CWE-506") || /^malicious (code|package)/i.test(r.summary || "")
  );
  const fix = osvFix(all, dep);
  const sev = malicious ? { score: null, severity: "CRITICAL", cvss: null } : osvSeverity(all);
  const weaknesses = [...new Set(all.flatMap((r) => r.database_specific?.cwe_ids || []))];
  const details = (p.details || "").replace(/\s*\n\s*/g, " ").trim();
  const desc = [p.summary, details && details !== p.summary ? details : null].filter(Boolean).join(" — ");
  const ghsa = ids.find((x) => x.startsWith("GHSA-"));
  const kev = cve ? kevLookup(cve) : null;
  const refs = all.flatMap((r) => (r.references || []).map((x) => ({ url: x.url, tags: [x.type] })));
  return {
    id: cve || p.id,
    aliases: ids.filter((x) => x !== (cve || p.id)),
    sources: ["OSV"],
    malicious,
    title: p.summary || null,
    published: p.published?.slice(0, 10),
    lastModified: p.modified?.slice(0, 10),
    status: p.database_specific?.github_reviewed === false ? "unreviewed" : "published",
    severity: sev.severity,
    score: sev.score,
    cvss: sev.cvss,
    description: desc.length > 1800 ? desc.slice(0, 1800) + "…" : desc,
    cwes: weaknesses,
    codeFixGuidance: cweGuidance(weaknesses),
    affected: fix.ranges.map((r) => ({ cpe: `${dep.name} (${dep.ecosystem})`, range: r })),
    package: pkgInfo(dep),
    fixedVersion: malicious ? null : fix.fixedVersion,
    fixedVersionSource: fix.fixedVersion ? "OSV" : null,
    fixVersionsInDescription: [],
    fixedVersionsAll: fix.allFixed,
    fixNotes: fix.notes,
    upgradeCommand: malicious ? null : upgradeFor(dep, fix.fixedVersion),
    kev: kevInfo(kev),
    epss: null,
    references: rankRefs(refs, maxRefs),
    nvdUrl: cve ? `https://nvd.nist.gov/vuln/detail/${cve}` : null,
    advisoryUrl: ghsa ? `https://github.com/advisories/${ghsa}` : `https://osv.dev/vulnerability/${p.id}`,
    matched: fix.matched,
  };
}

/** Merge an NVD finding into an OSV finding for the same CVE + package. */
export function mergeFindings(osv, nvd) {
  osv.sources = [...new Set([...osv.sources, ...nvd.sources])];
  if (osv.score == null && nvd.score != null) Object.assign(osv, { score: nvd.score, severity: nvd.severity, cvss: nvd.cvss });
  if (!osv.fixedVersion && nvd.fixedVersion) Object.assign(osv, { fixedVersion: nvd.fixedVersion, fixedVersionSource: nvd.fixedVersionSource, upgradeCommand: nvd.upgradeCommand });
  osv.cwes = [...new Set([...osv.cwes, ...nvd.cwes])];
  osv.codeFixGuidance = cweGuidance(osv.cwes);
  osv.status = nvd.status ? `${osv.status}; NVD: ${nvd.status}` : osv.status;
  osv.references = rankRefs([...osv.references, ...nvd.references], Math.max(osv.references.length, 8));
  osv.nvdDescription = nvd.description !== osv.description ? nvd.description : undefined;
  return osv;
}

export function attachEpss(findings, epssMap) {
  for (const f of findings) {
    const e = epssMap.get(f.id);
    if (e) f.epss = { probability: e.epss, percentile: e.percentile, date: e.date };
  }
  return findings;
}

const EPSS_HIGH = 0.1; // >= 10% chance of exploitation within 30 days

/**
 * Priority order: malicious package → CISA KEV → high EPSS → HIGH/CRITICAL → EPSS → newest.
 * by: "priority" (default) | "recent" | "severity"
 */
export function sortFindings(list, { by = "priority" } = {}) {
  const ep = (f) => f.epss?.probability ?? -1;
  return list.sort((a, b) => {
    if (a.malicious !== b.malicious) return a.malicious ? -1 : 1;
    if (by === "severity") return (b.score ?? -1) - (a.score ?? -1) || (b.published || "").localeCompare(a.published || "");
    if (!!b.kev !== !!a.kev) return b.kev ? 1 : -1;
    if (by === "priority") {
      const ea = ep(a) >= EPSS_HIGH, eb = ep(b) >= EPSS_HIGH;
      if (ea !== eb) return eb ? 1 : -1;
      const sa = severityRank(a.severity) >= 3, sb = severityRank(b.severity) >= 3;
      if (sa !== sb) return sb ? 1 : -1;
      if (ep(a) !== ep(b)) return ep(b) - ep(a);
    }
    return (b.published || "").localeCompare(a.published || "") || (b.score ?? -1) - (a.score ?? -1);
  });
}

const pct = (x) => `${(x * 100).toFixed(x < 0.01 ? 2 : 1)}%`;

export function findingToMarkdown(f, { verbose = true } = {}) {
  const tags = [];
  if (f.malicious) tags.push("🚨 MALICIOUS PACKAGE");
  if (f.kev) tags.push("🔥 ACTIVELY EXPLOITED (CISA KEV)");
  if (f.epss && f.epss.probability >= EPSS_HIGH) tags.push(`⚠️ EPSS ${pct(f.epss.probability)}`);
  tags.push(`${f.severity}${f.score != null ? ` ${f.score}` : ""}`);
  const head = f.package ? ` — ${f.package.name}@${f.package.version}${f.package.direct === false ? " (transitive)" : ""}` : "";
  const L = [`### ${f.id}${head}  [${tags.join(" | ")}]`];
  if (f.title && !f.description.startsWith(f.title)) L.push(`- Title: ${f.title}`);
  if (f.aliases?.length) L.push(`- Also known as: ${f.aliases.join(", ")}`);
  L.push(`- Published: ${f.published} · Modified: ${f.lastModified} · Status: ${f.status} · Sources: ${f.sources.join(" + ")}`);
  if (f.package?.source) L.push(`- Found in: ${f.package.source}`);
  const vn = versionNote(f.package);
  if (vn) L.push(`- ${vn}`);
  if (f.package?.confidence && f.package.confidence !== "high") L.push(`- Match confidence: ${f.package.confidence} (NVD CPE name match, platform not specific to ${f.package.ecosystem} — verify it is the same project)`);
  if (f.malicious) {
    L.push(`- 🚨 This package version is flagged as MALICIOUS. Remove it immediately, check whether install scripts ran (CI and dev machines), and rotate any credentials/tokens available in those environments.`);
  }
  if (f.suppressionOverridden) L.push(`- ⚠️ Suppressed in .vulnwatch.json ("${f.suppressionOverridden.reason}") but still shown: ${f.suppressionOverridden.why}. Confirm with the user before ignoring it.`);
  L.push(`- Summary: ${f.description.length > 900 ? f.description.slice(0, 900) + "… (truncated; see advisory)" : f.description}`);
  if (f.nvdDescription && verbose && f.nvdDescription.length < 600) L.push(`- NVD description: ${f.nvdDescription}`);
  if (f.cvss) L.push(`- ${f.cvss}`);
  if (f.epss) L.push(`- EPSS: ${pct(f.epss.probability)} probability of exploitation in next 30 days (percentile ${pct(f.epss.percentile)}, ${f.epss.date})`);
  if (f.fixedVersion) L.push(`- ✅ Fixed in: **${f.fixedVersion}**${f.fixedVersionSource && !["NVD", "OSV"].includes(f.fixedVersionSource) ? ` (source: ${f.fixedVersionSource})` : ""}${f.fixedVersionsAll.length > 1 ? ` (fixed releases per branch: ${f.fixedVersionsAll.join(", ")})` : ""}`);
  else if (f.fixedVersionsAll.length) L.push(`- Fixed releases per branch: ${f.fixedVersionsAll.join(", ")}`);
  if (!f.fixedVersion && f.fixVersionsInDescription?.length) L.push(`- Fix versions mentioned in description: ${f.fixVersionsInDescription.join(", ")}`);
  if (f.fixNotes.length) L.push(`- Version notes: ${f.fixNotes.join("; ")}`);
  if (f.upgradeCommand) L.push(`- Action: \`${f.upgradeCommand.split("\n")[0]}\`${f.upgradeCommand.includes("\n") ? "\n  -" + f.upgradeCommand.split("\n").slice(1).join(" ") : ""}`);
  if (f.kev) {
    L.push(`- CISA KEV: added ${f.kev.dateAdded}, federal due date ${f.kev.dueDate}, ransomware use: ${f.kev.ransomware}`);
    L.push(`  - Required action: ${f.kev.requiredAction}`);
  }
  if (f.cwes.length) L.push(`- Weakness: ${f.cwes.join(", ")}`);
  for (const g of f.codeFixGuidance) L.push(`  - ${g.cwe} ${g.name} → code fix: ${g.fix}`);
  if (verbose && f.affected.length) L.push(`- Affected: ${f.affected.map((a) => `${a.cpe} ${a.range}`).join("; ")}`);
  if (verbose && f.references.length) {
    L.push(`- References:`);
    for (const r of f.references) L.push(`  - ${r.url}${r.tags.length ? ` [${r.tags.join(", ")}]` : ""}`);
  }
  if (f.advisoryUrl) L.push(`- Advisory: ${f.advisoryUrl}`);
  if (f.nvdUrl) L.push(`- NVD: ${f.nvdUrl}`);
  return L.join("\n");
}

import { bestMetric, cwes, description, fixGuidance, references, severityRank, affectedRanges, compareVersions } from "./nvd.js";
import { cweGuidance } from "./remediation.js";
import { ECOSYSTEMS } from "./ecosystems.js";

const REF_PRIORITY = ["Patch", "Vendor Advisory", "Mitigation", "Release Notes", "Third Party Advisory", "Exploit", "Issue Tracking"];

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

/**
 * Build a normalised, agent-friendly finding from an NVD CVE (+ optional KEV entry + package context).
 * pkg: { name, version, ecosystem, direct, product }
 */
export function buildFinding(cve, kev, pkg = null, { maxRefs = 6 } = {}) {
  const metric = bestMetric(cve);
  const weaknesses = cwes(cve);
  const fix = pkg ? fixGuidance(cve, pkg.product, pkg.version) : null;
  const eco = pkg?.ecosystem && ECOSYSTEMS[pkg.ecosystem];
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
  let upgradeCommand = null;
  if (recommended && eco) {
    upgradeCommand = eco.upgrade(pkg.name, recommended);
    if (pkg.direct === false && eco.transitiveHint) upgradeCommand += `\n    ${eco.transitiveHint(pkg.name, recommended)}`;
  }
  const ranges = (fix ? fix.ranges : affectedRanges(cve)).slice(0, 8).map((r) => ({
    cpe: `${r.vendor}:${r.product}${r.targetSw && r.targetSw !== "*" ? ` (${r.targetSw})` : ""}`,
    range: rangeText(r),
  }));
  return {
    id: cve.id,
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
    package: pkg ? { name: pkg.name, version: pkg.version, ecosystem: pkg.ecosystem, direct: pkg.direct ?? null, confidence: pkg.confidence } : null,
    fixedVersion: recommended,
    fixedVersionSource: recommendedSource,
    fixVersionsInDescription: descFixes,
    fixedVersionsAll: fix?.allFixedVersions || [],
    fixNotes: fix?.notes || [],
    upgradeCommand,
    kev: kev
      ? {
          dateAdded: kev.dateAdded,
          dueDate: kev.dueDate,
          name: kev.vulnerabilityName,
          requiredAction: kev.requiredAction,
          ransomware: kev.knownRansomwareCampaignUse,
          notes: kev.notes,
        }
      : null,
    references: rankRefs(references(cve), maxRefs),
    nvdUrl: `https://nvd.nist.gov/vuln/detail/${cve.id}`,
  };
}

/** KEV first, then newest, then highest severity/score. */
export function sortFindings(list, { by = "priority" } = {}) {
  return list.sort((a, b) => {
    if (by === "severity") {
      return (b.score ?? -1) - (a.score ?? -1) || (b.published || "").localeCompare(a.published || "");
    }
    if (!!b.kev !== !!a.kev) return b.kev ? 1 : -1;
    if (by === "priority") {
      const sa = severityRank(a.severity) >= 3, sb = severityRank(b.severity) >= 3; // HIGH/CRITICAL before rest
      if (sa !== sb) return sb ? 1 : -1;
    }
    return (b.published || "").localeCompare(a.published || "") || (b.score ?? -1) - (a.score ?? -1);
  });
}

export function findingToMarkdown(f, { verbose = true } = {}) {
  const tags = [];
  if (f.kev) tags.push("🔥 ACTIVELY EXPLOITED (CISA KEV)");
  tags.push(`${f.severity}${f.score != null ? ` ${f.score}` : ""}`);
  const head = f.package ? ` — ${f.package.name}@${f.package.version}${f.package.direct === false ? " (transitive)" : ""}` : "";
  const L = [`### ${f.id}${head}  [${tags.join(" | ")}]`];
  L.push(`- Published: ${f.published} · Modified: ${f.lastModified} · NVD status: ${f.status}`);
  if (f.package?.confidence && f.package.confidence !== "high") L.push(`- Match confidence: ${f.package.confidence} (CPE platform not specific to ${f.package.ecosystem} — verify it is the same project)`);
  L.push(`- Summary: ${f.description}`);
  if (f.cvss) L.push(`- ${f.cvss}`);
  if (f.fixedVersion) L.push(`- ✅ Fixed in: **${f.fixedVersion}**${f.fixedVersionSource && f.fixedVersionSource !== "NVD" ? ` (source: ${f.fixedVersionSource})` : ""}${f.fixedVersionsAll.length > 1 ? ` (fixed releases per branch: ${f.fixedVersionsAll.join(", ")})` : ""}`);
  else if (f.fixedVersionsAll.length) L.push(`- Fixed releases per branch: ${f.fixedVersionsAll.join(", ")}`);
  if (!f.fixedVersion && f.fixVersionsInDescription.length) L.push(`- Fix versions mentioned in description: ${f.fixVersionsInDescription.join(", ")}`);
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
  L.push(`- NVD: ${f.nvdUrl}`);
  return L.join("\n");
}

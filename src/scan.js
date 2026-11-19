import { loadKev } from "./kev.js";
import { nvdQueryAll, affectedRanges, severityRank, compareVersions } from "./nvd.js";
import { osvQueryDeps, dedupeOsv, mapLimit } from "./osv.js";
import { getEpss } from "./epss.js";
import { getRegistryInfo, nearestPublished } from "./registry.js";
import { buildFinding, buildOsvFinding, mergeFindings, attachEpss, sortFindings, osvFix, findingToMarkdown } from "./report.js";
import { cpeProductCandidates } from "./deps.js";
import { ECOSYSTEMS, targetSwRelevance } from "./ecosystems.js";

/** NVD CPE-based lookup for one package version. */
export async function nvdFindingsForPackage(dep, kevById, { vendor } = {}) {
  const products = cpeProductCandidates(dep);
  const byId = new Map();
  for (const product of products) {
    const match = `cpe:2.3:a:${vendor || "*"}:${product}:${dep.version}`;
    const { cves } = await nvdQueryAll({ virtualMatchString: match, noRejected: true }, 300);
    for (const cve of cves) {
      if (byId.has(cve.id)) continue;
      const ranges = affectedRanges(cve).filter((r) => r.product?.toLowerCase() === product);
      const rel = ranges.length ? Math.max(...ranges.map((r) => targetSwRelevance(r.targetSw, dep.ecosystem))) : 1;
      if (rel === 0) continue; // same product name, different platform
      byId.set(cve.id, { cve, product, confidence: rel === 2 || vendor ? "high" : "medium" });
    }
  }
  return [...byId.values()].map(({ cve, product, confidence }) =>
    buildFinding(cve, kevById.get(cve.id) || null, { ...dep, product, confidence })
  );
}

const depKey = (d) => `${d.ecosystem}:${d.name}@${d.version}`;

/**
 * Analyze dependencies with OSV (all deps, batched) and NVD (nvdDeps subset, rate limited),
 * merge duplicates, enrich with KEV + EPSS, filter and sort.
 */
export async function analyzeDependencies(deps, { useOsv = true, nvdDeps = [], vendor, minSeverity, onProgress } = {}) {
  const { byId: kevById } = await loadKev();
  const kevLookup = (id) => kevById.get(id) || null;
  const errors = [];
  const perDep = new Map(deps.map((d) => [depKey(d), []]));

  if (useOsv && deps.length) {
    await onProgress?.("OSV batch query");
    try {
      const recs = await osvQueryDeps(deps);
      deps.forEach((dep, i) => {
        for (const g of dedupeOsv(recs[i])) perDep.get(depKey(dep)).push(buildOsvFinding(g, dep, kevLookup));
      });
    } catch (err) {
      errors.push(`OSV: ${err.message}`);
    }
  }

  let n = 0;
  for (const dep of nvdDeps) {
    await onProgress?.(`NVD ${dep.name}@${dep.version}`, n++, nvdDeps.length);
    try {
      const list = perDep.get(depKey(dep)) || [];
      for (const nf of await nvdFindingsForPackage(dep, kevById, { vendor })) {
        const same = list.find((f) => f.id === nf.id || f.aliases.includes(nf.id));
        if (same) mergeFindings(same, nf);
        else list.push(nf);
      }
      perDep.set(depKey(dep), list);
    } catch (err) {
      errors.push(`NVD ${dep.name}@${dep.version}: ${err.message}`);
    }
  }

  let findings = [...perDep.values()].flat();
  attachEpss(findings, await getEpss(findings.map((f) => f.id)));
  if (minSeverity) {
    const r = severityRank(minSeverity);
    findings = findings.filter((f) => f.malicious || f.kev || severityRank(f.severity) >= r || f.severity === "UNSCORED");
  }
  return { findings: sortFindings(findings), errors };
}

/** Per package: the highest fixed version needed to clear all its findings. */
export function actionPlan(findings) {
  const plan = new Map();
  for (const f of findings) {
    if (!f.package) continue;
    const key = depKey(f.package);
    const p = plan.get(key) || { ...f.package, cves: [], kev: false, malicious: false, maxEpss: 0, worst: "NONE", target: null, unfixed: [] };
    p.cves.push(f.id);
    p.kev ||= Boolean(f.kev);
    p.malicious ||= f.malicious;
    p.maxEpss = Math.max(p.maxEpss, f.epss?.probability || 0);
    if (severityRank(f.severity) > severityRank(p.worst)) p.worst = f.severity;
    if (f.fixedVersion) {
      if (!p.target || compareVersions(f.fixedVersion, p.target) > 0) p.target = f.fixedVersion;
    } else if (!f.malicious) p.unfixed.push(f.id);
    plan.set(key, p);
  }
  return [...plan.values()].sort(
    (a, b) => b.malicious - a.malicious || b.kev - a.kev || (b.maxEpss >= 0.1) - (a.maxEpss >= 0.1) || severityRank(b.worst) - severityRank(a.worst) || b.cves.length - a.cves.length
  );
}

/**
 * Add registry data (latest version, deprecation, staleness) and walk the recommended
 * version forward until OSV reports no remaining advisories for it (max 4 hops).
 */
export async function enrichPlan(plan) {
  await mapLimit(plan, 6, async (p) => {
    p.registry = await getRegistryInfo(p);
    p.recommended = p.target && p.registry ? nearestPublished(p.registry, p.target) : p.target;
  });
  const cveOf = (g) => [g.primary.id, ...(g.primary.aliases || [])].find((x) => x.startsWith("CVE-")) || g.primary.id;
  let pending = plan.filter((p) => p.recommended && !p.malicious);
  for (let hop = 0; hop < 4 && pending.length; hop++) {
    let recs;
    try {
      recs = await osvQueryDeps(pending.map((p) => ({ ...p, version: p.recommended })));
    } catch {
      break;
    }
    const next = [];
    pending.forEach((p, i) => {
      const groups = dedupeOsv(recs[i]);
      p.recommendedVulns = groups.map(cveOf);
      if (!groups.length) return;
      // compute fixes for the advisories that still affect the candidate version
      const fixes = groups.map((g) => osvFix([g.primary, ...g.others], { ...p, version: p.recommended }).fixedVersion).filter(Boolean);
      if (!fixes.length) return; // remaining advisories have no fix on this line → stop here
      const bump = fixes.sort(compareVersions).at(-1);
      const cand = p.registry ? nearestPublished(p.registry, bump) : bump;
      if (compareVersions(cand, p.recommended) <= 0) return;
      p.recommended = cand;
      next.push(p);
    });
    pending = next;
  }
  // latest version check
  const latestChecks = plan.filter((p) => p.registry?.latest && p.registry.latest !== p.recommended);
  if (latestChecks.length) {
    try {
      const recs = await osvQueryDeps(latestChecks.map((p) => ({ ...p, version: p.registry.latest })));
      latestChecks.forEach((p, i) => (p.latestVulns = dedupeOsv(recs[i]).map(cveOf)));
    } catch {
      /* optional */
    }
  }
  return plan;
}

/** Deprecated / yanked / stale direct dependencies (even without CVEs). */
export async function healthIssues(deps, exclude = new Set()) {
  const direct = deps.filter((d) => d.direct !== false && !exclude.has(depKey(d))).slice(0, 80);
  const out = [];
  await mapLimit(direct, 8, async (d) => {
    const info = await getRegistryInfo(d);
    if (!info) return;
    const issues = [];
    if (info.currentDeprecated) issues.push(`deprecated: ${info.currentDeprecated}`);
    else if (info.deprecated) issues.push(`package deprecated: ${info.deprecated}`);
    if (info.currentYanked) issues.push(`this version was yanked (${info.currentYanked})`);
    if (info.stale) issues.push(`possibly unmaintained: ${info.stale}`);
    if (issues.length) out.push({ ...d, issues, latest: info.latest });
  });
  return out.sort((a, b) => a.name.localeCompare(b.name));
}

export function planToMarkdown(plan) {
  if (!plan.length) return "";
  const L = ["## Action plan (fix in this order)", ""];
  plan.forEach((p, i) => {
    const eco = ECOSYSTEMS[p.ecosystem];
    const flags = [p.malicious && "🚨MALICIOUS", p.kev && "🔥KEV", p.maxEpss >= 0.1 && `⚠️EPSS ${(p.maxEpss * 100).toFixed(0)}%`].filter(Boolean).join(" ");
    const ids = p.cves.length > 10 ? `${p.cves.slice(0, 10).join(", ")} …+${p.cves.length - 10} more` : p.cves.join(", ");
    L.push(`${i + 1}. **${p.name}@${p.version}** [${p.ecosystem}]${p.direct === false ? " (transitive)" : ""} — ${p.worst}${flags ? ` ${flags}` : ""}, ${p.cves.length} issue(s): ${ids}${p.source ? ` · in ${p.source}` : ""}`);
    if (p.malicious) {
      L.push(`   - 🚨 REMOVE this package now (do not upgrade). Audit CI/dev machines where it was installed and rotate exposed secrets.`);
      return;
    }
    const target = p.recommended || p.target;
    if (target && eco) {
      L.push(`   - Upgrade to **>= ${target}**: \`${eco.upgrade(p.name, target)}\``);
      if (p.recommended && p.target && p.recommended !== p.target) L.push(`   - (minimum fix for the reported issues is ${p.target}; raised to ${p.recommended} because ${p.target} is itself affected by newer advisories)`);
      if (p.recommendedVulns?.length) L.push(`   - ⚠️ ${target} still has known advisories without a fix on this line: ${p.recommendedVulns.slice(0, 8).join(", ")} — consider the latest version or a replacement.`);
      else if (p.recommendedVulns) L.push(`   - ✓ ${target} has no known advisories in OSV.`);
    }
    if (p.registry?.latest) {
      const lv = p.latestVulns;
      L.push(`   - Latest release: ${p.registry.latest}${p.registry.referenceDate ? ` (${p.registry.referenceDate})` : ""}${lv ? (lv.length ? ` — still affected by ${lv.slice(0, 8).join(", ")}` : " — no known advisories") : ""}`);
      if (p.registry.deprecated) L.push(`   - ⚠️ Package is deprecated: ${p.registry.deprecated} → plan a replacement.`);
      if (p.registry.stale) L.push(`   - ⚠️ ${p.registry.stale} → consider an actively maintained alternative.`);
    }
    if (target && String(target).split(".")[0] !== String(p.version).split(".")[0])
      L.push(`   - ⚠️ Major version bump (${p.version} → ${target}): review the changelog/breaking changes and update call sites.`);
    if (p.direct === false && target && eco?.transitiveHint) L.push(`   - ${eco.transitiveHint(p.name, target)}`);
    if (p.unfixed.length) L.push(`   - No fixed version recorded for: ${p.unfixed.join(", ")} → check the advisory, apply mitigations or replace the package.`);
  });
  return L.join("\n");
}

export function healthToMarkdown(items) {
  if (!items.length) return "";
  const L = ["## Package health (deprecated / yanked / unmaintained direct dependencies)", ""];
  for (const d of items) L.push(`- **${d.name}@${d.version}** [${d.ecosystem}]${d.latest ? ` (latest ${d.latest})` : ""}: ${d.issues.join("; ")}`);
  return L.join("\n");
}

/**
 * Render findings for an agent: top `detailed` findings in full, the rest as one-line summaries
 * (capped at `compact`), so very large projects stay within a reasonable context size.
 */
export function findingsToMarkdown(findings, { detailed = 15, compact = 150 } = {}) {
  if (!findings.length) return "_No known vulnerabilities found for the scanned versions._";
  const head = findings.slice(0, detailed).map((f) => findingToMarkdown(f)).join("\n\n");
  const rest = findings.slice(detailed);
  if (!rest.length) return head;
  const lines = rest.slice(0, compact).map((f) => {
    const tags = [f.malicious && "MALICIOUS", f.kev && "KEV", f.epss && f.epss.probability >= 0.1 && `EPSS ${(f.epss.probability * 100).toFixed(0)}%`].filter(Boolean).join(" ");
    const t = (f.title || f.description || "").slice(0, 110);
    return `- ${f.id}${f.package ? ` — ${f.package.name}@${f.package.version}` : ""} — ${f.severity}${f.score != null ? ` ${f.score}` : ""}${tags ? ` ${tags}` : ""}${f.fixedVersion ? ` — fixed ${f.fixedVersion}` : ""} — ${t}`;
  });
  const more = rest.length > compact ? `\n- …and ${rest.length - compact} more (use format="json" or get_vulnerability for details)` : "";
  return `${head}\n\n### Other findings (summary — call get_vulnerability <id> for full details)\n${lines.join("\n")}${more}`;
}

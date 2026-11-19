#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { resolve } from "node:path";
import { z } from "zod";

import { loadKev, getKevEntry, searchKev } from "./kev.js";
import { getCve, hasApiKey, nvdQueryAll, nvdQueryLatest, severityRank, affectedRanges, compareVersions } from "./nvd.js";
import { buildFinding, findingToMarkdown, sortFindings } from "./report.js";
import { collectDependencies, cpeProductCandidates } from "./deps.js";
import { ECOSYSTEMS, resolveEcosystem, targetSwRelevance } from "./ecosystems.js";

const VERSION = "0.1.0";
const NVD_MAX_RANGE_DAYS = 120;
const ECO_ENUM = z
  .string()
  .describe("Language/ecosystem: npm|javascript|typescript, pypi|python, go, maven|java, composer|php, rubygems|ruby, cargo|rust, nuget|dotnet");
const SEVERITY = z.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]);
const FORMAT = z.enum(["markdown", "json"]).default("markdown").describe("markdown for reading, json for structured processing");

const INSTRUCTIONS = `vuln-watch: security vulnerability intelligence from CISA KEV (actively exploited) and NVD (CVE details).
Use it to find AND FIX vulnerabilities while coding:
- Before adding/upgrading a dependency, or when asked about project security → scan_project_dependencies (path = project root) or check_package.
- To learn what is newly vulnerable in the project's language → latest_ecosystem_vulnerabilities.
- When a CVE ID appears (logs, audit output, advisories) → get_vulnerability.
- KEV entries are being exploited in the wild: fix them first.
Every finding contains the fixed version, an upgrade command, affected version ranges, CWE-specific code-fix guidance, KEV required action/due date and patch/advisory links.
After finding issues: apply the upgrade (edit manifest + lockfile), apply code fixes for the CWE where the vulnerable API is used in this codebase, then re-run the scan to verify.`;

const server = new McpServer({ name: "vuln-watch", version: VERSION }, { instructions: INSTRUCTIONS });

// ---------- helpers ----------

const text = (s) => ({ content: [{ type: "text", text: s }] });
const errorResult = (err) => ({ content: [{ type: "text", text: `Error: ${err?.message || err}` }], isError: true });

function dateRange(days) {
  const d = Math.min(Math.max(1, days), NVD_MAX_RANGE_DAYS);
  const end = new Date();
  const start = new Date(end.getTime() - d * 86400_000);
  return { pubStartDate: start.toISOString(), pubEndDate: end.toISOString(), clamped: days > NVD_MAX_RANGE_DAYS, days: d };
}

function minSeverityFilter(min) {
  if (!min) return () => true;
  const r = severityRank(min);
  return (f) => severityRank(f.severity) >= r;
}

async function progress(extra, done, total, message) {
  const token = extra?._meta?.progressToken;
  if (token === undefined) return;
  try {
    await extra.sendNotification({ method: "notifications/progress", params: { progressToken: token, progress: done, total, message } });
  } catch {
    /* ignore */
  }
}

function rateNote() {
  return hasApiKey()
    ? ""
    : "\n> Note: NVD_API_KEY is not set, so NVD is limited to 5 requests/30s. Get a free key at https://nvd.nist.gov/developers/request-an-api-key and set NVD_API_KEY for ~10x faster scans.";
}

/** Look up CVEs affecting a specific package version via NVD CPE matching + KEV. */
async function findingsForPackage(dep, { vendor } = {}) {
  const eco = dep.ecosystem;
  const products = cpeProductCandidates(dep);
  const byId = new Map();
  for (const product of products) {
    const match = `cpe:2.3:a:${vendor || "*"}:${product}:${dep.version}`;
    const { cves } = await nvdQueryAll({ virtualMatchString: match, noRejected: true }, 300);
    for (const cve of cves) {
      if (byId.has(cve.id)) continue;
      const ranges = affectedRanges(cve).filter((r) => r.product?.toLowerCase() === product);
      const rel = ranges.length ? Math.max(...ranges.map((r) => targetSwRelevance(r.targetSw, eco))) : 1;
      if (rel === 0) continue; // same product name, different platform (e.g. a WordPress plugin)
      byId.set(cve.id, { cve, product, confidence: rel === 2 || vendor ? "high" : "medium" });
    }
  }
  const out = [];
  for (const { cve, product, confidence } of byId.values()) {
    const kev = await getKevEntry(cve.id);
    out.push(buildFinding(cve, kev, { ...dep, product, confidence }));
  }
  return sortFindings(out);
}

function actionPlan(findings) {
  // per package: the highest fixed version needed to clear all its CVEs
  const plan = new Map();
  for (const f of findings) {
    if (!f.package) continue;
    const key = `${f.package.ecosystem}:${f.package.name}@${f.package.version}`;
    const p = plan.get(key) || { ...f.package, cves: [], kev: false, worst: "NONE", target: null, unfixed: [] };
    p.cves.push(f.id);
    p.kev ||= Boolean(f.kev);
    if (severityRank(f.severity) > severityRank(p.worst)) p.worst = f.severity;
    if (f.fixedVersion) {
      if (!p.target || compareVersions(f.fixedVersion, p.target) > 0) p.target = f.fixedVersion;
    } else p.unfixed.push(f.id);
    plan.set(key, p);
  }
  return [...plan.values()].sort(
    (a, b) => (b.kev - a.kev) || severityRank(b.worst) - severityRank(a.worst) || b.cves.length - a.cves.length
  );
}

function planToMarkdown(plan) {
  if (!plan.length) return "";
  const L = ["## Action plan (fix in this order)", ""];
  plan.forEach((p, i) => {
    const eco = ECOSYSTEMS[p.ecosystem];
    const cmd = p.target && eco ? eco.upgrade(p.name, p.target) : null;
    L.push(
      `${i + 1}. **${p.name}@${p.version}**${p.direct === false ? " (transitive)" : ""} — ${p.worst}${p.kev ? " 🔥KEV" : ""}, ${p.cves.length} CVE(s): ${p.cves.join(", ")}`
    );
    if (cmd) L.push(`   - Upgrade to **>= ${p.target}**: \`${cmd}\``);
    if (p.target && String(p.target).split(".")[0] !== String(p.version).split(".")[0])
      L.push(`   - ⚠️ Major version bump (${p.version} → ${p.target}): review the changelog/breaking changes and update call sites accordingly.`);
    if (p.direct === false && p.target && eco?.transitiveHint) L.push(`   - ${eco.transitiveHint(p.name, p.target)}`);
    if (p.unfixed.length) L.push(`   - No fixed version recorded in NVD for: ${p.unfixed.join(", ")} → check references/advisories, consider replacing the package or applying the mitigation.`);
  });
  return L.join("\n");
}

function render(findings, format, header, extra = {}) {
  if (format === "json") return text(JSON.stringify({ ...extra, count: findings.length, findings }, null, 2));
  const body = findings.length ? findings.map((f) => findingToMarkdown(f)).join("\n\n") : "_No matching vulnerabilities found._";
  return text(`${header}\n\n${body}`);
}

// ---------- tools ----------

server.registerTool(
  "scan_project_dependencies",
  {
    title: "Scan project dependencies for known vulnerabilities",
    description:
      "Reads package-lock.json/package.json, requirements*.txt and go.mod in a project directory, checks each dependency version against NVD (CPE version ranges) and CISA KEV, and returns a prioritized action plan with fixed versions, upgrade commands and code-fix guidance. Direct dependencies are scanned first. Use offset to continue a truncated scan.",
    inputSchema: {
      path: z.string().describe("Project root directory or a manifest file path"),
      include_dev: z.boolean().default(false).describe("Include devDependencies"),
      include_transitive: z.boolean().default(true).describe("Include transitive deps from lockfiles (scanned after direct deps)"),
      max_packages: z.number().int().min(1).max(500).optional().describe("Max packages to query in this call (default 10 without NVD_API_KEY, 60 with)"),
      offset: z.number().int().min(0).default(0).describe("Skip the first N packages (to continue a previous scan)"),
      min_severity: SEVERITY.optional(),
      format: FORMAT,
    },
    annotations: { readOnlyHint: true, openWorldHint: true },
  },
  async (args, extra) => {
    try {
      const target = resolve(args.path);
      let deps = await collectDependencies(target, { includeDev: args.include_dev });
      if (!args.include_transitive) deps = deps.filter((d) => d.direct !== false);
      // direct first, then by name
      deps.sort((a, b) => (a.direct === false) - (b.direct === false) || a.name.localeCompare(b.name));
      if (!deps.length) return text(`No supported manifests with pinned versions found in ${target} (supported: package-lock.json, package.json, requirements*.txt, go.mod).`);

      const max = args.max_packages ?? (hasApiKey() ? 60 : 10);
      const slice = deps.slice(args.offset, args.offset + max);
      const filter = minSeverityFilter(args.min_severity);
      await loadKev();

      const findings = [];
      const errors = [];
      let i = 0;
      for (const dep of slice) {
        await progress(extra, i, slice.length, `${dep.name}@${dep.version}`);
        try {
          findings.push(...(await findingsForPackage(dep)).filter(filter));
        } catch (err) {
          errors.push(`${dep.name}@${dep.version}: ${err.message}`);
        }
        i++;
      }
      sortFindings(findings);
      const plan = actionPlan(findings);
      const next = args.offset + slice.length;
      const remaining = deps.length - next;
      const ecosystems = [...new Set(deps.map((d) => d.ecosystem))];

      if (args.format === "json") {
        return text(JSON.stringify({ path: target, ecosystems, totalDependencies: deps.length, scanned: { offset: args.offset, count: slice.length }, remaining, nextOffset: remaining > 0 ? next : null, actionPlan: plan, findings, errors }, null, 2));
      }
      const head = [
        `# Dependency vulnerability scan: ${target}`,
        `Ecosystems: ${ecosystems.map((e) => ECOSYSTEMS[e]?.label || e).join(", ")} · Dependencies found: ${deps.length} · Scanned this call: ${slice.length} (offset ${args.offset})`,
        `Vulnerable packages: ${plan.length} · Findings: ${findings.length} (KEV: ${findings.filter((f) => f.kev).length}, CRITICAL: ${findings.filter((f) => f.severity === "CRITICAL").length}, HIGH: ${findings.filter((f) => f.severity === "HIGH").length})`,
        remaining > 0 ? `\n⚠️ ${remaining} dependencies not scanned yet → call again with offset=${next}.` : "",
        errors.length ? `\nErrors: ${errors.join("; ")}` : "",
        rateNote(),
      ].filter(Boolean).join("\n");
      const body = findings.length ? findings.map((f) => findingToMarkdown(f)).join("\n\n") : "_No known vulnerabilities found for the scanned versions._";
      return text(`${head}\n\n${planToMarkdown(plan)}\n\n## Findings (KEV → HIGH/CRITICAL → newest)\n\n${body}\n\n---\nNext steps: update manifests + lockfiles to the target versions, search the codebase for usages of the vulnerable APIs described above and apply the code-fix guidance, then re-run this scan to verify. Matching is based on NVD CPE data; packages with no CPE entry will not be detected.`);
    } catch (err) {
      return errorResult(err);
    }
  }
);

server.registerTool(
  "check_package",
  {
    title: "Check a package/product version for vulnerabilities",
    description:
      "Checks one library or product version (e.g. lodash 4.17.15 on npm, django 3.2.0 on pypi, nginx 1.18.0, openssl 3.0.1) against NVD version ranges and CISA KEV. Returns every CVE affecting that version with fixed version, upgrade command and code-fix guidance.",
    inputSchema: {
      name: z.string().describe("Package or product name, e.g. 'lodash', '@babel/traverse', 'django', 'github.com/gin-gonic/gin', 'nginx'"),
      version: z.string().describe("Installed version, e.g. '4.17.15'"),
      ecosystem: ECO_ENUM.optional(),
      vendor: z.string().optional().describe("Optional CPE vendor to narrow results, e.g. 'djangoproject', 'f5', 'openssl'"),
      min_severity: SEVERITY.optional(),
      format: FORMAT,
    },
    annotations: { readOnlyHint: true, openWorldHint: true },
  },
  async (args) => {
    try {
      const eco = resolveEcosystem(args.ecosystem);
      const dep = { name: args.name, version: args.version.replace(/^v/, ""), ecosystem: eco, direct: true };
      const findings = (await findingsForPackage(dep, { vendor: args.vendor?.toLowerCase() })).filter(minSeverityFilter(args.min_severity));
      const plan = actionPlan(findings);
      if (args.format === "json") return text(JSON.stringify({ package: dep, actionPlan: plan, count: findings.length, findings }, null, 2));
      const head = `# ${args.name}@${dep.version}${eco ? ` (${ECOSYSTEMS[eco].label})` : ""}: ${findings.length} known vulnerabilit${findings.length === 1 ? "y" : "ies"}${findings.some((f) => f.kev) ? " — includes ACTIVELY EXPLOITED (KEV)" : ""}${rateNote()}`;
      const body = findings.length ? findings.map((f) => findingToMarkdown(f)).join("\n\n") : "_No known vulnerabilities in NVD for this version (note: only packages with NVD CPE entries can be matched; try vendor or a different product name if unsure)._";
      return text(`${head}\n\n${planToMarkdown(plan)}\n\n${body}`);
    } catch (err) {
      return errorResult(err);
    }
  }
);

server.registerTool(
  "latest_ecosystem_vulnerabilities",
  {
    title: "Latest vulnerabilities for a language/ecosystem",
    description:
      "Lists the most recently published CVEs relevant to a language/package ecosystem (npm/Node.js, Python, Go, Java, PHP, Ruby, Rust, .NET), newest first, with KEV status, fixed versions and remediation. Combines NVD CPE platform matching with keyword search so freshly published (not yet analyzed) CVEs are included.",
    inputSchema: {
      ecosystem: ECO_ENUM,
      days: z.number().int().min(1).max(120).default(30).describe("Look-back window in days (NVD max 120)"),
      keyword: z.string().optional().describe("Optional extra keyword to narrow down, e.g. 'express', 'deserialization'"),
      min_severity: SEVERITY.optional(),
      kev_only: z.boolean().default(false),
      limit: z.number().int().min(1).max(100).default(20),
      format: FORMAT,
    },
    annotations: { readOnlyHint: true, openWorldHint: true },
  },
  async (args) => {
    try {
      const eco = resolveEcosystem(args.ecosystem);
      if (!eco) return errorResult(`Unknown ecosystem '${args.ecosystem}'. Use one of: ${Object.keys(ECOSYSTEMS).join(", ")}`);
      const prof = ECOSYSTEMS[eco];
      const range = dateRange(args.days);
      const base = { pubStartDate: range.pubStartDate, pubEndDate: range.pubEndDate, noRejected: true, hasKev: args.kev_only || undefined };
      const byId = new Map();
      const add = (cves, source) => {
        for (const c of cves) if (!byId.has(c.id)) byId.set(c.id, { cve: c, source });
      };
      const queries = [];
      for (const sw of prof.targetSw.slice(0, 1)) {
        queries.push(["cpe", { ...base, virtualMatchString: `cpe:2.3:a:*:*:*:*:*:*:*:${sw}:*:*`, keywordSearch: args.keyword }]);
      }
      for (const kw of prof.keywords) {
        queries.push(["keyword", { ...base, keywordSearch: args.keyword ? `${args.keyword} ${kw}` : kw }]);
      }
      const errors = [];
      for (const [source, q] of queries) {
        try {
          const { cves } = await nvdQueryLatest(q, Math.min(200, args.limit * 3));
          add(cves, source);
        } catch (err) {
          errors.push(`${source}: ${err.message}`);
        }
      }
      const filter = minSeverityFilter(args.min_severity);
      let findings = [];
      for (const { cve } of byId.values()) {
        // drop CVEs whose CPE data clearly targets another platform
        const ranges = affectedRanges(cve);
        if (ranges.length && !ranges.some((r) => targetSwRelevance(r.targetSw, eco) > 0)) continue;
        const f = buildFinding(cve, await getKevEntry(cve.id), null, { maxRefs: 4 });
        if (filter(f)) findings.push(f);
      }
      findings = sortFindings(findings, { by: "recent" }).slice(0, args.limit);
      const header = `# Latest ${prof.label} vulnerabilities — last ${range.days} days${args.keyword ? `, keyword "${args.keyword}"` : ""}\nShowing ${findings.length} (KEV first, then newest). ${errors.length ? `Errors: ${errors.join("; ")}` : ""}${rateNote()}\nTip: run scan_project_dependencies to see which of these affect the current project.`;
      return render(findings, args.format, header, { ecosystem: eco, days: range.days, errors });
    } catch (err) {
      return errorResult(err);
    }
  }
);

server.registerTool(
  "search_vulnerabilities",
  {
    title: "Search NVD for vulnerabilities",
    description:
      "Keyword search over NVD CVE descriptions (newest first), annotated with CISA KEV status. Use for libraries/products/frameworks or vulnerability types, e.g. 'next.js middleware', 'spring framework', 'prototype pollution', 'log4j'.",
    inputSchema: {
      keyword: z.string().describe("Words that must all appear in the CVE description"),
      ecosystem: ECO_ENUM.optional().describe("Restrict to a language ecosystem (drops CVEs whose CPE targets another platform)"),
      days: z.number().int().min(1).max(120).optional().describe("Only CVEs published in the last N days"),
      cwe: z.string().optional().describe("e.g. CWE-79"),
      min_severity: SEVERITY.optional(),
      kev_only: z.boolean().default(false),
      exact_match: z.boolean().default(false).describe("Treat keyword as an exact phrase"),
      limit: z.number().int().min(1).max(100).default(15),
      format: FORMAT,
    },
    annotations: { readOnlyHint: true, openWorldHint: true },
  },
  async (args) => {
    try {
      const eco = resolveEcosystem(args.ecosystem);
      const q = {
        keywordSearch: args.keyword,
        keywordExactMatch: args.exact_match || undefined,
        cweId: args.cwe?.toUpperCase(),
        hasKev: args.kev_only || undefined,
        noRejected: true,
      };
      if (args.days) Object.assign(q, { pubStartDate: dateRange(args.days).pubStartDate, pubEndDate: dateRange(args.days).pubEndDate });
      const { total, cves } = await nvdQueryLatest(q, Math.min(200, args.limit * (eco || args.min_severity ? 3 : 1)));
      const filter = minSeverityFilter(args.min_severity);
      let findings = [];
      for (const cve of cves) {
        if (eco) {
          const ranges = affectedRanges(cve);
          if (ranges.length && !ranges.some((r) => targetSwRelevance(r.targetSw, eco) > 0)) continue;
        }
        const f = buildFinding(cve, await getKevEntry(cve.id), null, { maxRefs: 4 });
        if (filter(f)) findings.push(f);
      }
      findings = sortFindings(findings, { by: "recent" }).slice(0, args.limit);
      return render(findings, args.format, `# NVD search "${args.keyword}" — ${total} total matches, showing ${findings.length} most recent (KEV first)${rateNote()}`, { total });
    } catch (err) {
      return errorResult(err);
    }
  }
);

server.registerTool(
  "get_vulnerability",
  {
    title: "Get full details for a CVE",
    description:
      "Full CVE details from NVD plus CISA KEV status: description, CVSS, CWE with code-fix guidance, every affected version range with fixed versions, KEV required action/due date and patch/advisory references. Optionally pass the installed package version to get the exact fixed version.",
    inputSchema: {
      cve_id: z.string().regex(/^CVE-\d{4}-\d{4,}$/i).describe("e.g. CVE-2021-44228"),
      installed_version: z.string().optional().describe("Your installed version, to compute the nearest fixed version"),
      product: z.string().optional().describe("CPE product name of the package you use (if the CVE lists several products)"),
      ecosystem: ECO_ENUM.optional(),
      format: FORMAT,
    },
    annotations: { readOnlyHint: true, openWorldHint: true },
  },
  async (args) => {
    try {
      const id = args.cve_id.toUpperCase();
      const [cve, kev] = await Promise.all([getCve(id), getKevEntry(id)]);
      if (!cve) {
        if (kev) return text(`${id} not found in NVD, but it is in CISA KEV:\n${JSON.stringify(kev, null, 2)}`);
        return text(`${id} not found in NVD or CISA KEV.`);
      }
      const eco = resolveEcosystem(args.ecosystem);
      const pkg = args.installed_version
        ? { name: args.product || affectedRanges(cve)[0]?.product || "package", product: args.product, version: args.installed_version.replace(/^v/, ""), ecosystem: eco, direct: true, confidence: "high" }
        : null;
      const f = buildFinding(cve, kev, pkg, { maxRefs: 30 });
      const fmtRange = (r) => [r.exactVersion && `= ${r.exactVersion}`, r.versionStartIncluding && `>= ${r.versionStartIncluding}`, r.versionStartExcluding && `> ${r.versionStartExcluding}`, r.versionEndExcluding && `< ${r.versionEndExcluding}`, r.versionEndIncluding && `<= ${r.versionEndIncluding}`].filter(Boolean).join(", ") || "all versions";
      const all = affectedRanges(cve);
      const wanted = args.product?.toLowerCase();
      // product of interest first, then ranged (library-style) entries, cap the rest
      const ordered = [...all.filter((r) => wanted && r.product?.toLowerCase() === wanted), ...all.filter((r) => !(wanted && r.product?.toLowerCase() === wanted))];
      const seenAff = new Set();
      const uniq = ordered.filter((r) => { const k = r.criteria + fmtRange(r); return seenAff.has(k) ? false : seenAff.add(k); });
      const MAX_AFF = 25;
      f.affected = uniq.slice(0, MAX_AFF).map((r) => ({ cpe: `${r.vendor}:${r.product}${r.targetSw && r.targetSw !== "*" ? ` (${r.targetSw})` : ""}`, range: fmtRange(r) }));
      if (uniq.length > MAX_AFF) {
        const vendors = [...new Set(uniq.slice(MAX_AFF).map((r) => r.vendor))];
        f.affected.push({ cpe: `…and ${uniq.length - MAX_AFF} more configurations`, range: `(vendors: ${vendors.slice(0, 15).join(", ")}${vendors.length > 15 ? ", …" : ""})` });
      }
      if (args.format === "json") return text(JSON.stringify({ finding: f, kevRaw: kev }, null, 2));
      let md = findingToMarkdown(f);
      if (kev?.notes) md += `\n- KEV notes: ${kev.notes}`;
      if (pkg && !f.fixedVersion) md += `\n- ℹ️ Installed version ${pkg.version} did not match a vulnerable range with a recorded fix${args.product ? "" : " (pass `product` if the CVE covers several products)"} — check the affected ranges above.`;
      return text(md);
    } catch (err) {
      return errorResult(err);
    }
  }
);

server.registerTool(
  "check_kev",
  {
    title: "Check CVEs against CISA KEV",
    description: "Checks which CVE IDs are in CISA's Known Exploited Vulnerabilities catalog (exploited in the wild) and returns required action, due date and ransomware usage. Fast, local lookup.",
    inputSchema: { cve_ids: z.array(z.string()).min(1).max(500) },
    annotations: { readOnlyHint: true, openWorldHint: true },
  },
  async ({ cve_ids }) => {
    try {
      const { catalog } = await loadKev();
      const L = [`# CISA KEV check (catalog ${catalog.catalogVersion}, ${catalog.count} entries)`, ""];
      const hits = [];
      for (const raw of cve_ids) {
        const k = await getKevEntry(raw.trim());
        if (k) hits.push(k);
        else L.push(`- ${raw.toUpperCase()}: not in KEV`);
      }
      for (const k of hits) {
        L.push(`- 🔥 **${k.cveID}** IN KEV — ${k.vendorProject} ${k.product}: ${k.vulnerabilityName}\n  - Added ${k.dateAdded}, due ${k.dueDate}, ransomware: ${k.knownRansomwareCampaignUse}\n  - ${k.shortDescription}\n  - Required action: ${k.requiredAction}${k.notes ? `\n  - Notes: ${k.notes}` : ""}`);
      }
      L.splice(1, 0, `${hits.length} of ${cve_ids.length} are known exploited. Fix those first; use get_vulnerability for fixed versions.`);
      return text(L.join("\n"));
    } catch (err) {
      return errorResult(err);
    }
  }
);

server.registerTool(
  "search_kev",
  {
    title: "Search CISA Known Exploited Vulnerabilities",
    description: "Searches the CISA KEV catalog (vulnerabilities actively exploited in the wild) by keyword, vendor, product, recency or ransomware use. Newest first.",
    inputSchema: {
      query: z.string().optional().describe("Words that must all appear (CVE id, vendor, product, name, description)"),
      vendor: z.string().optional(),
      product: z.string().optional(),
      days: z.number().int().min(1).optional().describe("Only entries added in the last N days"),
      ransomware_only: z.boolean().default(false),
      limit: z.number().int().min(1).max(200).default(25),
      format: FORMAT,
    },
    annotations: { readOnlyHint: true, openWorldHint: true },
  },
  async (args) => {
    try {
      const r = await searchKev({ query: args.query, vendor: args.vendor, product: args.product, days: args.days, ransomwareOnly: args.ransomware_only, limit: args.limit });
      if (args.format === "json") return text(JSON.stringify(r, null, 2));
      const L = [`# CISA KEV search — ${r.total} match(es), showing ${r.rows.length} (catalog ${r.catalogVersion})`];
      for (const k of r.rows) {
        L.push(`### ${k.cveID} — ${k.vendorProject} ${k.product}\n- ${k.vulnerabilityName}\n- Added ${k.dateAdded} · due ${k.dueDate} · ransomware: ${k.knownRansomwareCampaignUse}${k.cwes?.length ? ` · ${k.cwes.join(", ")}` : ""}\n- ${k.shortDescription}\n- Required action: ${k.requiredAction}\n- NVD: https://nvd.nist.gov/vuln/detail/${k.cveID}`);
      }
      return text(L.join("\n\n"));
    } catch (err) {
      return errorResult(err);
    }
  }
);

// ---------- prompt ----------

server.registerPrompt(
  "security_audit",
  {
    title: "Audit and fix vulnerable dependencies",
    description: "Scan the current project for known vulnerabilities and fix them",
    argsSchema: { path: z.string().optional().describe("Project root (default: current directory)") },
  },
  ({ path }) => ({
    messages: [
      {
        role: "user",
        content: {
          type: "text",
          text: `Run a security audit of the project at ${path || "the current working directory"} using the vuln-watch tools:
1. Call scan_project_dependencies (continue with offset until no dependencies remain).
2. Call latest_ecosystem_vulnerabilities for each detected ecosystem (days=30) to catch brand-new issues.
3. Fix in priority order: CISA KEV → CRITICAL → HIGH. For each: update the manifest and lockfile to the fixed version (use overrides/resolutions for transitive deps), and grep the codebase for usage of the vulnerable feature, applying the CWE code-fix guidance.
4. Re-run the scan to verify, then summarize what was fixed, what remains (no fix available) and recommended mitigations.`,
        },
      },
    ],
  })
);

const transport = new StdioServerTransport();
await server.connect(transport);
// warm the KEV cache in the background
loadKev().catch(() => {});

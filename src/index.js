#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { resolve } from "node:path";
import { z } from "zod";

import { loadKev, getKevEntry, searchKev } from "./kev.js";
import { getCve, hasApiKey, nvdQueryLatest, severityRank, affectedRanges } from "./nvd.js";
import { buildFinding, buildOsvFinding, findingToMarkdown, sortFindings, attachEpss } from "./report.js";
import { collectDependencies } from "./deps.js";
import { ECOSYSTEMS, resolveEcosystem, targetSwRelevance } from "./ecosystems.js";
import { analyzeDependencies, actionPlan, enrichPlan, healthIssues, planToMarkdown, healthToMarkdown, findingsToMarkdown } from "./scan.js";
import { getEpss } from "./epss.js";
import { getOsvVuln, OSV_ECOSYSTEM } from "./osv.js";
import { getRegistryInfo } from "./registry.js";
import { loadIgnoreConfig, applyIgnores, pathIgnored, addIgnoreEntry, removeIgnoreEntries, describeEntry, entryStatus, findIgnoreFile, readIgnoreFile, today, IGNORE_FILE } from "./ignore.js";
import { stat } from "node:fs/promises";
import { dirname, join } from "node:path";

const VERSION = "0.2.0";
const NVD_MAX_RANGE_DAYS = 120;
const ECO_ENUM = z
  .string()
  .describe("Language/ecosystem: npm|javascript|typescript, pypi|python, go, maven|java|kotlin, nuget|dotnet|csharp, composer|php, rubygems|ruby, cargo|rust, pub|dart|flutter, hex|elixir, swift, cran|r");
const SEVERITY = z.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]);
const FORMAT = z.enum(["markdown", "json"]).default("markdown").describe("markdown for reading, json for structured processing");
const SOURCES = z
  .enum(["auto", "osv", "nvd", "both"])
  .default("auto")
  .describe("auto = OSV for every package (+ NVD CPE cross-check when NVD_API_KEY is set); osv = fast package-native only; nvd = NVD CPE matching only; both = OSV + NVD");

const INSTRUCTIONS = `vuln-watch: security vulnerability intelligence from OSV.dev (package advisories incl. GitHub Advisory DB and malicious packages), NVD (CVE details), CISA KEV (actively exploited) and FIRST EPSS (exploit probability), plus package registry metadata.
Use it to find AND FIX vulnerabilities while coding:
- Before adding/upgrading a dependency → check_package (version optional = latest). It also flags malicious, deprecated and unmaintained packages.
- When asked about project security, or after changing manifests/lockfiles → scan_project_dependencies (path = project root, recursive=true for monorepos). Supports JS/TS, Python, Go (incl. stdlib), Rust, PHP, Ruby, Java/Kotlin (Maven parent POM/BOM, Gradle version catalogs, transitive resolution), C#/.NET, Dart/Flutter, Elixir, Swift and R.
- Findings whose version was estimated from a range (no lockfile) can be false positives: say so and recommend adding a lockfile.
- False positives: when a finding verifiably does not apply (vulnerable API unused, dev/test-only, other platform), record it with ignore_vulnerability (concrete reason, expiry) so it is not reported again; list_ignored / remove_ignore manage them. Never suppress malicious or CISA KEV findings without the user's explicit approval.
- To learn what is newly vulnerable in the project's language → latest_ecosystem_vulnerabilities.
- When a CVE/GHSA/PYSEC/GO/RUSTSEC ID appears (logs, audit output, advisories) → get_vulnerability.
Priority: 🚨 malicious package → 🔥 CISA KEV → high EPSS → CRITICAL/HIGH.
Every finding contains the fixed version, an upgrade command, affected ranges, CWE-specific code-fix guidance, KEV required action and patch/advisory links; the action plan says whether the target/latest version is clean.
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

function progressFn(extra) {
  const token = extra?._meta?.progressToken;
  let step = 0;
  return async (message, done, total) => {
    if (token === undefined) return;
    try {
      await extra.sendNotification({ method: "notifications/progress", params: { progressToken: token, progress: done ?? step++, total, message } });
    } catch {
      /* ignore */
    }
  };
}

function rateNote() {
  return hasApiKey()
    ? ""
    : "\n> Note: NVD_API_KEY is not set, so NVD is limited to 5 requests/30s. Get a free key at https://nvd.nist.gov/developers/request-an-api-key and set NVD_API_KEY for ~10x faster NVD lookups.";
}

function render(findings, format, header, extra = {}) {
  if (format === "json") return text(JSON.stringify({ ...extra, count: findings.length, findings }, null, 2));
  const body = findings.length ? findings.map((f) => findingToMarkdown(f)).join("\n\n") : "_No matching vulnerabilities found._";
  return text(`${header}\n\n${body}`);
}

function summaryLine(findings, plan) {
  const c = (fn) => findings.filter(fn).length;
  return `Vulnerable packages: ${plan.length} · Findings: ${findings.length} (MALICIOUS: ${c((f) => f.malicious)}, KEV: ${c((f) => f.kev)}, EPSS≥10%: ${c((f) => (f.epss?.probability || 0) >= 0.1)}, CRITICAL: ${c((f) => f.severity === "CRITICAL")}, HIGH: ${c((f) => f.severity === "HIGH")})`;
}

function fpSummaryLine(cfg, ign, hidden, skippedPaths) {
  const parts = [];
  if (cfg) parts.push(`${IGNORE_FILE}: ${ign.suppressed.length} suppressed${ign.highRiskKept.length ? `, ${ign.highRiskKept.length} kept despite suppression (KEV/malicious)` : ""}${ign.expired.length ? `, ${ign.expired.length} expired entr${ign.expired.length === 1 ? "y" : "ies"}` : ""}`);
  if (skippedPaths.size) parts.push(`ignorePaths skipped ${skippedPaths.size} manifest(s)`);
  if (hidden.lowConfidence) parts.push(`${hidden.lowConfidence} low-confidence NVD name match(es) hidden (include_low_confidence=true to show)`);
  if (hidden.estimated) parts.push(`${hidden.estimated} finding(s) on estimated versions hidden`);
  return parts.length ? `False-positive controls: ${parts.join(" · ")}` : "";
}

function fpSummaryJson(cfg, ign, hidden, skippedPaths) {
  return {
    ignoreFile: cfg?.file || null,
    suppressed: ign.suppressed.map(({ finding, entry }) => ({ id: finding.id, package: finding.package && `${finding.package.name}@${finding.package.version}`, reason: entry.reason, expires: entry.expires || null })),
    keptDespiteSuppression: ign.highRiskKept.map(({ finding, entry }) => ({ id: finding.id, reason: entry.reason, why: finding.suppressionOverridden?.why })),
    expiredEntries: ign.expired,
    invalidEntries: ign.invalid,
    unusedEntries: ign.unused,
    skippedManifests: Object.fromEntries(skippedPaths),
    hidden,
  };
}

function suppressedToMarkdown(cfg, ign, complete) {
  if (!cfg) return "";
  const L = [];
  if (ign.suppressed.length) {
    L.push(`## Suppressed by ${cfg.file} (${ign.suppressed.length})`);
    for (const { finding: f, entry: e } of ign.suppressed.slice(0, 60)) L.push(`- ${f.id}${f.package ? ` — ${f.package.name}@${f.package.version}` : ""} (${f.severity}) — "${e.reason}"${e.expires ? `, expires ${e.expires}` : ""}`);
    if (ign.suppressed.length > 60) L.push(`- …and ${ign.suppressed.length - 60} more`);
  }
  if (ign.highRiskKept.length) {
    L.push(`\n⚠️ ${ign.highRiskKept.length} suppressed finding(s) are still shown because they are malicious or actively exploited (CISA KEV). Re-verify them with the user; to hide them anyway the entry needs "allowHighRisk": true.`);
  }
  if (ign.expired.length) L.push(`\nExpired suppressions (now reported again — re-verify and renew or remove):\n${ign.expired.map((e) => `- ${describeEntry(e)}`).join("\n")}`);
  if (ign.invalid.length) L.push(`\nInvalid entries (need "reason" and "id" or "package"):\n${ign.invalid.map((e) => `- ${JSON.stringify(e)}`).join("\n")}`);
  if (complete && ign.unused.length) L.push(`\nUnused suppressions (matched nothing in this scan — likely fixed; consider removing with remove_ignore):\n${ign.unused.map((e) => `- ${describeEntry(e)}`).join("\n")}`);
  return L.join("\n");
}

const NEXT_STEPS =
  "---\nIf a finding does not apply to this project (vulnerable function not used, dev-only tooling, platform not used), verify it in the code and record it with ignore_vulnerability (with a concrete reason) instead of repeating it.\nNext steps: remove malicious packages first, then update manifests + lockfiles to the target versions (prefer the version marked as having no known advisories), search the codebase for usages of the vulnerable APIs described above and apply the code-fix guidance, then re-run the scan to verify.";

// ---------- tools ----------

server.registerTool(
  "scan_project_dependencies",
  {
    title: "Scan project dependencies for known vulnerabilities",
    description:
      "Reads lockfiles/manifests for JavaScript/TypeScript (package-lock, pnpm, yarn, bun, node_modules), Python (poetry/uv/pdm/pylock/Pipfile.lock, requirements, pyproject), Go (go.mod + toolchain stdlib), Rust, PHP, Ruby, Java/Kotlin (pom.xml with parent POM/BOM resolution, Gradle incl. version catalogs and Spring Boot BOM, gradle.lockfile; transitive deps resolved via Maven Central), C#/.NET (packages.lock.json, obj/project.assets.json, csproj + Directory.Packages.props, packages.config), Dart/Flutter, Elixir, Swift and R, and checks every dependency version against OSV.dev (GitHub Advisory DB, PyPA, Go, RustSec, malicious packages) and NVD, enriched with CISA KEV and EPSS. Returns a prioritized action plan (target version verified clean, latest version, deprecation/maintenance status, upgrade commands) plus detailed findings with code-fix guidance.",
    inputSchema: {
      path: z.string().describe("Project root directory or a manifest/lockfile path"),
      recursive: z.boolean().default(false).describe("Also scan sub-directories (monorepos), up to depth 4; skips node_modules, vendor, build output, virtualenvs"),
      include_dev: z.boolean().default(false).describe("Include dev/test dependencies"),
      include_transitive: z.boolean().default(true).describe("Include transitive deps (from lockfiles; for Maven/Gradle resolved via Maven Central POMs)"),
      sources: SOURCES,
      max_packages: z.number().int().min(1).max(2000).optional().describe("Max packages for the slow NVD cross-check in this call (default 10 without NVD_API_KEY, 60 with). OSV always checks all packages."),
      offset: z.number().int().min(0).default(0).describe("Continue the NVD cross-check from this package index (OSV results are reported in the offset=0 call)"),
      check_health: z.boolean().default(true).describe("Report deprecated / yanked / unmaintained direct dependencies via package registries"),
      min_severity: SEVERITY.optional().describe("Hide findings below this severity (malicious and KEV findings are always shown)"),
      detailed_findings: z.number().int().min(0).max(500).default(15).describe("How many top-priority findings to show in full detail (the rest are one-line summaries). The action plan always covers every package."),
      estimated_versions: z.enum(["flag", "hide"]).default("flag").describe("Findings for versions estimated from a range (no lockfile): flag = show with a false-positive warning, hide = leave them out (count only)"),
      include_low_confidence: z.boolean().default(false).describe("Include NVD-only matches based on a guessed CPE product name (match confidence: medium). Hidden by default to avoid false positives."),
      apply_ignore_file: z.boolean().default(true).describe(`Apply suppressions and ignorePaths from the nearest ${".vulnwatch.json"}`),
      format: FORMAT,
    },
    annotations: { readOnlyHint: true, openWorldHint: true },
  },
  async (args, extra) => {
    try {
      const target = resolve(args.path);
      const progress = progressFn(extra);
      await progress("reading manifests / resolving Maven & Gradle graphs");
      let { deps, manifests, notes } = await collectDependencies(target, { includeDev: args.include_dev, recursive: args.recursive, transitive: args.include_transitive });
      if (!args.include_transitive) deps = deps.filter((d) => d.direct !== false);
      // false-positive controls: ignorePaths from .vulnwatch.json
      const ignoreCfg = args.apply_ignore_file ? await loadIgnoreConfig(target) : null;
      const scanRoot = (await stat(target)).isDirectory() ? target : dirname(target);
      const skippedPaths = new Map();
      if (ignoreCfg?.ignorePaths?.length) {
        deps = deps.filter((d) => {
          const hit = pathIgnored(ignoreCfg, join(scanRoot, d.source || ""));
          if (hit) skippedPaths.set(d.source, hit);
          return !hit;
        });
        manifests = manifests.map((m) => (skippedPaths.has(m.replace(/ \(.*\)$/, "")) ? `${m.replace(/ \(.*\)$/, "")} (skipped: ignorePaths "${skippedPaths.get(m.replace(/ \(.*\)$/, ""))}")` : m));
      }
      deps.sort((a, b) => (a.direct === false) - (b.direct === false) || a.name.localeCompare(b.name));
      if (!deps.length)
        return text(`No dependencies with resolvable versions found in ${target}.${manifests.length ? ` Manifests seen: ${manifests.join(", ")}` : ""}\nSupported: package-lock.json, pnpm-lock.yaml, yarn.lock, bun.lock, package.json(+node_modules), poetry.lock, uv.lock, pdm.lock, pylock.toml, Pipfile.lock, requirements*.txt, pyproject.toml, go.mod, Cargo.lock/Cargo.toml, composer.lock/composer.json, Gemfile.lock/Gemfile, pom.xml, build.gradle(.kts), gradle/libs.versions.toml, gradle.lockfile, packages.lock.json, obj/project.assets.json, *.csproj, Directory.Packages.props, packages.config, pubspec.lock, mix.lock, Package.resolved, renv.lock. Try recursive=true for monorepos.${notes?.length ? `\nNotes: ${notes.join("; ")}` : ""}`);

      const useOsv = args.sources !== "nvd" && args.offset === 0;
      const useNvd = args.sources === "nvd" || args.sources === "both" || (args.sources === "auto" && hasApiKey());
      const max = args.max_packages ?? (hasApiKey() ? 60 : 10);
      const nvdDeps = useNvd ? deps.slice(args.offset, args.offset + max) : [];

      const analysis = await analyzeDependencies(deps, { useOsv, nvdDeps, minSeverity: args.min_severity, onProgress: progress });
      const { errors } = analysis;
      let findings = analysis.findings;
      // false-positive controls
      const hidden = { lowConfidence: 0, estimated: 0 };
      findings = findings.filter((f) => {
        if (!args.include_low_confidence && f.package?.confidence === "medium" && f.sources.length === 1 && f.sources[0] === "NVD" && !f.kev && !f.malicious) return hidden.lowConfidence++, false;
        if (args.estimated_versions === "hide" && f.package?.versionSource === "range" && !f.kev && !f.malicious) return hidden.estimated++, false;
        return true;
      });
      const ign = applyIgnores(findings, ignoreCfg);
      findings = ign.kept;
      await progress("registry lookups");
      const plan = await enrichPlan(actionPlan(findings));
      const health = args.check_health ? await healthIssues(deps, new Set(plan.map((p) => `${p.ecosystem}:${p.name}@${p.version}`))) : [];

      const nextOffset = useNvd && args.offset + nvdDeps.length < deps.length ? args.offset + nvdDeps.length : null;
      const ecosystems = [...new Set(deps.map((d) => d.ecosystem))];
      const coverage = {
        osv: useOsv ? `all ${deps.length} packages` : args.offset > 0 ? "reported in the offset=0 call" : "skipped",
        nvd: useNvd ? `packages ${args.offset + 1}–${args.offset + nvdDeps.length} of ${deps.length}` : "skipped (set NVD_API_KEY or sources='both' to cross-check NVD CPE data)",
      };
      if (args.format === "json") {
        return text(JSON.stringify({ path: target, manifests, notes, ecosystems, totalDependencies: deps.length, coverage, nextOffset, falsePositiveControls: fpSummaryJson(ignoreCfg, ign, hidden, skippedPaths), actionPlan: plan, packageHealth: health, findings, errors }, null, 2));
      }
      const head = [
        `# Dependency vulnerability scan: ${target}`,
        `Manifests: ${manifests.join(", ")}`,
        `Ecosystems: ${ecosystems.map((e) => ECOSYSTEMS[e]?.label || e).join(", ")} · Dependencies: ${deps.length} (direct ${deps.filter((d) => d.direct !== false).length})`,
        (() => {
          const c = (s) => deps.filter((d) => d.versionSource === s).length;
          const est = c("range");
          return `Version sources: lockfile ${c("lockfile")}, installed ${c("installed")}, exact pin ${c("manifest")}, resolved graph ${c("resolved")}, estimated from range ${est}${est ? " ⚠️ (estimated versions can cause false positives — add a lockfile)" : ""}`;
        })(),
        notes.length ? `Notes:\n${notes.map((n) => `- ${n}`).join("\n")}` : "",
        `Coverage: OSV ${coverage.osv} · NVD ${coverage.nvd}`,
        summaryLine(findings, plan),
        fpSummaryLine(ignoreCfg, ign, hidden, skippedPaths),
        nextOffset != null ? `\n⚠️ NVD cross-check not finished → call again with offset=${nextOffset}.` : "",
        errors.length ? `\nErrors: ${errors.join("; ")}` : "",
        useNvd ? rateNote() : "",
      ].filter(Boolean).join("\n");
      const body = findingsToMarkdown(findings, { detailed: args.detailed_findings });
      return text([head, planToMarkdown(plan), healthToMarkdown(health), `## Findings (malicious → KEV → EPSS → HIGH/CRITICAL → newest)\n\n${body}`, suppressedToMarkdown(ignoreCfg, ign, args.offset === 0), NEXT_STEPS].filter(Boolean).join("\n\n"));
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
      "Checks one library or product version before installing/upgrading it (e.g. lodash 4.17.15 on npm, django on pypi, org.apache.logging.log4j:log4j-core on maven, nginx 1.18.0). Uses OSV (package advisories + malicious packages) when an ecosystem is given and NVD CPE matching for products, enriched with CISA KEV, EPSS and registry data (latest version, deprecation, last release). If version is omitted the latest published version is checked.",
    inputSchema: {
      name: z.string().describe("Package/product name: 'lodash', '@babel/traverse', 'django', 'github.com/gin-gonic/gin', 'group:artifact' for Maven, 'vendor/package' for Composer, or a product like 'nginx'"),
      version: z.string().optional().describe("Version to check, e.g. '4.17.15'. Omit to check the latest published version (requires ecosystem)."),
      ecosystem: ECO_ENUM.optional(),
      vendor: z.string().optional().describe("Optional CPE vendor to narrow NVD results, e.g. 'djangoproject', 'f5', 'openssl'"),
      sources: SOURCES,
      min_severity: SEVERITY.optional(),
      project_path: z.string().optional().describe(`Apply suppressions from this project's ${IGNORE_FILE}`),
      format: FORMAT,
    },
    annotations: { readOnlyHint: true, openWorldHint: true },
  },
  async (args, extra) => {
    try {
      const eco = resolveEcosystem(args.ecosystem);
      let version = args.version?.replace(/^v/, "");
      let reg = null;
      if (eco) reg = await getRegistryInfo({ name: args.name, version: version || "0", ecosystem: eco });
      if (!version) {
        if (!reg?.latest)
          return errorResult(
            eco
              ? `${args.name} was not found in the ${eco} registry. Check the spelling — a non-existent or misspelled name is a typosquatting risk; do not install a look-alike package. Pass version explicitly to check a product instead.`
              : "version is required when ecosystem is not given"
          );
        version = reg.latest;
      }
      const dep = { name: args.name, version, ecosystem: eco, direct: true };
      const useOsv = Boolean(eco && OSV_ECOSYSTEM[eco]) && args.sources !== "nvd";
      const useNvd = args.sources === "nvd" || args.sources === "both" || !useOsv || (args.sources === "auto" && hasApiKey());
      const analysis = await analyzeDependencies([dep], { useOsv, nvdDeps: useNvd ? [dep] : [], vendor: args.vendor?.toLowerCase(), minSeverity: args.min_severity, onProgress: progressFn(extra) });
      const { errors } = analysis;
      const ignoreCfg = args.project_path ? await loadIgnoreConfig(resolve(args.project_path)) : null;
      const ign = applyIgnores(analysis.findings, ignoreCfg);
      const findings = ign.kept;
      const plan = await enrichPlan(actionPlan(findings));
      if (eco && version !== reg?.latest) reg = await getRegistryInfo(dep);
      if (args.format === "json") return text(JSON.stringify({ package: dep, registry: reg, sources: { osv: useOsv, nvd: useNvd }, actionPlan: plan, count: findings.length, findings, errors }, null, 2));

      const L = [`# ${args.name}@${version}${eco ? ` (${ECOSYSTEMS[eco].label})` : ""}${args.version ? "" : " — latest published version"}`];
      L.push(`Sources: ${[useOsv && "OSV", useNvd && "NVD"].filter(Boolean).join(" + ")} + CISA KEV + EPSS${errors.length ? ` · Errors: ${errors.join("; ")}` : ""}`);
      if (reg) {
        const info = [`latest ${reg.latest}${reg.referenceDate ? ` (${reg.referenceDate})` : ""}`];
        if (reg.currentDeprecated) info.push(`⚠️ this version is deprecated: ${reg.currentDeprecated}`);
        else if (reg.deprecated) info.push(`⚠️ package deprecated: ${reg.deprecated}`);
        if (reg.currentYanked) info.push(`⚠️ this version was yanked (${reg.currentYanked})`);
        if (reg.stale) info.push(`⚠️ ${reg.stale}`);
        L.push(`Registry: ${info.join(" · ")}${reg.url ? ` · ${reg.url}` : ""}`);
      } else if (eco && !(eco === "go" && args.name === "stdlib") && eco !== "swift") {
        L.push(`Registry: package not found in the ${eco} registry — check the name (typosquatting risk if you expected it to exist).`);
      }
      L.push(findings.length ? summaryLine(findings, plan) : ign.suppressed.length ? `✅ No unsuppressed vulnerabilities (${ign.suppressed.length} suppressed by ${ignoreCfg.file}).` : "✅ No known vulnerabilities for this version.");
      if (findings.length && ign.suppressed.length) L.push(`${ign.suppressed.length} finding(s) suppressed by ${ignoreCfg.file}.`);
      if (useNvd && !hasApiKey()) L.push(rateNote().trim());
      if (!useOsv && !eco) L.push("> Tip: pass ecosystem (npm, pypi, go, maven, ...) for precise package-level matching via OSV.");
      const body = findings.length ? findingsToMarkdown(findings, { detailed: 30 }) : "";
      return text([L.join("\n"), planToMarkdown(plan), body].filter(Boolean).join("\n\n"));
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
      attachEpss(findings, await getEpss(findings.map((f) => f.id)));
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
      attachEpss(findings, await getEpss(findings.map((f) => f.id)));
      return render(findings, args.format, `# NVD search "${args.keyword}" — ${total} total matches, showing ${findings.length} most recent (KEV first)${rateNote()}`, { total });
    } catch (err) {
      return errorResult(err);
    }
  }
);

server.registerTool(
  "get_vulnerability",
  {
    title: "Get full details for a vulnerability (CVE / GHSA / OSV id)",
    description:
      "Full details for one vulnerability by CVE, GHSA, PYSEC, GO, RUSTSEC or MAL id: description, CVSS, EPSS, CWE with code-fix guidance, per-package fixed versions (OSV), every affected range (NVD), CISA KEV required action/due date and patch/advisory references. Pass installed_version (+ ecosystem/package) to get the exact fixed version for your package.",
    inputSchema: {
      id: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]+$/).describe("e.g. CVE-2021-44228, GHSA-35jh-r3h4-6jhm, PYSEC-2021-19, GO-2022-0969"),
      installed_version: z.string().optional().describe("Your installed version, to compute the nearest fixed version"),
      package: z.string().optional().describe("Package name you use (OSV) or CPE product name (NVD), if the advisory covers several packages"),
      ecosystem: ECO_ENUM.optional(),
      format: FORMAT,
    },
    annotations: { readOnlyHint: true, openWorldHint: true },
  },
  async (args) => {
    try {
      const raw = args.id.trim();
      const isCve = /^CVE-\d{4}-\d+$/i.test(raw);
      const id = isCve ? raw.toUpperCase() : raw;
      // OSV: for a CVE, follow its GHSA/other aliases to get package-level fix data
      const osvRecords = [];
      try {
        const first = await getOsvVuln(id);
        if (first) {
          if (!isCve || (first.affected || []).some((a) => a.package)) osvRecords.push(first);
          for (const alias of (first.aliases || []).filter((a) => /^(GHSA|PYSEC|GO|RUSTSEC|RUBYSEC|MAL)-/.test(a)).slice(0, 3)) {
            const rec = await getOsvVuln(alias);
            if (rec) osvRecords.push(rec);
          }
        }
      } catch {
        /* OSV optional */
      }
      const cveId = isCve ? id : osvRecords.flatMap((r) => [r.id, ...(r.aliases || [])]).find((x) => /^CVE-\d{4}-\d+$/.test(x)) || null;
      const [cve, kev] = cveId ? await Promise.all([getCve(cveId).catch(() => null), getKevEntry(cveId)]) : [null, null];
      if (!cve && !osvRecords.length) {
        if (kev) return text(`${id} not found in NVD/OSV, but it is in CISA KEV:\n${JSON.stringify(kev, null, 2)}`);
        return text(`${id} not found in NVD, OSV or CISA KEV.`);
      }

      const eco = resolveEcosystem(args.ecosystem);
      const version = args.installed_version?.replace(/^v/, "");
      // package table from OSV
      const pkgRows = [];
      for (const r of osvRecords) {
        for (const a of r.affected || []) {
          if (!a.package) continue;
          const ranges = (a.ranges || []).filter((x) => x.type !== "GIT").map((x) => {
            const ev = x.events || [];
            const parts = [];
            let intro = null;
            for (const e of ev) {
              if (e.introduced !== undefined) intro = e.introduced;
              else if (e.fixed !== undefined) { parts.push(`${intro && intro !== "0" ? `>= ${intro}, ` : ""}< ${e.fixed}`); intro = null; }
              else if (e.last_affected !== undefined) { parts.push(`${intro && intro !== "0" ? `>= ${intro}, ` : ""}<= ${e.last_affected} (no fix)`); intro = null; }
            }
            if (intro !== null) parts.push(`>= ${intro} (no fix)`);
            return parts.join("; ");
          }).filter(Boolean);
          const key = `${a.package.ecosystem}/${a.package.name}`;
          const rtext = ranges.join("; ") || (a.versions?.length ? `versions: ${a.versions.slice(0, 10).join(", ")}${a.versions.length > 10 ? ", …" : ""}` : "");
          const prev = pkgRows.find((p) => p.key === key);
          if (!prev) pkgRows.push({ key, ecosystem: a.package.ecosystem, name: a.package.name, ranges: rtext });
          else if (rtext && !prev.ranges.includes(rtext)) prev.ranges = [prev.ranges, rtext].filter(Boolean).join("; ");
        }
      }

      let f;
      const kevLookup = (x) => (x === cveId ? kev : null);
      const want = args.package?.toLowerCase();
      const nameMatches = (n) => !want || [n.toLowerCase(), n.toLowerCase().split(/[:/]/).pop()].includes(want);
      const osvEcoKey = Object.entries(OSV_ECOSYSTEM).find(([, v]) => pkgRows.some((p) => p.ecosystem === v && nameMatches(p.name)))?.[0];
      const pkgRow = pkgRows.find((p) => nameMatches(p.name) && (!eco || p.ecosystem === OSV_ECOSYSTEM[eco])) || null;
      if (cve) {
        const pkg = version ? { name: args.package || affectedRanges(cve)[0]?.product || "package", product: args.package, version, ecosystem: eco, direct: true, confidence: "high" } : null;
        f = buildFinding(cve, kev, pkg, { maxRefs: 30 });
        const fmtRange = (r) => [r.exactVersion && `= ${r.exactVersion}`, r.versionStartIncluding && `>= ${r.versionStartIncluding}`, r.versionStartExcluding && `> ${r.versionStartExcluding}`, r.versionEndExcluding && `< ${r.versionEndExcluding}`, r.versionEndIncluding && `<= ${r.versionEndIncluding}`].filter(Boolean).join(", ") || "all versions";
        const all = affectedRanges(cve);
        const wanted = args.package?.toLowerCase();
        const ordered = [...all.filter((r) => wanted && r.product?.toLowerCase() === wanted), ...all.filter((r) => !(wanted && r.product?.toLowerCase() === wanted))];
        const seenAff = new Set();
        const uniq = ordered.filter((r) => { const k = r.criteria + fmtRange(r); return seenAff.has(k) ? false : seenAff.add(k); });
        const MAX_AFF = 25;
        f.affected = uniq.slice(0, MAX_AFF).map((r) => ({ cpe: `${r.vendor}:${r.product}${r.targetSw && r.targetSw !== "*" ? ` (${r.targetSw})` : ""}`, range: fmtRange(r) }));
        if (uniq.length > MAX_AFF) {
          const vendors = [...new Set(uniq.slice(MAX_AFF).map((r) => r.vendor))];
          f.affected.push({ cpe: `…and ${uniq.length - MAX_AFF} more configurations`, range: `(vendors: ${vendors.slice(0, 15).join(", ")}${vendors.length > 15 ? ", …" : ""})` });
        }
        if (osvRecords.length) {
          f.sources.push("OSV");
          f.aliases = [...new Set(osvRecords.flatMap((r) => [r.id, ...(r.aliases || [])]).filter((x) => x !== cveId))];
          const ghsa = f.aliases.find((x) => x.startsWith("GHSA-"));
          if (ghsa) f.advisoryUrl = `https://github.com/advisories/${ghsa}`;
        }
      } else {
        const depEco = eco || osvEcoKey;
        const dep = { name: pkgRow?.name || args.package || "package", version: version || "0.0.0-unknown", ecosystem: depEco, direct: true };
        f = buildOsvFinding({ primary: osvRecords[0], others: osvRecords.slice(1) }, dep, kevLookup, { maxRefs: 30 });
        if (!version) Object.assign(f, { package: null, fixedVersion: null, upgradeCommand: null });
      }
      // precise package fix from OSV when installed_version given
      if (version && pkgRow && osvRecords.length) {
        const depEco = eco || Object.entries(OSV_ECOSYSTEM).find(([, v]) => v === pkgRow.ecosystem)?.[0];
        const dep = { name: pkgRow.name, version, ecosystem: depEco, direct: true };
        const of = buildOsvFinding({ primary: osvRecords[0], others: osvRecords.slice(1) }, dep, kevLookup);
        if (of.fixedVersion) Object.assign(f, { fixedVersion: of.fixedVersion, fixedVersionSource: "OSV", upgradeCommand: of.upgradeCommand, package: of.package });
      }
      attachEpss([f], await getEpss([f.id]));

      if (args.format === "json") return text(JSON.stringify({ finding: f, packages: pkgRows, kevRaw: kev }, null, 2));
      let md = findingToMarkdown(f);
      if (pkgRows.length) {
        md += `\n- Affected packages (OSV, fixed version = upper bound):`;
        for (const p of pkgRows.slice(0, 30)) md += `\n  - ${p.ecosystem}/${p.name}: ${p.ranges || "see advisory"}`;
        if (pkgRows.length > 30) md += `\n  - …and ${pkgRows.length - 30} more`;
      }
      if (kev?.notes) md += `\n- KEV notes: ${kev.notes}`;
      if (version && !f.fixedVersion) md += `\n- ℹ️ Installed version ${version} did not match an affected range with a recorded fix${args.package ? "" : " (pass `package` + `ecosystem` if the advisory covers several packages)"} — check the affected ranges above.`;
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
      const epss = await getEpss(cve_ids);
      const ep = (id) => { const e = epss.get(id.toUpperCase()); return e ? ` · EPSS ${(e.epss * 100).toFixed(1)}% (pct ${(e.percentile * 100).toFixed(0)})` : ""; };
      const L = [`# CISA KEV check (catalog ${catalog.catalogVersion}, ${catalog.count} entries)`, ""];
      const hits = [];
      for (const raw of cve_ids) {
        const k = await getKevEntry(raw.trim());
        if (k) hits.push(k);
        else L.push(`- ${raw.toUpperCase()}: not in KEV${ep(raw.trim())}`);
      }
      for (const k of hits) {
        L.push(`- 🔥 **${k.cveID}** IN KEV — ${k.vendorProject} ${k.product}: ${k.vulnerabilityName}\n  - Added ${k.dateAdded}, due ${k.dueDate}, ransomware: ${k.knownRansomwareCampaignUse}${ep(k.cveID)}\n  - ${k.shortDescription}\n  - Required action: ${k.requiredAction}${k.notes ? `\n  - Notes: ${k.notes}` : ""}`);
      }
      L.splice(1, 0, `${hits.length} of ${cve_ids.length} are known exploited. Fix those first; use get_vulnerability for fixed versions. EPSS = probability of exploitation in the next 30 days.`);
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

// ---------- false-positive management ----------

async function highRiskInfo(id) {
  const up = id.toUpperCase();
  let cve = /^CVE-/.test(up) ? up : null;
  let malicious = /^MAL-/.test(up);
  try {
    const rec = await getOsvVuln(/^CVE-/.test(up) ? up : id);
    if (rec) {
      cve ||= [rec.id, ...(rec.aliases || [])].find((x) => /^CVE-/.test(x)) || null;
      malicious ||= (rec.database_specific?.cwe_ids || []).includes("CWE-506") || /^malicious (code|package)/i.test(rec.summary || "");
    }
  } catch {
    /* best effort */
  }
  const kev = cve ? await getKevEntry(cve) : null;
  return { cve, kev, malicious };
}

const DATE = z.string().regex(/^(\d{4}-\d{2}-\d{2}|never)$/, "YYYY-MM-DD or 'never'");

server.registerTool(
  "ignore_vulnerability",
  {
    title: "Record a false positive / accepted risk",
    description: `Suppresses a finding in future scans by writing it to the project's ${IGNORE_FILE} (committed to git so the whole team shares it). Use ONLY after verifying in the code that it does not apply (e.g. the vulnerable function/feature is never used, the package is build/test-only, the affected platform is not used) or when the user explicitly accepts the risk — always give a concrete reason. Suppressions expire (default 90 days) so they get re-reviewed. Malicious packages and CISA KEV (actively exploited) findings are refused unless allow_high_risk=true, which requires the user's explicit approval.`,
    inputSchema: {
      path: z.string().describe(`Project root (where ${IGNORE_FILE} lives or will be created; an existing file in a parent directory is reused)`),
      id: z.string().optional().describe("Advisory id (CVE/GHSA/PYSEC/GO/...). Matches aliases too. Omit to suppress every advisory of `package`."),
      package: z.string().optional().describe("Package name to scope the suppression to (recommended)"),
      version: z.string().optional().describe("Only this exact version (the finding re-appears after the version changes)"),
      ecosystem: ECO_ENUM.optional(),
      reason: z.string().min(10).describe("Concrete justification, e.g. 'lodash.template is never called (checked src/**)'"),
      expires: DATE.optional().describe("Re-review date YYYY-MM-DD (default: 90 days from today) or 'never'"),
      allow_high_risk: z.boolean().default(false).describe("Required to suppress malicious or CISA KEV findings — only with explicit user approval"),
    },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  async (args) => {
    try {
      if (!args.id && !args.package) return errorResult("Provide at least one of id or package.");
      const eco = args.ecosystem ? resolveEcosystem(args.ecosystem) || args.ecosystem : undefined;
      if (args.id) {
        const risk = await highRiskInfo(args.id);
        if ((risk.kev || risk.malicious) && !args.allow_high_risk) {
          return errorResult(
            `${args.id} is ${risk.malicious ? "a MALICIOUS package advisory" : `actively exploited (CISA KEV, added ${risk.kev.dateAdded})`}. Not suppressed. Fix it instead, or — only if the user explicitly accepts this risk — call again with allow_high_risk=true.`
          );
        }
      }
      const expires = args.expires || new Date(Date.now() + 90 * 86400_000).toISOString().slice(0, 10);
      const { file, entry, updated } = await addIgnoreEntry(resolve(args.path), {
        id: args.id,
        package: args.package,
        version: args.version,
        ecosystem: eco,
        reason: args.reason,
        expires,
        allowHighRisk: args.allow_high_risk || undefined,
      });
      return text(`${updated ? "Updated" : "Added"} suppression in ${file}:\n- ${describeEntry(entry)}\n\nCommit ${IGNORE_FILE} so the team shares it. It will be reported again after ${entry.expires === "never" ? "— never (consider an expiry date)" : entry.expires}${entry.version ? ` or when ${entry.package || "the package"} is no longer ${entry.version}` : ""}.`);
    } catch (err) {
      return errorResult(err);
    }
  }
);

server.registerTool(
  "list_ignored",
  {
    title: "List suppressed vulnerabilities",
    description: `Shows the suppressions and ignorePaths in the project's ${IGNORE_FILE}, with status (active / expiring soon / expired / invalid).`,
    inputSchema: { path: z.string().describe("Project root or any path inside it") },
    annotations: { readOnlyHint: true, openWorldHint: false },
  },
  async ({ path }) => {
    try {
      const file = await findIgnoreFile(resolve(path));
      if (!file) return text(`No ${IGNORE_FILE} found for ${resolve(path)} (searched upwards to the git root). Use ignore_vulnerability to create one.`);
      const cfg = await readIgnoreFile(file);
      const soon = new Date(Date.now() + 14 * 86400_000).toISOString().slice(0, 10);
      const L = [`# ${file}`, `${cfg.ignore.length} suppression(s), ${cfg.ignorePaths.length} ignored path pattern(s)`, ""];
      for (const e of cfg.ignore) {
        let st = entryStatus(e);
        if (st === "active" && e.expires && e.expires !== "never" && e.expires <= soon) st = "expiring soon";
        if (st === "active" && (!e.expires || e.expires === "never")) st = "active (no expiry)";
        L.push(`- [${st}] ${describeEntry(e)}${e.added ? ` · added ${e.added}` : ""}`);
      }
      if (cfg.ignorePaths.length) L.push("", "Ignored paths (manifests under these are not scanned):", ...cfg.ignorePaths.map((p) => `- ${p}`));
      return text(L.join("\n"));
    } catch (err) {
      return errorResult(err);
    }
  }
);

server.registerTool(
  "remove_ignore",
  {
    title: "Remove a suppression",
    description: `Removes suppression entries from ${IGNORE_FILE} (e.g. when the package was upgraded, or the finding turned out to be relevant).`,
    inputSchema: {
      path: z.string().describe("Project root or any path inside it"),
      id: z.string().optional(),
      package: z.string().optional(),
      version: z.string().optional(),
    },
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
  },
  async (args) => {
    try {
      if (!args.id && !args.package) return errorResult("Provide id and/or package to select the entries to remove.");
      const { file, removed } = await removeIgnoreEntries(resolve(args.path), args);
      if (!file) return text(`No ${IGNORE_FILE} found.`);
      if (!removed.length) return text(`No matching suppression in ${file}.`);
      return text(`Removed ${removed.length} suppression(s) from ${file}:\n${removed.map((e) => `- ${describeEntry(e)}`).join("\n")}`);
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
1. Call scan_project_dependencies with recursive=true (continue with offset if it says the NVD cross-check is not finished).
2. Call latest_ecosystem_vulnerabilities for each detected ecosystem (days=30) to catch brand-new issues.
3. Fix in priority order: MALICIOUS packages (remove) → CISA KEV → high EPSS → CRITICAL → HIGH; also replace deprecated/unmaintained packages from the package health section. For each: update the manifest and lockfile to the fixed version (use overrides/resolutions for transitive deps), and grep the codebase for usage of the vulnerable feature, applying the CWE code-fix guidance.
4. For findings that verifiably do not apply (vulnerable function/feature unused, dev/test-only, other platform, version estimated from a range but the installed version is fixed), record them with ignore_vulnerability using a concrete reason. Never suppress malicious or CISA KEV findings without asking the user.
5. Re-run the scan to verify, then summarize what was fixed, what was suppressed (and why), what remains (no fix available) and recommended mitigations.`,
        },
      },
    ],
  })
);

const transport = new StdioServerTransport();
await server.connect(transport);
// warm the KEV cache in the background
loadKev().catch(() => {});

# vuln-watch-mcp

An MCP server that lets Claude Code or Codex **find security vulnerabilities while coding and apply the fixes themselves**.

Data sources:
- **CISA KEV**: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json (vulnerabilities actively exploited in the wild)
- **NVD CVE API 2.0**: https://services.nvd.nist.gov/rest/json/cves/2.0 (CVE details, CVSS, CWE, affected version ranges)

## Core design: information an agent can act on

Every result includes the following:

| Item | Description |
|---|---|
| Priority | 🔥 KEV (actively exploited) → CRITICAL/HIGH → most recent first |
| Fixed version | Upper bound from the NVD CPE range (`versionEndExcluding`), cross-checked against "fixed in X" text in the CVE description |
| Upgrade command | Ecosystem-specific commands such as `npm install x@y`, `pip install "x>=y"`, `go get x@vY` |
| Transitive dependencies | Guidance on `npm ls`, `overrides`/`resolutions`, constraints, etc. |
| Major-upgrade warning | Flags when breaking changes need review |
| Code fix guidance | Code-level fixes per CWE (e.g. CWE-1321 Prototype Pollution → block `__proto__` keys) |
| KEV info | Date added, CISA due date, ransomware use, required action |
| References | Patch commits / vendor advisories / GHSA listed first |
| Action plan | Per package, the single target version that clears all of its CVEs |

## Tools

| Tool | Purpose |
|---|---|
| `scan_project_dependencies` | Reads `package-lock.json`/`package.json`, `requirements*.txt` and `go.mod`, then checks every dependency version (direct dependencies first; `offset` continues a scan) |
| `check_package` | Checks a single package/product version (`lodash 4.17.15`, `django 3.2.0`, `nginx 1.18.0`, …) |
| `latest_ecosystem_vulnerabilities` | Latest CVEs for a language/ecosystem (npm, python, go, java, php, ruby, rust, dotnet), newest first |
| `search_vulnerabilities` | NVD keyword search (newest first; `ecosystem`, `cwe`, `days`, `kev_only` filters) |
| `get_vulnerability` | Full details for one CVE; pass `installed_version` to get the fixed version |
| `check_kev` | Checks whether CVE IDs are in KEV (fast local lookup) |
| `search_kev` | Searches KEV by vendor, product, keyword, recency or ransomware use |

Prompt: `security_audit` runs the whole loop: scan → check latest vulnerabilities → fix → verify again.

## Installation

```bash
cd /mnt/d/Source/vuln_watch_mcp
npm install
```

An **NVD API key** is strongly recommended (free): https://nvd.nist.gov/developers/request-an-api-key
Without a key, NVD allows 5 requests per 30 seconds, so the server waits about 6.5 seconds per request. With a key, the wait is about 0.7 seconds.

### Claude Code

```bash
claude mcp add vuln-watch --scope user \
  -e NVD_API_KEY=your-key \
  -- node /mnt/d/Source/vuln_watch_mcp/src/index.js
```

### Codex (`~/.codex/config.toml`)

```toml
[mcp_servers.vuln-watch]
command = "node"
args = ["/mnt/d/Source/vuln_watch_mcp/src/index.js"]
env = { NVD_API_KEY = "your-key" }
startup_timeout_sec = 20
tool_timeout_sec = 600   # dependency scans can take a while (the default is 60 seconds)
```

### Usage examples (prompts)

- "Check this project's dependencies for security vulnerabilities and fix them"
- "Show me the critical Python vulnerabilities from the last 2 weeks"
- "Are there any vulnerabilities in next 15.5.0?"
- "How do I fix CVE-2021-44228 in our log4j 2.14.1?"

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `NVD_API_KEY` | (none) | NVD API key |
| `KEV_TTL_HOURS` | 6 | KEV catalog cache lifetime |
| `NVD_TTL_HOURS` | 12 | NVD response cache lifetime |
| `VULN_WATCH_CACHE_DIR` | `~/.cache/vuln-watch-mcp` | Disk cache location (stale cache is used when offline) |

## Testing

```bash
npm run smoke                                     # list tools and prompts
node scripts/smoke.js scan_project_dependencies '{"path":"examples/vulnerable-node"}'
node scripts/smoke.js latest_ecosystem_vulnerabilities '{"ecosystem":"npm","days":14}'
```

## Limitations

- Package matching depends on NVD CPE data. Packages without a CPE entry, and brand-new CVEs NVD has not analyzed yet (`Awaiting Analysis`), are not detected by version scans. Use `latest_ecosystem_vulnerabilities`/`search_vulnerabilities` (keyword-based) to supplement them.
- Package names are matched to CPE product names (e.g. `@scope/name` → `name`). Matches with `Match confidence: medium` need to be checked to confirm they are the same project.
- `package.json` ranges such as `^1.2.3` are treated as the minimum version (`1.2.3`). Keep a lockfile in place for accurate results.

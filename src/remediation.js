// Short, code-level remediation guidance per CWE so a coding agent can act on it.
export const CWE_GUIDANCE = {
  "CWE-20": ["Improper Input Validation", "Validate type/length/format of all external input at trust boundaries with an allow-list schema (e.g. zod/joi/pydantic)."],
  "CWE-22": ["Path Traversal", "Resolve paths with path.resolve/realpath and verify they stay inside an allowed base dir; reject '..' and absolute paths from user input."],
  "CWE-77": ["Command Injection", "Never build shell strings from input; use execFile/spawn with argument arrays (shell:false) and allow-list arguments."],
  "CWE-78": ["OS Command Injection", "Use execFile/spawn (no shell) or subprocess.run([...], shell=False); never interpolate user input into a command line."],
  "CWE-79": ["Cross-site Scripting (XSS)", "Contextually encode output, avoid innerHTML/dangerouslySetInnerHTML/v-html with untrusted data, sanitize HTML with DOMPurify, set a strict CSP."],
  "CWE-89": ["SQL Injection", "Use parameterized queries / ORM bindings only; never concatenate input into SQL. Validate identifiers against an allow-list."],
  "CWE-94": ["Code Injection", "Remove eval/new Function/vm on untrusted data; use safe parsers (JSON.parse) and sandboxed template engines."],
  "CWE-200": ["Information Exposure", "Strip secrets/stack traces from responses and logs; return generic errors to clients."],
  "CWE-269": ["Improper Privilege Management", "Run with least privilege and re-check authorization on every privileged operation."],
  "CWE-276": ["Incorrect Default Permissions", "Create files/dirs with restrictive modes (0600/0700) and review default ACLs."],
  "CWE-287": ["Improper Authentication", "Use a vetted auth library; enforce auth on every route server-side; verify token signature, issuer, audience and expiry."],
  "CWE-306": ["Missing Authentication for Critical Function", "Require authentication middleware on admin/critical endpoints; deny by default."],
  "CWE-319": ["Cleartext Transmission", "Enforce TLS (HTTPS, HSTS) and refuse plaintext fallbacks."],
  "CWE-327": ["Broken/Risky Crypto", "Use modern primitives (AES-GCM, ChaCha20-Poly1305, SHA-256+, argon2/bcrypt for passwords) from standard libraries."],
  "CWE-352": ["CSRF", "Use SameSite cookies plus CSRF tokens for state-changing requests; check Origin/Referer."],
  "CWE-400": ["Uncontrolled Resource Consumption", "Set limits on request body size, recursion depth, timeouts and rate limits."],
  "CWE-401": ["Memory Leak", "Release resources on all paths; bound caches."],
  "CWE-416": ["Use After Free", "Upgrade the affected native component; avoid manual lifetime management."],
  "CWE-434": ["Unrestricted File Upload", "Allow-list extensions + MIME sniffing, store outside webroot with random names, never execute uploads."],
  "CWE-476": ["NULL Pointer Dereference", "Upgrade the component; add null checks on external data."],
  "CWE-502": ["Deserialization of Untrusted Data", "Never deserialize untrusted data with pickle/yaml.load/Java serialization/node-serialize; use JSON + schema validation (yaml.safe_load)."],
  "CWE-601": ["Open Redirect", "Redirect only to relative paths or an allow-list of hosts."],
  "CWE-611": ["XXE", "Disable DTDs/external entities in XML parsers (e.g. defusedxml, libxml noent=false)."],
  "CWE-639": ["IDOR", "Check object ownership/authorization for every ID received from the client."],
  "CWE-668": ["Exposure of Resource", "Restrict access scope of files/ports/endpoints to what is required."],
  "CWE-770": ["Allocation without Limits", "Bound allocations, payload sizes, and concurrency."],
  "CWE-787": ["Out-of-bounds Write", "Upgrade the affected native component; validate lengths before buffer operations."],
  "CWE-125": ["Out-of-bounds Read", "Upgrade the affected native component; validate lengths/indices."],
  "CWE-190": ["Integer Overflow", "Check arithmetic bounds before allocation/indexing."],
  "CWE-798": ["Hard-coded Credentials", "Move secrets to env vars/secret manager; rotate any committed credentials."],
  "CWE-862": ["Missing Authorization", "Enforce authorization checks server-side on every handler (deny by default)."],
  "CWE-863": ["Incorrect Authorization", "Centralize authorization logic and test role/ownership checks."],
  "CWE-918": ["SSRF", "Allow-list outbound hosts, block private/link-local IP ranges after DNS resolution, disable redirects."],
  "CWE-1321": ["Prototype Pollution", "Reject __proto__/constructor/prototype keys in merges, use Object.create(null)/Map, freeze prototypes; upgrade the library."],
  "CWE-1333": ["ReDoS", "Avoid catastrophic-backtracking regexes on untrusted input; cap input length or use RE2."],
};

export function cweGuidance(ids) {
  return ids
    .filter((id) => CWE_GUIDANCE[id])
    .map((id) => ({ cwe: id, name: CWE_GUIDANCE[id][0], fix: CWE_GUIDANCE[id][1] }));
}

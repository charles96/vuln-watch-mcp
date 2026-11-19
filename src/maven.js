import { readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { cacheGet, cacheSet } from "./cache.js";
import { compareVersions } from "./nvd.js";

/**
 * Lightweight Maven model resolver:
 *  - parent POM inheritance (local relativePath first, then Maven Central)
 *  - property interpolation (${...}, project.*, parent.*)
 *  - dependencyManagement incl. imported BOMs (scope=import)
 *  - approximate transitive resolution (compile/runtime, non-optional, exclusions)
 * POMs are immutable, so they are cached for 30 days.
 */

const REPOS = [
  process.env.MAVEN_REPO_URL || "https://repo1.maven.org/maven2",
  "https://dl.google.com/dl/android/maven2", // androidx, com.google.android.*, Compose BOM
];
const GOOGLE_GROUP = /^(androidx\.|com\.google\.android\.|com\.android\.|com\.google\.firebase|com\.google\.gms|com\.google\.mlkit|com\.google\.ar)/;
const POM_TTL = 30 * 86400_000;

const ga = (g, a) => `${g}:${a}`;

async function fetchPom(g, a, v) {
  const key = `pom:${g}:${a}:${v}`;
  const hit = await cacheGet(key, POM_TTL);
  if (hit !== undefined) return hit;
  let xml = null;
  const repos = GOOGLE_GROUP.test(g) ? [REPOS[1], REPOS[0]] : REPOS;
  for (const repo of repos) {
    try {
      const res = await fetch(`${repo}/${g.replace(/\./g, "/")}/${a}/${v}/${a}-${v}.pom`, {
        headers: { "User-Agent": "vuln-watch-mcp" },
        signal: AbortSignal.timeout(20_000),
      });
      if (res.ok) {
        xml = await res.text();
        break;
      }
      if (res.status !== 404) return null; // transient: don't cache
    } catch {
      return null;
    }
  }
  await cacheSet(key, xml);
  return xml;
}

function tag(xml, name) {
  return xml?.match(new RegExp(`<${name}>\\s*([^<]*?)\\s*</${name}>`))?.[1];
}

function block(xml, name) {
  return xml?.match(new RegExp(`<${name}>([\\s\\S]*?)</${name}>`))?.[1] || "";
}

function parseDeps(section) {
  return [...section.matchAll(/<dependency>([\s\S]*?)<\/dependency>/g)].map((m) => {
    const body = m[1];
    const exclusions = [...block(body, "exclusions").matchAll(/<exclusion>([\s\S]*?)<\/exclusion>/g)].map((e) => ga(tag(e[1], "groupId"), tag(e[1], "artifactId")));
    const noExcl = body.replace(/<exclusions>[\s\S]*?<\/exclusions>/, "");
    return {
      g: tag(noExcl, "groupId"),
      a: tag(noExcl, "artifactId"),
      v: tag(noExcl, "version"),
      scope: tag(noExcl, "scope") || null,
      type: tag(noExcl, "type") || "jar",
      optional: tag(noExcl, "optional") === "true",
      exclusions,
    };
  });
}

/** Parse the raw (non-effective) model of a POM document. */
export function parsePomXml(xmlRaw) {
  const xml = xmlRaw.replace(/<!--[\s\S]*?-->/g, "");
  const parentXml = block(xml, "parent");
  // strip sections whose nested <version>/<dependency> would confuse top-level lookups
  const top = xml
    .replace(/<parent>[\s\S]*?<\/parent>/, "")
    .replace(/<dependencyManagement>[\s\S]*?<\/dependencyManagement>/, "")
    .replace(/<dependencies>[\s\S]*?<\/dependencies>/g, "")
    .replace(/<build>[\s\S]*?<\/build>/, "")
    .replace(/<profiles>[\s\S]*?<\/profiles>/, "")
    .replace(/<reporting>[\s\S]*?<\/reporting>/, "");
  const properties = {};
  for (const m of block(top, "properties").matchAll(/<([\w.\-]+)>([^<]*)<\/\1>/g)) properties[m[1]] = m[2].trim();
  const noMgmt = xml.replace(/<dependencyManagement>[\s\S]*?<\/dependencyManagement>/, "").replace(/<build>[\s\S]*?<\/build>/, "").replace(/<profiles>[\s\S]*?<\/profiles>/, "");
  return {
    parent: parentXml
      ? { g: tag(parentXml, "groupId"), a: tag(parentXml, "artifactId"), v: tag(parentXml, "version"), relativePath: tag(parentXml, "relativePath") }
      : null,
    g: tag(top, "groupId"),
    a: tag(top, "artifactId"),
    v: tag(top, "version"),
    packaging: tag(top, "packaging") || "jar",
    modules: [...block(top, "modules").matchAll(/<module>([^<]+)<\/module>/g)].map((m) => m[1].trim()),
    properties,
    depMgmt: parseDeps(block(block(xml, "dependencyManagement"), "dependencies")),
    deps: parseDeps(block(noMgmt, "dependencies")),
  };
}

function interpolate(value, props, depth = 0) {
  if (!value || !value.includes("${") || depth > 10) return value;
  const out = value.replace(/\$\{([^}]+)\}/g, (m, k) => (props[k] !== undefined ? props[k] : m));
  return out === value ? out : interpolate(out, props, depth + 1);
}

const effCache = new Map();

/**
 * Build an effective model. `source` is either {file} (local pom.xml) or {g,a,v} (remote).
 * Returns { g, a, v, properties, managed: Map<ga, {v, scope, exclusions}>, deps: [...] } or null.
 */
export async function effectiveModel(source, stack = []) {
  const id = source.file ? `file:${source.file}` : `${source.g}:${source.a}:${source.v}`;
  if (effCache.has(id)) return effCache.get(id);
  if (stack.includes(id) || stack.length > 12) return null;
  const p = (async () => {
    let xml;
    if (source.file) xml = await readFile(source.file, "utf8").catch(() => null);
    else xml = await fetchPom(source.g, source.a, source.v);
    if (!xml) return null;
    const raw = parsePomXml(xml);

    // parent: local relativePath (default ../pom.xml) if it matches, else Central
    let parent = null;
    if (raw.parent?.g && raw.parent?.a) {
      if (source.file) {
        const rel = raw.parent.relativePath === "" ? null : raw.parent.relativePath || "../pom.xml";
        if (rel) {
          let pf = resolve(dirname(source.file), rel);
          if (!pf.endsWith(".xml")) pf = join(pf, "pom.xml");
          const pxml = await readFile(pf, "utf8").catch(() => null);
          if (pxml) {
            const pr = parsePomXml(pxml);
            if (pr.a === raw.parent.a && (pr.g || pr.parent?.g) === raw.parent.g) parent = await effectiveModel({ file: pf }, [...stack, id]);
          }
        }
      }
      if (!parent && raw.parent.v) parent = await effectiveModel({ g: raw.parent.g, a: raw.parent.a, v: raw.parent.v }, [...stack, id]);
    }

    const g = raw.g || raw.parent?.g;
    const v = raw.v || raw.parent?.v;
    const props = { ...(parent?.properties || {}), ...raw.properties };
    Object.assign(props, {
      "project.groupId": g, "pom.groupId": g, groupId: g,
      "project.artifactId": raw.a, "pom.artifactId": raw.a,
      "project.version": v, "pom.version": v, version: v,
      "project.parent.version": raw.parent?.v, "parent.version": raw.parent?.v,
      "project.parent.groupId": raw.parent?.g,
    });
    const I = (x) => interpolate(x, props);

    // dependencyManagement: own entries first, then imported BOMs, then parent's
    const managed = new Map();
    for (const d of raw.depMgmt) {
      const dg = I(d.g), da = I(d.a), dv = I(d.v);
      if (d.scope === "import" && d.type === "pom") {
        if (dv && !dv.includes("${")) {
          const bom = await effectiveModel({ g: dg, a: da, v: dv }, [...stack, id]);
          for (const [k, mv] of bom?.managed || []) if (!managed.has(k)) managed.set(k, mv);
        }
        continue;
      }
      if (!managed.has(ga(dg, da))) managed.set(ga(dg, da), { v: dv, scope: d.scope, exclusions: d.exclusions });
    }
    for (const [k, mv] of parent?.managed || []) if (!managed.has(k)) managed.set(k, mv);

    // dependencies: own + inherited from parent
    const deps = [];
    const seen = new Set();
    for (const d of [...raw.deps.map((d) => ({ ...d, g: I(d.g), a: I(d.a), v: I(d.v) })), ...(parent?.deps || [])]) {
      const k = ga(d.g, d.a);
      if (seen.has(k)) continue;
      seen.add(k);
      const m = managed.get(k);
      deps.push({ ...d, v: d.v || m?.v, scope: d.scope || m?.scope || "compile", exclusions: [...d.exclusions, ...(m?.exclusions || [])] });
    }
    return { g, a: raw.a, v, packaging: raw.packaging, modules: raw.modules, properties: props, managed, deps };
  })();
  effCache.set(id, p);
  return p;
}

const RUNTIME_SCOPES = new Set(["compile", "runtime", null, undefined]);
const excluded = (exclusions, g, a) => exclusions.some((e) => e === ga(g, a) || e === `${g}:*` || e === "*:*");

/**
 * Resolve the dependency graph from a list of direct deps.
 * strategy: "nearest" (Maven) or "highest" (Gradle).
 * rootManaged: Map of versions that override transitive versions (root dependencyManagement / BOMs).
 * Returns [{ g, a, v, depth, scope, direct }]
 */
export async function resolveGraph(directDeps, { rootManaged = new Map(), strategy = "nearest", maxArtifacts = 600, maxDepth = 8, internal = () => false } = {}) {
  const chosen = new Map();
  let frontier = directDeps.filter((d) => d.g && d.a && d.v).map((d) => ({ ...d, depth: 0, exclusions: d.exclusions || [] }));
  while (frontier.length && chosen.size < maxArtifacts) {
    const next = [];
    // record this level
    const toExpand = [];
    for (const d of frontier) {
      const k = ga(d.g, d.a);
      const prev = chosen.get(k);
      if (prev) {
        if (strategy === "highest" && compareVersions(d.v, prev.v) > 0) {
          prev.v = d.v;
          toExpand.push(d);
        }
        continue;
      }
      chosen.set(k, { g: d.g, a: d.a, v: d.v, depth: d.depth, scope: d.scope || "compile", direct: d.depth === 0, dev: d.dev });
      toExpand.push(d);
    }
    if (frontier[0]?.depth >= maxDepth) break;
    // expand children in parallel (bounded)
    const results = [];
    for (let i = 0; i < toExpand.length; i += 8) {
      results.push(...(await Promise.all(toExpand.slice(i, i + 8).map(async (d) => {
        if (internal(d.g, d.a, d.v)) return [];
        const m = await effectiveModel({ g: d.g, a: d.a, v: d.v });
        if (!m) return [];
        return m.deps
          .filter((c) => c.g && c.a && RUNTIME_SCOPES.has(c.scope) && !c.optional && c.type !== "pom" && !excluded(d.exclusions, c.g, c.a))
          .map((c) => {
            const override = rootManaged.get(ga(c.g, c.a))?.v;
            const v = override || c.v;
            return v && !v.includes("${") && !/^[[(]/.test(v)
              ? { g: c.g, a: c.a, v, scope: c.scope === "runtime" ? "runtime" : d.scope === "runtime" ? "runtime" : "compile", depth: d.depth + 1, exclusions: [...d.exclusions, ...c.exclusions], dev: d.dev }
              : null;
          })
          .filter(Boolean);
      }))));
    }
    for (const r of results) next.push(...r);
    frontier = next;
  }
  return [...chosen.values()];
}

/** Managed versions from a BOM coordinate (used for Gradle platform()/Spring Boot plugin). */
export async function bomManaged(g, a, v) {
  const m = await effectiveModel({ g, a, v });
  return m?.managed || new Map();
}

/**
 * Resolve a local pom.xml into a flat dependency list (direct + transitive).
 */
export async function resolveLocalPom(file, { includeDev = false, transitive = true, modules = new Set() } = {}) {
  const model = await effectiveModel({ file });
  if (!model) throw new Error("cannot parse pom.xml");
  const internal = (g, a, v) => modules.has(ga(g, a)) || (g === model.g && v === model.v);
  const unresolved = [];
  const direct = [];
  for (const d of model.deps) {
    if (!d.g || !d.a || d.type === "pom") continue;
    if (internal(d.g, d.a, d.v)) continue;
    const dev = d.scope === "test";
    if (dev && !includeDev) continue;
    if (d.scope === "system") continue;
    if (!d.v || d.v.includes("${")) {
      unresolved.push(ga(d.g, d.a));
      continue;
    }
    direct.push({ ...d, dev });
  }
  const resolved = transitive
    ? await resolveGraph(direct, { rootManaged: model.managed, strategy: "nearest", internal })
    : direct.map((d) => ({ g: d.g, a: d.a, v: d.v, depth: 0, direct: true, dev: d.dev, scope: d.scope }));
  return { model, deps: resolved, unresolved };
}

import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { parse as parseToml } from "smol-toml";
import { bomManaged, resolveGraph } from "./maven.js";

/**
 * Gradle build script resolver (Groovy + Kotlin DSL), without running Gradle:
 *  - string / map / Kotlin notation, $variables from ext/def/val and gradle.properties
 *  - version catalogs (gradle/libs.versions.toml): libraries, bundles, plugins
 *  - platform()/enforcedPlatform()/mavenBom BOMs and the Spring Boot plugin BOM
 *  - approximate transitive resolution via Maven Central POMs (highest version wins)
 */

const TEST_CONF = /^(test|androidTest|testFixtures|kapt|annotationProcessor|ksp|detekt|lint)/i;
const SKIP_CONF = /^(classpath|id|plugin|kotlin|alias|apply)$/i;

async function readIfExists(f) {
  return readFile(f, "utf8").catch(() => null);
}

/**
 * Directories from `dir` upwards: past the scan root up to the Gradle build root
 * (the directory containing settings.gradle[.kts]), max 6 levels.
 */
async function upwardDirs(dir) {
  const out = [];
  let d = dir;
  for (let i = 0; i < 7; i++) {
    out.push(d);
    if ((await readIfExists(join(d, "settings.gradle"))) != null || (await readIfExists(join(d, "settings.gradle.kts"))) != null) break;
    const up = dirname(d);
    if (up === d) break;
    d = up;
  }
  return out;
}

/** Nearest file named `name` walking up to the Gradle build root. */
async function findUp(dir, _root, name) {
  for (const d of await upwardDirs(dir)) {
    const t = await readIfExists(join(d, name));
    if (t != null) return { file: join(d, name), text: t };
  }
  return null;
}

function parseProperties(text) {
  const out = {};
  for (const l of (text || "").split(/\r?\n/)) {
    const m = l.match(/^\s*([\w.\-]+)\s*[=:]\s*(.*?)\s*$/);
    if (m && !l.trim().startsWith("#")) out[m[1]] = m[2];
  }
  return out;
}

const accessor = (alias) => alias.replace(/[-_]/g, ".").toLowerCase();

/** Parse gradle/libs.versions.toml into { libs: Map<accessor, {g,a,v}>, bundles: Map, plugins: Map } */
export function parseVersionCatalog(text) {
  const t = parseToml(text);
  const versions = t.versions || {};
  const ver = (x) => {
    if (x == null) return null;
    if (typeof x === "string") return x;
    if (x.ref) return ver(versions[x.ref]);
    return x.strictly || x.require || x.prefer || null;
  };
  const libs = new Map();
  for (const [alias, def] of Object.entries(t.libraries || {})) {
    let g, a, v;
    if (typeof def === "string") [g, a, v] = def.split(":");
    else {
      if (def.module) [g, a] = def.module.split(":");
      else [g, a] = [def.group, def.name];
      v = def.version !== undefined ? ver(def.version) : def["version.ref"] ? ver({ ref: def["version.ref"] }) : null;
      if (def.version?.ref) v = ver({ ref: def.version.ref });
    }
    if (g && a) libs.set(accessor(alias), { g, a, v: v || null });
  }
  const bundles = new Map(Object.entries(t.bundles || {}).map(([k, list]) => [accessor(k), list.map(accessor)]));
  const plugins = new Map();
  for (const [alias, def] of Object.entries(t.plugins || {})) {
    const id = typeof def === "string" ? def.split(":")[0] : def.id;
    const v = typeof def === "string" ? def.split(":")[1] : def.version !== undefined ? ver(def.version) : def["version.ref"] ? ver({ ref: def["version.ref"] }) : null;
    plugins.set(accessor(alias), { id, v: v || (def.version?.ref ? ver({ ref: def.version.ref }) : null) });
  }
  return { libs, bundles, plugins };
}

/**
 * Parse one build.gradle(.kts). Returns { deps:[{g,a,v,dev}], boms:[{g,a,v}], unresolved:[] }.
 */
export async function parseGradleBuild(file, root, { includeDev = false, transitive = true } = {}) {
  let text = (await readFile(file, "utf8")).replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:])\/\/.*$/gm, "$1");
  const dir = dirname(file);

  // variables: gradle.properties (nearest first, then upwards), ext {}, def/val/var
  const vars = {};
  const propFiles = [];
  for (const d of await upwardDirs(dir)) {
    const t = await readIfExists(join(d, "gradle.properties"));
    if (t) propFiles.push(t);
  }
  for (const t of propFiles.reverse()) Object.assign(vars, parseProperties(t));
  for (const m of text.matchAll(/(?:^|\s)(?:def|val|var|ext\.|extra\[")?\s*([A-Za-z_][\w]*)"?\]?\s*=\s*["']([^"'$]+)["']/gm)) vars[m[1]] = m[2];
  for (const m of text.matchAll(/set\(\s*["']([\w.]+)["']\s*,\s*["']([^"']+)["']\s*\)/g)) vars[m[1]] = m[2];
  const sub = (s) => s?.replace(/\$\{?([\w.]+)\}?/g, (mm, k) => (vars[k] !== undefined ? vars[k] : mm));

  // version catalog (gradle/libs.versions.toml up the tree)
  const cat = await findUp(dir, root, join("gradle", "libs.versions.toml"));
  let catalog = null;
  if (cat) {
    try {
      catalog = parseVersionCatalog(cat.text);
    } catch {
      catalog = null;
    }
  }

  const deps = [];
  const boms = [];
  const unresolved = [];
  const add = (g, a, v, conf) => {
    const dev = TEST_CONF.test(conf || "");
    if (dev && !includeDev) return;
    deps.push({ g, a, v: v ? sub(v) : null, dev, conf });
  };

  // plugins: Spring Boot BOM
  const bootPlugin =
    text.match(/id\s*\(?\s*["']org\.springframework\.boot["']\s*\)?\s*version\s*["']([^"']+)["']/)?.[1] ||
    text.match(/["']org\.springframework\.boot:spring-boot-gradle-plugin:([^"']+)["']/)?.[1];
  if (bootPlugin) boms.push({ g: "org.springframework.boot", a: "spring-boot-dependencies", v: sub(bootPlugin) });
  if (catalog) {
    for (const m of text.matchAll(/alias\s*\(\s*libs\.plugins\.([\w.]+)\s*\)/g)) {
      const p = catalog.plugins.get(m[1].toLowerCase());
      if (p?.id === "org.springframework.boot" && p.v) boms.push({ g: "org.springframework.boot", a: "spring-boot-dependencies", v: p.v });
    }
  }
  // explicit BOMs
  for (const m of text.matchAll(/(?:platform|enforcedPlatform|mavenBom)\s*\(?\s*["']([\w.\-]+):([\w.\-]+):([^"']+)["']/g)) boms.push({ g: m[1], a: m[2], v: sub(m[3]) });

  // string notation: conf 'g:a:v' / conf("g:a:v") / conf "g:a" (versionless)
  for (const m of text.matchAll(/\b(\w+)\s*\(?\s*["']([\w.\-]+):([\w.\-]+)(?::([^"':@]+))?(?::[\w\-]+)?(?:@\w+)?["']/g)) {
    const [, conf, g, a, v] = m;
    if (SKIP_CONF.test(conf) || /^(platform|enforcedPlatform|mavenBom)$/.test(conf)) continue;
    if (/^(maven|url|uri|from|into|include|exclude|group|module|substitute|using)$/i.test(conf)) continue;
    add(g, a, v, conf);
  }
  // map notation: conf group: 'g', name: 'a', version: 'v'
  for (const m of text.matchAll(/\b(\w+)\s*\(?\s*group\s*[:=]\s*["']([^"']+)["']\s*,\s*name\s*[:=]\s*["']([^"']+)["'](?:\s*,\s*version\s*[:=]\s*["']([^"']+)["'])?/g)) {
    add(m[2], m[3], m[4], m[1]);
  }
  // version catalog accessors: conf(libs.x.y) / conf libs.x.y / libs.bundles.z
  if (catalog) {
    for (const m of text.matchAll(/\b(\w+)\s*\(?\s*(?:platform\s*\(\s*)?libs\.([\w.]+)/g)) {
      const [, conf, path] = m;
      if (SKIP_CONF.test(conf) || path.startsWith("plugins.") || path.startsWith("versions.")) continue;
      const key = path.toLowerCase().replace(/\.get$/, "");
      const isPlatform = /platform\s*\(\s*libs\./.test(m[0]);
      const list = key.startsWith("bundles.") ? catalog.bundles.get(key.slice(8)) || [] : [key];
      for (const k of list) {
        const lib = catalog.libs.get(k);
        if (!lib) continue;
        if (isPlatform && lib.v) boms.push({ g: lib.g, a: lib.a, v: lib.v });
        else add(lib.g, lib.a, lib.v, conf);
      }
    }
  }

  // resolve versionless deps through BOMs
  const managed = new Map();
  for (const b of boms) {
    if (!b.v || b.v.includes("$")) continue;
    for (const [k, mv] of await bomManaged(b.g, b.a, b.v)) if (!managed.has(k)) managed.set(k, mv);
  }
  const direct = [];
  const seen = new Set();
  for (const dep of deps) {
    const k = `${dep.g}:${dep.a}`;
    if (seen.has(k)) continue;
    seen.add(k);
    const v = dep.v && !dep.v.includes("$") ? dep.v.replace(/[!]{2}.*$/, "").replace(/^\[|\]$/g, "") : managed.get(k)?.v;
    if (!v || /[\[(,+]/.test(v) || v.includes("$")) {
      unresolved.push(k);
      continue;
    }
    direct.push({ g: dep.g, a: dep.a, v, dev: dep.dev, scope: dep.dev ? "test" : "compile", exclusions: [] });
  }
  const resolved = transitive
    ? await resolveGraph(direct, { rootManaged: managed, strategy: "highest" })
    : direct.map((x) => ({ ...x, depth: 0, direct: true }));
  return {
    deps: resolved.map((r) => ({ name: `${r.g}:${r.a}`, version: r.v, ecosystem: "maven", dev: Boolean(r.dev), direct: r.depth === 0, versionSource: r.depth === 0 ? "manifest" : "resolved" })),
    boms,
    unresolved,
    catalog: cat?.file || null,
  };
}

import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";

const CACHE_DIR =
  process.env.VULN_WATCH_CACHE_DIR || join(homedir(), ".cache", "vuln-watch-mcp");
const memory = new Map();

function keyFile(key) {
  return join(CACHE_DIR, createHash("sha256").update(key).digest("hex").slice(0, 32) + ".json");
}

/** Returns cached value if younger than ttlMs, else undefined. Memory first, then disk. */
export async function cacheGet(key, ttlMs) {
  const now = Date.now();
  const m = memory.get(key);
  if (m && now - m.t < ttlMs) return m.v;
  try {
    const raw = JSON.parse(await readFile(keyFile(key), "utf8"));
    if (now - raw.t < ttlMs) {
      memory.set(key, raw);
      return raw.v;
    }
  } catch {
    /* miss */
  }
  return undefined;
}

/** Returns a stale cached value regardless of age (fallback when network fails). */
export async function cacheGetStale(key) {
  const m = memory.get(key);
  if (m) return m.v;
  try {
    return JSON.parse(await readFile(keyFile(key), "utf8")).v;
  } catch {
    return undefined;
  }
}

export async function cacheSet(key, value) {
  const entry = { t: Date.now(), v: value };
  memory.set(key, entry);
  try {
    await mkdir(CACHE_DIR, { recursive: true });
    await writeFile(keyFile(key), JSON.stringify(entry));
  } catch {
    /* disk cache is best-effort */
  }
}

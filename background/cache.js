const memory = new Map();
const TTL_MS = 30 * 60 * 1000;

/** Ответы Safe Browsing — чтобы не ходить на backend на каждый скан одной страницы */
const threatMemory = new Map();
const THREAT_TTL_MS = 10 * 60 * 1000;

export function getCachedThreat(url) {
  const hit = threatMemory.get(url);
  if (!hit) return null;
  if (Date.now() - hit.ts > THREAT_TTL_MS) {
    threatMemory.delete(url);
    return null;
  }
  return hit.value;
}

export function setCachedThreat(url, value) {
  if (!value) return;
  if (threatMemory.size > 300) {
    const oldest = [...threatMemory.entries()].sort((a, b) => a[1].ts - b[1].ts).slice(0, 100);
    oldest.forEach(([k]) => threatMemory.delete(k));
  }
  threatMemory.set(url, { ts: Date.now(), value });
}

function keyOf(hostname, urlPath, contentHash = "") {
  return `${hostname}|${urlPath || "/"}|${contentHash || "na"}`;
}

export function hashContent(payload = {}) {
  const raw = [
    payload.hasSensitiveForm ? "1" : "0",
    payload.hasRelevantForm ? "r" : "-",
    payload.modalDetected ? "m" : "-",
    payload.formCrossOrigin ? "x" : "-",
    JSON.stringify(payload.fields || {}),
    (payload.snippets || []).slice(0, 20).join("|")
  ].join("::");
  let h = 0;
  for (let i = 0; i < raw.length; i++) {
    h = ((h << 5) - h + raw.charCodeAt(i)) | 0;
  }
  return String(h);
}

export async function getCachedVerdict(hostname, pathname = "/", contentHash = "") {
  const k = keyOf(hostname, pathname, contentHash);
  const mem = memory.get(k);
  if (mem && Date.now() - mem.ts < TTL_MS) return mem.value;

  try {
    const data = await chrome.storage.session.get("pg_cache");
    const bag = data.pg_cache || {};
    const hit = bag[k];
    if (hit && Date.now() - hit.ts < TTL_MS) {
      memory.set(k, hit);
      return hit.value;
    }
  } catch (_) {}
  return null;
}

export async function setCachedVerdict(hostname, pathname, value, contentHash = "") {
  const k = keyOf(hostname, pathname, contentHash);
  const entry = { ts: Date.now(), value };
  memory.set(k, entry);
  try {
    const data = await chrome.storage.session.get("pg_cache");
    const bag = data.pg_cache || {};
    bag[k] = entry;
    const keys = Object.keys(bag);
    if (keys.length > 200) {
      keys
        .sort((a, b) => (bag[a].ts || 0) - (bag[b].ts || 0))
        .slice(0, keys.length - 200)
        .forEach((x) => delete bag[x]);
    }
    await chrome.storage.session.set({ pg_cache: bag });
  } catch (_) {}
}

/** Сброс кэша для хоста (или всего) — нужно при RESCAN / смене модалки */
export async function clearVerdictCache(hostname = null) {
  if (!hostname) {
    memory.clear();
    threatMemory.clear();
    try {
      await chrome.storage.session.remove("pg_cache");
    } catch (_) {}
    return;
  }
  const host = hostname.toLowerCase();
  const matches = (k) =>
    k.startsWith(host + "|") ||
    k.startsWith(host + "/") || // local-file/modal-phish.html|...
    k.split("|")[0] === host ||
    k.split("|")[0].startsWith(host + "/");

  for (const k of [...memory.keys()]) {
    if (matches(k)) memory.delete(k);
  }
  try {
    const data = await chrome.storage.session.get("pg_cache");
    const bag = data.pg_cache || {};
    for (const k of Object.keys(bag)) {
      if (matches(k)) delete bag[k];
    }
    await chrome.storage.session.set({ pg_cache: bag });
  } catch (_) {}
}

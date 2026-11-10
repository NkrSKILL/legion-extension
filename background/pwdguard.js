/**
 * Zero-Knowledge Password Reuse Guard (Legion).
 *
 * Защищает от главной угрозы фишинга: ввода реального пароля от доверенного сайта
 * (Госуслуги, ВК, банк, почта) на стороннем сайте-однодневке.
 *
 * Приватность:
 * 1. Content script никогда не передаёт сам пароль — только необратимый SHA-256 пре-хэш.
 * 2. Service worker дополнительно солит его уникальной 256-битной солью устройства
 *    через Web Crypto API: SHA-256(deviceSalt + "::" + clientDigest).
 * 3. В локальном хранилище лежит только { saltedHash: "gosuslugi.ru" }.
 */

import { normalizeDomain } from "./settings.js";

const STORAGE_KEY = "pg_zk_pwd_guard";
let memBag = { salt: null, hashes: {} };

function getLocalStore() {
  if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
    return chrome.storage.local;
  }
  return null;
}

function randomHex(bytes = 32) {
  const arr = new Uint8Array(bytes);
  if (typeof crypto !== "undefined" && crypto.getRandomValues) {
    crypto.getRandomValues(arr);
  } else {
    for (let i = 0; i < bytes; i++) arr[i] = Math.floor(Math.random() * 256);
  }
  return Array.from(arr, (b) => b.toString(16).padStart(2, "0")).join("");
}

async function sha256Hex(str) {
  const data = new TextEncoder().encode(str);
  const buf = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, "0")).join("");
}

async function loadBag() {
  const store = getLocalStore();
  if (store) {
    try {
      const res = await store.get(STORAGE_KEY);
      if (res && res[STORAGE_KEY] && res[STORAGE_KEY].salt) {
        memBag = res[STORAGE_KEY];
        return memBag;
      }
    } catch (_) {}
  }
  if (!memBag.salt) {
    memBag = { salt: randomHex(32), hashes: {} };
    if (store) {
      try {
        await store.set({ [STORAGE_KEY]: memBag });
      } catch (_) {}
    }
  }
  return memBag;
}

async function saveBag(bag) {
  memBag = bag;
  const store = getLocalStore();
  if (store) {
    try {
      await store.set({ [STORAGE_KEY]: bag });
    } catch (_) {}
  }
}

function isSameOrSubdomain(host, trustedDomain) {
  const h = (host || "").toLowerCase();
  const d = (trustedDomain || "").toLowerCase();
  if (!h || !d) return false;
  return h === d || h.endsWith("." + d) || d.endsWith("." + h);
}

/**
 * Сохранить необратимый отпечаток пароля с доверенного сайта из белого списка.
 */
export async function recordTrustedPasswordHash(clientDigest, hostname) {
  if (!clientDigest || typeof clientDigest !== "string" || clientDigest.length < 32) {
    return { ok: false };
  }
  const domain = normalizeDomain(hostname);
  if (!domain) return { ok: false };

  const bag = await loadBag();
  const salted = await sha256Hex(`${bag.salt}::zk-v1::${clientDigest}`);
  bag.hashes = bag.hashes || {};

  // Ограничиваем размер таблицы 200 записями
  const keys = Object.keys(bag.hashes);
  if (keys.length >= 200 && !bag.hashes[salted]) {
    delete bag.hashes[keys[0]];
  }

  bag.hashes[salted] = {
    domain,
    ts: Date.now()
  };
  await saveBag(bag);
  return { ok: true, domain, count: Object.keys(bag.hashes).length };
}

/**
 * Проверить, не вводит ли пользователь свой пароль от доверенного сайта на чужом домене.
 */
export async function checkPasswordReuse(clientDigest, currentHostname) {
  if (!clientDigest || typeof clientDigest !== "string" || clientDigest.length < 32) {
    return { reused: false };
  }
  const bag = await loadBag();
  if (!bag.hashes || !Object.keys(bag.hashes).length) {
    return { reused: false };
  }

  const salted = await sha256Hex(`${bag.salt}::zk-v1::${clientDigest}`);
  const hit = bag.hashes[salted];
  if (!hit || !hit.domain) return { reused: false };

  if (isSameOrSubdomain(currentHostname, hit.domain)) {
    return { reused: false };
  }

  return {
    reused: true,
    trustedDomain: hit.domain,
    reason: `Zero-Knowledge защита: вы вводите свой пароль от «${hit.domain}» на стороннем сайте ${currentHostname}`
  };
}

export async function getPwdGuardStats() {
  const bag = await loadBag();
  const entries = Object.values(bag.hashes || {});
  const domains = [...new Set(entries.map((e) => e.domain).filter(Boolean))];
  return {
    count: entries.length,
    domains
  };
}

export async function clearPwdGuardHashes() {
  const bag = await loadBag();
  bag.hashes = {};
  await saveBag(bag);
  return { count: 0, domains: [] };
}

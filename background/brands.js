/**
 * Детект имитации брендов, IDN-омографов (Punycode / confusables)
 * и подгрузки чужих фирменных ресурсов (Asset / Favicon Spoofing).
 */

let brandsCache = null;
let aliasRegexCache = null;

/** Официальные CDN и вспомогательные домены брендов для проверки кражи иконок/логотипов */
const BRAND_ASSET_DOMAINS = {
  "Госуслуги": ["gosuslugi.ru", "gu-st.ru", "esia.gosuslugi.ru"],
  "Сбер": ["sberbank.ru", "sber.ru", "sberbank.com"],
  "Т-Банк": ["tbank.ru", "tinkoff.ru", "cdn-tinkoff.ru"],
  "ВТБ": ["vtb.ru"],
  "Альфа-Банк": ["alfabank.ru"],
  "Яндекс": ["yandex.ru", "ya.ru", "yastatic.net", "yandex.net"],
  "VK": ["vk.com", "vk.ru", "userapi.com", "vkuserphoto.ru"],
  "Telegram": ["telegram.org", "t.me", "telesco.pe"],
  "Steam": ["steampowered.com", "steamcommunity.com", "steamstatic.com"],
  "Wildberries": ["wildberries.ru", "wb.ru", "wbbasket.ru"],
  "Ozon": ["ozon.ru", "ozone.ru"]
};

/** Таблица визуально похожих символов (Unicode Confusables → латинский скелет) */
const CONFUSABLE_MAP = {
  "а": "a", "ɑ": "a", "α": "a", "ạ": "a", "ă": "a", "à": "a", "á": "a", "â": "a", "ã": "a", "ä": "a",
  "б": "b", "в": "b", "ß": "b", "β": "b",
  "с": "c", "ϲ": "c", "ç": "c",
  "е": "e", "є": "e", "ε": "e", "ё": "e", "è": "e", "é": "e", "ê": "e",
  "і": "i", "ї": "i", "ɪ": "i", "ι": "i", "1": "i", "l": "i", "|": "i",
  "ј": "j",
  "к": "k", "κ": "k",
  "м": "m",
  "н": "h", "η": "h",
  "о": "o", "ο": "o", "0": "o", "ö": "o", "ó": "o", "ò": "o",
  "р": "p", "ρ": "p",
  "ѕ": "s", "5": "s",
  "т": "t", "τ": "t",
  "у": "y", "ү": "y", "ý": "y",
  "х": "x", "χ": "x",
  "г": "r",
  "п": "n",
  "и": "u", "υ": "u"
};

/** Удаление невидимых zero-width и форматирующих символов, которыми разбивают слова */
export function stripZeroWidth(str) {
  return String(str || "").replace(/[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF\u00AD]/g, "");
}

/** Проверка, были ли в тексте невидимые символы маскировки */
export function hasZeroWidthObfuscation(str) {
  const raw = String(str || "");
  const matches = raw.match(/[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF]/g);
  return !!matches && matches.length >= 2;
}

/** Декодирование одной Punycode-метки (RFC 3492, xn--...) в Unicode */
export function decodePunycodeLabel(input) {
  const label = String(input || "").toLowerCase();
  if (!label.startsWith("xn--")) return label;
  const encoded = label.slice(4);
  if (!encoded) return label;

  const base = 36;
  const tMin = 1;
  const tMax = 26;
  const skew = 38;
  const damp = 700;
  let bias = 72;
  let n = 128;
  let i = 0;

  const output = [];
  const delim = encoded.lastIndexOf("-");
  let pos = 0;
  if (delim > 0) {
    for (let j = 0; j < delim; j++) {
      output.push(encoded.charCodeAt(j));
    }
    pos = delim + 1;
  } else if (delim === 0) {
    pos = 1;
  }

  const adapt = (delta, numPoints, firstTime) => {
    let d = firstTime ? Math.floor(delta / damp) : delta >> 1;
    d += Math.floor(d / numPoints);
    let k = 0;
    while (d > ((base - tMin) * tMax) >> 1) {
      d = Math.floor(d / (base - tMin));
      k += base;
    }
    return Math.floor(k + ((base - tMin + 1) * d) / (d + skew));
  };

  const decodeDigit = (cp) => {
    if (cp - 48 < 10) return cp - 22;
    if (cp - 65 < 26) return cp - 65;
    if (cp - 97 < 26) return cp - 97;
    return base;
  };

  try {
    while (pos < encoded.length) {
      const oldi = i;
      let w = 1;
      for (let k = base; ; k += base) {
        if (pos >= encoded.length) return label;
        const digit = decodeDigit(encoded.charCodeAt(pos++));
        if (digit >= base) return label;
        i += digit * w;
        const t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
        if (digit < t) break;
        w *= base - t;
      }
      const outLen = output.length + 1;
      bias = adapt(i - oldi, outLen, oldi === 0);
      n += Math.floor(i / outLen);
      i %= outLen;
      output.splice(i, 0, n);
      i++;
    }
    return String.fromCodePoint(...output);
  } catch {
    return label;
  }
}

export function decodeIdnHost(hostname) {
  return String(hostname || "")
    .toLowerCase()
    .split(".")
    .map(decodePunycodeLabel)
    .join(".");
}

/** Перевод строки в латинский скелет для сравнения омографов */
export function toLatinSkeleton(str) {
  const s = stripZeroWidth(str).toLowerCase();
  let out = "";
  for (const ch of s) {
    out += CONFUSABLE_MAP[ch] || ch;
  }
  return out;
}

export async function loadBrands() {
  if (brandsCache) return brandsCache;
  const res = await fetch(chrome.runtime.getURL("data/brands.json"));
  brandsCache = await res.json();
  return brandsCache;
}

function escapeRegex(str) {
  return String(str).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Алиас как отдельное слово (без \p{L} — надёжнее в service worker) */
function aliasRegex(alias) {
  const a = escapeRegex(alias.toLowerCase());
  return new RegExp(`(?:^|[^a-zA-Zа-яА-ЯёЁ0-9_])${a}(?=[^a-zA-Zа-яА-ЯёЁ0-9_]|$)`, "i");
}

async function getAliasRegexes() {
  if (aliasRegexCache) return aliasRegexCache;
  const data = await loadBrands();
  aliasRegexCache = (data.brands || []).map((brand) => ({
    brand,
    regexes: (brand.aliases || []).map((a) => ({ alias: String(a), re: aliasRegex(String(a)) }))
  }));
  return aliasRegexCache;
}

function hostAllowedForBrand(hostname, domains) {
  const host = (hostname || "").toLowerCase();
  return (domains || []).some((d) => host === d || host.endsWith("." + d));
}

/**
 * Если текст страницы имитирует бренд, а домен чужой — сильный сигнал фишинга.
 * Предварительно очищаем невидимые zero-width символы.
 */
export async function detectBrandSpoof(hostname, snippets = [], title = "") {
  const rawText = `${title} ${(snippets || []).join(" ")}`;
  const text = stripZeroWidth(rawText).toLowerCase();
  if (!text.trim()) return [];

  const entries = await getAliasRegexes();
  const hits = [];

  for (const { brand, regexes } of entries) {
    const matched = regexes.find(({ re }) => re.test(text));
    if (!matched) continue;
    if (hostAllowedForBrand(hostname, brand.domains)) continue;
    hits.push({
      brand: brand.name,
      alias: matched.alias,
      reason: `Упоминается «${brand.name}», но домен ${hostname} ему не принадлежит`
    });
  }

  return hits;
}

/** Расстояние Дамерау—Левенштейна с ранним выходом */
function editDistance(a, b, maxDist = 2) {
  const s = a.toLowerCase();
  const t = b.toLowerCase();
  if (s === t) return 0;
  if (Math.abs(s.length - t.length) > maxDist) return maxDist + 1;

  let prev2 = null;
  let prev = new Array(t.length + 1);
  for (let j = 0; j <= t.length; j++) prev[j] = j;

  for (let i = 1; i <= s.length; i++) {
    const curr = new Array(t.length + 1);
    curr[0] = i;
    let rowMin = curr[0];
    for (let j = 1; j <= t.length; j++) {
      const cost = s[i - 1] === t[j - 1] ? 0 : 1;
      let v = Math.min(curr[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost);
      if (i > 1 && j > 1 && s[i - 1] === t[j - 2] && s[i - 2] === t[j - 1]) {
        v = Math.min(v, prev2[j - 2] + 1);
      }
      curr[j] = v;
      if (v < rowMin) rowMin = v;
    }
    if (rowMin > maxDist) return maxDist + 1;
    prev2 = prev;
    prev = curr;
  }
  return prev[t.length];
}

function hasDelimitedToken(host, token) {
  let from = 0;
  for (;;) {
    const idx = host.indexOf(token, from);
    if (idx < 0) return false;
    const before = idx === 0 ? "" : host[idx - 1];
    const after = host[idx + token.length] || "";
    const isBoundary = (ch) => ch === "" || /[^a-z0-9]/.test(ch);
    if (isBoundary(before) && isBoundary(after)) return true;
    from = idx + 1;
  }
}

/**
 * Детект IDN-омографов (Punycode xn--... и подмена похожих букв/цифр: sberbаnk с кириллической 'а').
 */
export async function detectHomograph(hostname) {
  const rawHost = (hostname || "").toLowerCase().replace(/^www\./, "");
  if (!rawHost || rawHost.startsWith("local-file") || rawHost === "unknown-host") return [];

  const decodedHost = decodeIdnHost(rawHost);
  const isPunycode = rawHost.includes("xn--") || decodedHost !== rawHost;
  const hostLabel = decodedHost.split(".")[0];
  const skeletonLabel = toLatinSkeleton(hostLabel);

  // Смешение кириллицы и латиницы в одной метке домена
  const hasCyr = /[а-яё]/i.test(hostLabel);
  const hasLat = /[a-z]/i.test(hostLabel);
  const mixedScript = hasCyr && hasLat;

  const data = await loadBrands();
  const hits = [];

  for (const brand of data.brands || []) {
    const domains = brand.domains || [];
    if (hostAllowedForBrand(rawHost, domains)) continue;

    let matched = false;
    for (const d of domains) {
      const base = d.toLowerCase().replace(/^www\./, "");
      const baseName = base.split(".")[0];
      if (baseName.length < 4) continue;
      const baseSkeleton = toLatinSkeleton(baseName);

      // Если скелет совпал с брендом (или расстояние <= 1 при наличии Punycode/цифровой подмены)
      const dist = editDistance(skeletonLabel, baseSkeleton, 1);
      if (
        skeletonLabel === baseSkeleton ||
        (isPunycode && dist <= 1) ||
        (skeletonLabel.includes(baseSkeleton) && isPunycode)
      ) {
        hits.push({
          brand: brand.name,
          decodedHost,
          isHomograph: true,
          reason: isPunycode
            ? `IDN-омограф (${decodedHost}): криптографическая подмена букв под «${brand.name}»`
            : `Подмена символов в домене под «${brand.name}» (${rawHost})`
        });
        matched = true;
        break;
      }
    }

    if (matched) continue;

    // Проверка декодированных кириллических/IDN-алиасов бренда (например, xn--80a1acny.ru → сбер.ru)
    if (isPunycode || hasCyr) {
      for (const rawAlias of brand.aliases || []) {
        const alias = String(rawAlias).toLowerCase().trim();
        if (alias.length < 3) continue;
        const aliasSkel = toLatinSkeleton(alias);
        if (
          hostLabel === alias ||
          (alias.length >= 4 && hostLabel.includes(alias)) ||
          (aliasSkel.length >= 4 && skeletonLabel === aliasSkel)
        ) {
          hits.push({
            brand: brand.name,
            decodedHost,
            isHomograph: true,
            reason: `IDN-омограф (${decodedHost}): домен маскируется под бренд «${brand.name}»`
          });
          break;
        }
      }
    }
  }

  if (!hits.length && mixedScript) {
    hits.push({
      brand: "Mixed-Script IDN",
      decodedHost,
      isHomograph: true,
      reason: `Подозрительный IDN-домен (${decodedHost}): смешение латиницы и кириллицы`
    });
  }

  return hits;
}

/**
 * Слабый lookalike + учёт омографов.
 */
export async function detectLookalike(hostname) {
  const data = await loadBrands();
  const host = (hostname || "").toLowerCase().replace(/^www\./, "");
  if (!host || host.startsWith("local-file") || host === "unknown-host") return [];

  const decoded = decodeIdnHost(host);
  const hostLabel = decoded.split(".")[0];
  const skeletonLabel = toLatinSkeleton(hostLabel);
  const hits = [];

  const homographs = await detectHomograph(host);
  hits.push(...homographs);

  for (const brand of data.brands || []) {
    const domains = brand.domains || [];
    if (hostAllowedForBrand(host, domains)) continue;

    for (const d of domains) {
      const base = d.toLowerCase().replace(/^www\./, "");
      const baseName = base.split(".")[0];
      if (baseName.length < 4) continue;

      if (hasDelimitedToken(decoded, baseName) && host !== base && !host.endsWith("." + base)) {
        hits.push({
          brand: brand.name,
          reason: `Домен похож на «${brand.name}» (${base}), но не совпадает`
        });
        break;
      }

      if (baseName.length >= 5 && hostLabel !== baseName) {
        const maxDist = baseName.length >= 8 ? 2 : 1;
        if (
          editDistance(hostLabel, baseName, maxDist) <= maxDist ||
          editDistance(skeletonLabel, toLatinSkeleton(baseName), 1) <= 1
        ) {
          hits.push({
            brand: brand.name,
            reason: `Домен похож на «${brand.name}» (возможная опечатка или подмена символов)`
          });
          break;
        }
      }
    }
  }

  const seen = new Set();
  return hits.filter((h) => {
    if (seen.has(h.brand)) return false;
    seen.add(h.brand);
    return true;
  });
}

/**
 * Визуальный/ресурсный детект: чужой сайт подгружает иконки, логотипы или стили
 * напрямую с официальных доменов/CDN крупного бренда.
 */
export async function detectAssetSpoof(hostname, assetHosts = []) {
  const host = (hostname || "").toLowerCase().replace(/^www\./, "");
  if (!host || ! Array.isArray(assetHosts) || !assetHosts.length) return [];

  const data = await loadBrands();
  const hits = [];

  for (const brand of data.brands || []) {
    const officialDomains = [
      ...(brand.domains || []),
      ...(BRAND_ASSET_DOMAINS[brand.name] || [])
    ].map((d) => d.toLowerCase());

    if (hostAllowedForBrand(host, officialDomains)) continue;

    const stolenFrom = assetHosts.find((ah) => {
      const a = String(ah || "").toLowerCase();
      return officialDomains.some((od) => a === od || a.endsWith("." + od));
    });

    if (stolenFrom) {
      hits.push({
        brand: brand.name,
        assetHost: stolenFrom,
        reason: `Визуальная мимикрия: страница подгружает логотипы/ресурсы «${brand.name}» (${stolenFrom}) на чужом домене`
      });
    }
  }

  return hits;
}

export function invalidateBrandCache() {
  brandsCache = null;
  aliasRegexCache = null;
}

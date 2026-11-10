import { DEFAULT_SETTINGS, riskThreshold, isUncertainRisk } from "./settings.js";
import {
  getCachedVerdict,
  setCachedVerdict,
  hashContent,
  clearVerdictCache,
  getCachedThreat,
  setCachedThreat
} from "./cache.js";
import {
  detectBrandSpoof,
  detectLookalike,
  detectHomograph,
  detectAssetSpoof,
  invalidateBrandCache
} from "./brands.js";
import { analyzeLocalHeuristics } from "./heuristics.js";
import { evaluateMlFeatures } from "./ml.js";
import { evaluateCaution, detectHttpInsecure, isLocalHost } from "./caution.js";
import { backendAnalyze, backendHealth, backendThreatCheck } from "./api.js";

const HEALTH_TTL_MS = 30 * 1000;

let listCache = null;
let settingsCache = null;
let healthCache = null;

async function loadJson(path) {
  const res = await fetch(chrome.runtime.getURL(path));
  return res.json();
}

/** Настройки читаются на каждый скан — держим в памяти воркера */
async function getSettings() {
  if (settingsCache) return settingsCache;
  const stored = await chrome.storage.sync.get(DEFAULT_SETTINGS);
  settingsCache = { ...DEFAULT_SETTINGS, ...stored };
  return settingsCache;
}

/**
 * Списки строим один раз: раньше Set из ~1200 домленов пересобирался на каждый скан.
 * suffix — домен и его поддомены, exact — только точный хост
 * (площадки с пользовательским контентом: *.wordpress.com доверять нельзя).
 */
async function getLists(settings) {
  const customKey = (settings.customWhitelist || []).join(",");
  if (listCache && listCache.customKey === customKey) return listCache;

  const [white, black] = await Promise.all([
    loadJson("data/whitelist.json"),
    loadJson("data/blacklist.json")
  ]);

  const norm = (arr) => (arr || []).map((d) => String(d).trim().toLowerCase()).filter(Boolean);

  listCache = {
    customKey,
    customSuffix: new Set(norm(settings.customWhitelist)),
    builtinSuffix: new Set(norm(white.domains)),
    whiteSuffix: new Set([...norm(white.domains), ...norm(settings.customWhitelist)]),
    whiteExact: new Set(norm(white.exactDomains)),
    blackSuffix: new Set(norm(black.domains))
  };
  return listCache;
}

/** Проверка, входит ли хост в пользовательский или встроенный белый список */
export async function getWhitelistInfo(hostname) {
  const settings = await getSettings();
  const lists = await getLists(settings);
  const inCustom = hostMatches(hostname, lists.customSuffix);
  const inBuiltin = hostMatches(hostname, lists.builtinSuffix, lists.whiteExact);
  return {
    whitelisted: inCustom || inBuiltin,
    inCustom,
    inBuiltin
  };
}

/**
 * Совпадение по хосту и его родительским суффиксам — O(числа точек),
 * вместо перебора всего списка на каждый скан.
 */
function hostMatches(hostname, suffixSet, exactSet = null) {
  const host = (hostname || "").toLowerCase();
  if (!host || host.startsWith("local-file") || host === "unknown-host") return false;
  if (exactSet && exactSet.has(host)) return true;
  if (suffixSet.has(host)) return true;

  let idx = host.indexOf(".");
  while (idx !== -1) {
    const suffix = host.slice(idx + 1);
    // односоставный суффикс («ru», «com») никогда не считаем — это была бы дыра на весь TLD
    if (suffix.includes(".") && suffixSet.has(suffix)) return true;
    idx = host.indexOf(".", idx + 1);
  }
  return false;
}

function pathKey(url) {
  try {
    return new URL(url).pathname || "/";
  } catch {
    return "/";
  }
}

/** Safe Browsing имеет смысл только для публичных http(s) адресов */
function isThreatCheckable(url, hostname) {
  if (!url || !/^https?:/i.test(url)) return false;
  return !isLocalHost(hostname, url);
}

async function getBackendHealth(baseUrl) {
  if (healthCache && healthCache.baseUrl === baseUrl && Date.now() - healthCache.ts < HEALTH_TTL_MS) {
    return healthCache.ok;
  }
  const health = await backendHealth(baseUrl);
  healthCache = { baseUrl, ts: Date.now(), ok: !!health.ok };
  return healthCache.ok;
}

function cacheSlice(state) {
  return {
    stage: state.stage,
    status: state.status,
    risk: state.risk,
    shouldWarn: state.shouldWarn,
    analyzed: state.analyzed,
    title: state.title,
    reasons: state.reasons,
    source: state.source,
    used_llm: state.used_llm,
    hostname: state.hostname,
    url: state.url,
    hasSensitiveForm: state.hasSensitiveForm,
    fields: state.fields,
    customWhitelisted: !!state.customWhitelisted,
    mlPct: state.mlPct ?? null,
    cautionTier: state.cautionTier || null
  };
}

/**
 * Протокол Legion:
 * whitelist → известные базы → форма-гейт → анализ (красный / жёлтый / safe)
 */
export async function runProtocol(payload) {
  const settings = await getSettings();

  const fields = payload.fields || {};
  const textHints = payload.textHints || {};
  // критичность — только по реальным полям; догадки по тексту модалки сюда не входят
  const hasCritical = !!(fields.password || fields.card || fields.govId || fields.otp);
  const hasSoftPii = !!(fields.email || fields.phone || fields.name);
  const hasTextHint = !!(textHints.password || textHints.email);
  const hasRelevantForm = !!(payload.hasRelevantForm || hasCritical || hasSoftPii || hasTextHint);

  const base = {
    url: payload.url,
    hostname: payload.hostname,
    hasSensitiveForm: !!payload.hasSensitiveForm || hasCritical,
    fields,
    textHints,
    formCrossOrigin: !!payload.formCrossOrigin,
    snippets: payload.snippets || [],
    analyzed: false,
    shouldWarn: false,
    userContinued: false,
    risk: 0,
    reasons: [],
    stage: "init",
    status: "idle",
    source: null,
    cautionTier: null,
    frame: payload.frame || "top"
  };

  if (!settings.enabled) {
    return { ...base, stage: "disabled", status: "off", title: "Защита выключена" };
  }

  const lists = await getLists(settings);

  // Stage 1 — whitelist (зелёный)
  const inCustom = hostMatches(payload.hostname, lists.customSuffix);
  if (inCustom || hostMatches(payload.hostname, lists.whiteSuffix, lists.whiteExact)) {
    return {
      ...base,
      stage: "whitelist",
      status: "safe",
      title: "Доверенный сайт",
      reasons: [
        inCustom
          ? "Домен добавлен вами в белый список"
          : "Домен во встроенном белом списке Legion"
      ],
      source: inCustom ? "custom_whitelist" : "whitelist",
      customWhitelisted: inCustom
    };
  }

  // Stage 2a — локальная база угроз
  if (hostMatches(payload.hostname, lists.blackSuffix)) {
    return {
      ...base,
      stage: "blacklist",
      status: "danger",
      risk: 100,
      shouldWarn: true,
      title: "Известная угроза",
      reasons: ["Домен совпал с локальной базой угроз Legion"],
      source: "blacklist"
    };
  }

  // Кэш вердикта — до сетевых вызовов.
  // Раньше health + threat-check уходили на каждый скан, даже если вердикт уже посчитан.
  const contentHash = hashContent(payload);
  const cached = await getCachedVerdict(payload.hostname, pathKey(payload.url), contentHash);
  if (cached) {
    return { ...base, ...cached, fromCache: true };
  }

  const useBackend = !!(settings.useBackend && settings.backendUrl);
  const backendOk = useBackend ? await getBackendHealth(settings.backendUrl) : false;

  // Stage 2b — Google Safe Browsing
  if (backendOk && isThreatCheckable(payload.url, payload.hostname)) {
    let sb = getCachedThreat(payload.url);
    if (sb === null) {
      sb = await backendThreatCheck(settings.backendUrl, {
        url: payload.url,
        hostname: payload.hostname
      });
      if (sb) setCachedThreat(payload.url, sb);
    }
    if (sb?.hit) {
      return {
        ...base,
        stage: "blacklist",
        status: "danger",
        risk: 100,
        shouldWarn: true,
        title: "Известная угроза",
        reasons: sb.reasons?.length ? sb.reasons : ["URL отмечен в Google Safe Browsing"],
        source: "safe_browsing"
      };
    }
  }

  // Нет релевантных форм → нет угроз по протоколу → safe
  if (!hasRelevantForm) {
    const state = {
      ...base,
      stage: "no_form",
      status: "safe",
      title: "Угроз не обнаружено",
      reasons: ["Нет форм с личными или конфиденциальными данными"],
      source: "gate"
    };
    await setCachedVerdict(payload.hostname, pathKey(payload.url), cacheSlice(state), contentHash);
    return state;
  }

  const checkBrand = settings.checkBrandSpoof !== false;
  const brandHits = checkBrand
    ? await detectBrandSpoof(payload.hostname, payload.snippets || [], payload.title || "")
    : [];
  const homographHits = checkBrand ? await detectHomograph(payload.hostname) : [];
  const assetHits = checkBrand
    ? await detectAssetSpoof(payload.hostname, payload.assetHosts || [])
    : [];
  const lookalikes = checkBrand ? await detectLookalike(payload.hostname) : [];
  const httpInsecure = detectHttpInsecure(payload.url || "");
  const mlResult = settings.mlEnabled !== false ? evaluateMlFeatures(payload) : null;
  const mlPct = mlResult ? mlResult.pct : null;

  // Текстовые эвристики гоняем всегда: раньше они не запускались,
  // если на странице были только email/телефон — и давящий скам оставался незамеченным.
  let analysis = analyzeLocalHeuristics(payload, {
    brandHits,
    assetHits,
    homographHits,
    mlResult,
    hasCritical,
    demoForceWarn: !!settings.demoForceWarn
  });

  // Риск без вклада бренда — иначе упоминание бренда «подтверждало» само себя
  const textOnlyRisk = brandHits.length
    ? analyzeLocalHeuristics(payload, { hasCritical, assetHits, homographHits, mlResult }).risk
    : analysis.risk;

  if (backendOk) {
    const remote = await backendAnalyze(settings.backendUrl, {
      url: payload.url,
      hostname: payload.hostname,
      title: payload.title || "",
      snippets: payload.snippets || [],
      has_sensitive_form: hasCritical || !!payload.hasSensitiveForm,
      local_risk: analysis.risk,
      local_reasons: analysis.reasons,
      brand_hits: brandHits.map((b) => b.brand),
      asset_hosts: payload.assetHosts || [],
      strictness: settings.strictness,
      allow_llm:
        !!settings.useLlmWhenUncertain && isUncertainRisk(analysis.risk, settings.strictness)
    });
    if (remote && typeof remote.risk === "number") {
      analysis = {
        risk: Math.min(100, Number(remote.risk)),
        reasons:
          Array.isArray(remote.reasons) && remote.reasons.length ? remote.reasons : analysis.reasons,
        source: remote.source || "backend",
        used_llm: !!remote.used_llm
      };
    }
  }

  // Прямой IDN-омограф или кража фирменных ресурсов бренда на странице с паролем/картой → красный
  if ((homographHits.length || assetHits.length) && hasCritical) {
    const state = {
      ...base,
      stage: "analysis",
      status: "danger",
      risk: Math.max(94, analysis.risk),
      shouldWarn: true,
      analyzed: true,
      mlPct,
      title: homographHits.length
        ? "Обнаружена криптографическая подмена домена"
        : "Обнаружена визуальная мимикрия под бренд",
      reasons: [
        ...homographHits.map((h) => h.reason),
        ...assetHits.map((a) => a.reason),
        ...brandHits.map((b) => b.reason),
        ...analysis.reasons.filter((r) => !r.includes("манипулятивных маркеров не обнаружено"))
      ].slice(0, 8),
      source: homographHits.length ? "idn_homograph" : "asset_spoof"
    };
    await setCachedVerdict(payload.hostname, pathKey(payload.url), cacheSlice(state), contentHash);
    return state;
  }

  /**
   * Красный по бренду требует подтверждения вторым сигналом.
   * Одного упоминания бренда мало: «Доставка Ozon» на обычном магазине
   * с полем пароля давала блокирующий оверлей.
   */
  const corroborated =
    lookalikes.length > 0 ||
    assetHits.length > 0 ||
    homographHits.length > 0 ||
    !!payload.formCrossOrigin ||
    httpInsecure ||
    textOnlyRisk >= 30 ||
    !!(mlResult && mlResult.probability >= 0.65);

  if (brandHits.length && hasCritical && corroborated) {
    const state = {
      ...base,
      stage: "analysis",
      status: "danger",
      risk: Math.max(92, analysis.risk),
      shouldWarn: true,
      analyzed: true,
      mlPct,
      title: "Обнаружены признаки фишинга",
      reasons: [
        ...brandHits.map((b) => b.reason),
        ...lookalikes.map((l) => l.reason),
        ...analysis.reasons.filter((r) => !r.includes("манипулятивных маркеров не обнаружено"))
      ].slice(0, 8),
      source: "brand_spoof"
    };
    await setCachedVerdict(payload.hostname, pathKey(payload.url), cacheSlice(state), contentHash);
    return state;
  }

  const thr = riskThreshold(settings.strictness);
  if (analysis.risk >= thr) {
    const state = {
      ...base,
      stage: "analysis",
      status: "danger",
      risk: analysis.risk,
      shouldWarn: true,
      analyzed: true,
      mlPct,
      title: "Обнаружены признаки фишинга",
      reasons: analysis.reasons,
      source: analysis.source,
      used_llm: !!analysis.used_llm
    };
    await setCachedVerdict(payload.hostname, pathKey(payload.url), cacheSlice(state), contentHash);
    return state;
  }

  // Cross-origin форма + критичные поля → тоже красный
  if (payload.formCrossOrigin && hasCritical) {
    const state = {
      ...base,
      stage: "analysis",
      status: "danger",
      risk: Math.max(analysis.risk, 78),
      shouldWarn: true,
      analyzed: true,
      mlPct,
      title: "Обнаружены признаки фишинга",
      reasons: [
        "Форма отправляет данные на другой домен",
        ...analysis.reasons.filter((r) => !r.includes("манипулятивных маркеров не обнаружено"))
      ].slice(0, 8),
      source: "form_cross_origin"
    };
    await setCachedVerdict(payload.hostname, pathKey(payload.url), cacheSlice(state), contentHash);
    return state;
  }

  // Жёлтый режим
  if (settings.cautionEnabled !== false) {
    const caution = evaluateCaution(payload, { lookalikes, httpInsecure, brandHits });
    if (caution.caution) {
      const state = {
        ...base,
        stage: "caution",
        status: "caution",
        risk: Math.max(analysis.risk, caution.risk),
        shouldWarn: false,
        analyzed: true,
        mlPct,
        title: caution.title,
        reasons: caution.reasons,
        source: `caution_${caution.tier}`,
        cautionTier: caution.tier,
        used_llm: !!analysis.used_llm
      };
      await setCachedVerdict(payload.hostname, pathKey(payload.url), cacheSlice(state), contentHash);
      return state;
    }
  }

  // Иначе — форма есть, угроз не найдено
  const state = {
    ...base,
    stage: "analysis",
    status: "safe",
    risk: analysis.risk,
    shouldWarn: false,
    analyzed: true,
    mlPct,
    title: hasCritical ? "Форма есть, угроз не найдено" : "Личные данные без признаков угрозы",
    reasons: analysis.reasons.length
      ? analysis.reasons
      : ["Дополнительных сигналов риска не обнаружено"],
    source: analysis.source || "local_heuristics",
    used_llm: !!analysis.used_llm
  };
  await setCachedVerdict(payload.hostname, pathKey(payload.url), cacheSlice(state), contentHash);
  return state;
}

export function invalidateListCaches() {
  listCache = null;
  settingsCache = null;
  healthCache = null;
  invalidateBrandCache();
}

// Смена настроек раньше не сбрасывала кэш вердиктов — строгость/белый список
// применялись только к новым страницам.
chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "sync") return;
  invalidateListCaches();
  clearVerdictCache();
});

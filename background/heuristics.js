/**
 * Быстрые локальные эвристики (работают без backend/LLM).
 * Форма сама по себе риск почти не даёт — только текстовые маркеры + spoof + обфускация.
 */

import { stripZeroWidth, hasZeroWidthObfuscation } from "./brands.js";

const PATTERNS = [
  { re: /осталось\s+\d+\s*(мин|минут|секунд|sec|min)/i, score: 35, reason: "Искусственная срочность (таймер)" },
  { re: /компенсац|выплат[аыуе]|начислен(ие|о)|возврат\s+средств/i, score: 28, reason: "Обещание выплат / компенсации" },
  { re: /пароль\s+от\s+(telegram|телеграм|steam|стим|discord|дискорд|вк|vk|госуслуг)/i, score: 48, reason: "Просьба пароля от стороннего сервиса" },
  { re: /аккаунт\s+будет\s+заблокир|срочно\s+подтверд|иначе\s+блокир/i, score: 35, reason: "Давление и угроза блокировки" },
  { re: /введите\s+пароль\s+от\s+госуслуг/i, score: 50, reason: "Фишинговая имитация Госуслуг" },
  { re: /лёгк(ие|ая)\s+деньг|халяв|бесплатн(о|ые)\s+деньг|лёгкий\s+заработок/i, score: 30, reason: "Обещание лёгкой наживы" },
  { re: /подтвердите\s+(данные|личность|вход).{0,40}(карт|парол|смс|код)/i, score: 22, reason: "Подозрительное подтверждение через секреты" },
  { re: /розыгрыш|бесплатн(ый|ая)\s+skin|скин[ыа].{0,20}(парол|steam|логин)/i, score: 32, reason: "Скам вокруг игровых аккаунтов/скинов" },
  { re: /security\s+alert|unusual\s+sign-?in|verify\s+your\s+account\s+now/i, score: 24, reason: "Типовой англоязычный phishing-шаблон" }
];

export function analyzeLocalHeuristics(
  payload,
  { brandHits = [], assetHits = [], homographHits = [], mlResult = null, demoForceWarn = false, hasCritical = false } = {}
) {
  const rawText = `${payload.title || ""} ${(payload.snippets || []).join(" ")}`;
  const text = stripZeroWidth(rawText);
  const sensitive = hasCritical || !!payload.hasSensitiveForm;
  let risk = 8;
  const reasons = [];

  if (hasZeroWidthObfuscation(rawText)) {
    risk += 32;
    reasons.push("Маскировка текста невидимыми символами (Zero-Width Obfuscation)");
  }

  for (const p of PATTERNS) {
    if (p.re.test(text)) {
      risk += p.score;
      if (p.reason) reasons.push(p.reason);
    }
  }

  // Бренд учитываем только рядом с критичными полями и без накопления
  if (brandHits.length && sensitive) {
    risk += 42;
    reasons.push(...brandHits.map((h) => h.reason));
  }

  // Подгрузка логотипов/ресурсов бренда на чужом домене
  if (assetHits.length && sensitive) {
    risk += 45;
    reasons.push(...assetHits.map((a) => a.reason));
  }

  // IDN-омограф (Punycode / подмена букв под бренд)
  if (homographHits.length && sensitive) {
    risk += 55;
    reasons.push(...homographHits.map((h) => h.reason));
  }

  // Вклад локального ML-классификатора структуры URL и DOM
  if (mlResult && mlResult.scoreBoost > 0 && sensitive) {
    risk += mlResult.scoreBoost;
    reasons.push(...(mlResult.reasons || []));
  }

  // слабый доп.сигнал: http + форма (localhost не считаем — это демо/отладка)
  try {
    if (payload.url && payload.url.startsWith("http://") && sensitive) {
      const host = new URL(payload.url).hostname;
      const isLocal =
        host === "localhost" ||
        host === "127.0.0.1" ||
        host === "[::1]" ||
        host.endsWith(".local");
      if (!isLocal) {
        risk += 15;
        reasons.push("Чувствительная форма на незащищённом HTTP");
      }
    }
  } catch (_) {}

  if (demoForceWarn) {
    risk = Math.max(risk, 85);
    reasons.push("Включён демо-режим принудительного предупреждения");
  }

  if (reasons.length === 0) {
    reasons.push(
      sensitive
        ? "Чувствительная форма найдена, манипулятивных маркеров не обнаружено"
        : "Манипулятивных маркеров в тексте не обнаружено"
    );
  }

  const uniq = [...new Set(reasons)];
  return { risk: Math.min(risk, 100), reasons: uniq, source: "local_heuristics" };
}

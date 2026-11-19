/**
 * Legion · Перехват скрытой отправки данных (модуль exfil-hook).
 *
 * Работает в MAIN world страницы на document_start — ДО скриптов сайта, поэтому
 * видит все fetch / XMLHttpRequest / sendBeacon / WebSocket, которые уходят с страницы.
 *
 * Правило: если в запрос на ДРУГОЙ сайт (не тот же домен второго уровня)
 * попадает значение из чувствительного поля (пароль, код из СМС, номер карты),
 * запрос останавливается, а расширению уходит событие — оно показывает предупреждение.
 *
 * Принципы безопасности, ради которых всё написано так:
 *  - не ломаем страницу: любая ошибка внутри хука глушится, оригинальный вызов сохраняется;
 *  - не читаем и не храним введённые данные: сравниваем значения на лету и не сохраняем;
 *  - в событие для расширения уходят только тип поля и адрес назначения, без значений.
 *
 * Известное ограничение: JS на странице может тоже подменить эти функции и отключить хук
 * (как и любой защиты внутри страницы). Поэтому это дополнение к протоколу, а не замена ему.
 */
(() => {
  if (window.__legionExfilHook) return;
  try {
    Object.defineProperty(window, "__legionExfilHook", { value: true });
  } catch (_) {
    return;
  }

  const CHANNEL = "__legion";
  /** "block" — останавливать, "off" — только пропускать (выключено пользователем или сайт в белом списке) */
  let mode = "block";

  const MIN_LEN = { password: 6, otp: 4, card: 12 };
  const SECOND_LEVEL_SUFFIXES = new Set(["co", "com", "net", "org", "gov", "edu", "ac"]);
  const REPORT_COOLDOWN_MS = 3000;
  const lastReportAt = new Map();

  // ------------------------------------------------------------ конфигурация от расширения
  window.addEventListener("message", (e) => {
    if (e.source !== window || !e.data || typeof e.data !== "object") return;
    if (e.data[CHANNEL] === "exfil-config") {
      mode = e.data.mode === "off" ? "off" : "block";
    }
  });

  // ------------------------------------------------------------ чувствительные поля
  function sensitiveValues() {
    const out = [];
    let nodes;
    try {
      nodes = document.querySelectorAll("input");
    } catch (_) {
      return out;
    }
    for (const el of nodes) {
      const value = el.value;
      if (!value) continue;
      const type = String(el.type || "").toLowerCase();
      const ac = String(el.getAttribute("autocomplete") || "").toLowerCase();
      const name = `${el.name || ""} ${el.id || ""}`.toLowerCase();
      if (type === "password" || ac === "current-password" || ac === "new-password") {
        out.push({ kind: "password", value });
      } else if (ac === "one-time-code" || /\b(otp|sms|2fa|totp)\b|verification.?code/.test(name)) {
        out.push({ kind: "otp", value });
      } else if (ac.startsWith("cc-") || /card|cvv|cvc/.test(name)) {
        out.push({ kind: "card", value });
      }
    }
    return out;
  }

  /** Возможные записи одного значения в теле запроса: как есть, в URL-кодировке и в JSON-экранировании */
  function variantsOf(value) {
    const set = new Set([value]);
    try {
      set.add(encodeURIComponent(value));
    } catch (_) {}
    try {
      set.add(JSON.stringify(value).slice(1, -1));
    } catch (_) {}
    return [...set];
  }

  const isWordChar = (ch) => /[A-Za-z0-9]/.test(ch);

  /** Совпадение целым «куском»: «123456» не должно срабатывать внутри «91234567» */
  function containsToken(haystack, needle) {
    let i = haystack.indexOf(needle);
    while (i !== -1) {
      const before = i > 0 ? haystack[i - 1] : "";
      const after = haystack[i + needle.length] || "";
      if (!isWordChar(before) && !isWordChar(after)) return true;
      i = haystack.indexOf(needle, i + 1);
    }
    return false;
  }

  /** Есть ли в тексте запроса значение чувствительного поля. Возвращает тип поля или null. */
  function findLeak(text) {
    if (!text) return null;
    const fields = sensitiveValues();
    if (!fields.length) return null;
    const digitsOnly = text.replace(/\D/g, "");
    for (const f of fields) {
      if (f.kind === "card") {
        const needle = f.value.replace(/\D/g, "");
        if (needle.length >= MIN_LEN.card && containsToken(digitsOnly, needle)) return f.kind;
        continue;
      }
      if (f.value.length < MIN_LEN[f.kind]) continue;
      for (const variant of variantsOf(f.value)) {
        if (variant.length >= MIN_LEN[f.kind] && containsToken(text, variant)) return f.kind;
      }
    }
    return null;
  }

  // ------------------------------------------------------------ адреса и «сайт»
  function destHostOf(urlLike) {
    try {
      const u = new URL(String(urlLike), location.href);
      if (!["http:", "https:", "ws:", "wss:"].includes(u.protocol)) return null;
      return u.hostname.toLowerCase();
    } catch (_) {
      return null;
    }
  }

  /** Приближённый «сайт» (домен второго уровня). Для IP и localhost — сам адрес. */
  function siteOf(host) {
    if (!host) return "";
    if (host.includes(":") || /^[\d.]+$/.test(host) || !host.includes(".")) return host;
    const parts = host.split(".");
    const n = parts.length;
    if (n >= 3 && parts[n - 1].length === 2 && SECOND_LEVEL_SUFFIXES.has(parts[n - 2])) {
      return parts.slice(-3).join(".");
    }
    return parts.slice(-2).join(".");
  }

  function isCrossSite(host) {
    const here = (location.hostname || "").toLowerCase();
    return siteOf(host) !== siteOf(here);
  }

  // ------------------------------------------------------------ тело запроса
  function bodyText(body) {
    if (body == null) return "";
    try {
      if (typeof body === "string") return body;
      if (body instanceof URLSearchParams) return body.toString();
      if (typeof FormData !== "undefined" && body instanceof FormData) {
        const parts = [];
        for (const [k, v] of body.entries()) {
          if (typeof v === "string") parts.push(`${k}=${v}`);
        }
        return parts.join("&");
      }
      if (body instanceof ArrayBuffer) return new TextDecoder().decode(body);
      if (ArrayBuffer.isView(body)) {
        return new TextDecoder().decode(new Uint8Array(body.buffer, body.byteOffset, body.byteLength));
      }
    } catch (_) {}
    return "";
  }

  // ------------------------------------------------------------ решение и отчёт
  function report(detail) {
    const key = `${detail.dest}|${detail.field}`;
    const now = Date.now();
    if (now - (lastReportAt.get(key) || 0) < REPORT_COOLDOWN_MS) return;
    lastReportAt.set(key, now);
    window.postMessage({ [CHANNEL]: "exfil-event", ...detail, url: location.href }, "*");
  }

  /** Вернуть true, если запрос нужно остановить. */
  function shouldStop(urlLike, text, via) {
    if (mode === "off") return false;
    const host = destHostOf(urlLike);
    if (!host || !isCrossSite(host)) return false;
    const field = findLeak(text);
    if (!field) return false;
    report({ kind: "blocked", via, dest: host, field });
    return true;
  }

  // ------------------------------------------------------------ fetch
  const origFetch = window.fetch;
  if (typeof origFetch === "function") {
    window.fetch = function legionFetch(input, init) {
      try {
        const isRequest = typeof Request !== "undefined" && input instanceof Request;
        const url = isRequest ? input.url : input;
        if (isRequest && input.body) {
          // тело у Request читается асинхронно — проверяем по клону, оригинал не трогаем
          return input
            .clone()
            .text()
            .then(
              (text) =>
                shouldStop(url, text, "fetch")
                  ? Promise.reject(new TypeError("Legion: запрос остановлен"))
                  : Reflect.apply(origFetch, window, arguments),
              () => Reflect.apply(origFetch, window, arguments)
            );
        }
        const body = init && init.body !== undefined ? init.body : null;
        if (shouldStop(url, bodyText(body), "fetch")) {
          return Promise.reject(new TypeError("Legion: запрос остановлен"));
        }
      } catch (_) {
        /* хук никогда не ломает страницу */
      }
      return Reflect.apply(origFetch, window, arguments);
    };
  }

  // ------------------------------------------------------------ XMLHttpRequest
  const XHR = window.XMLHttpRequest;
  if (XHR && XHR.prototype) {
    const xhrOpen = XHR.prototype.open;
    const xhrSend = XHR.prototype.send;
    XHR.prototype.open = function legionOpen(method, url) {
      try {
        this.__legionUrl = url;
      } catch (_) {}
      return Reflect.apply(xhrOpen, this, arguments);
    };
    XHR.prototype.send = function legionSend(body) {
      try {
        if (shouldStop(this.__legionUrl, bodyText(body), "xhr")) {
          // Страница должна получить обычный отказ, а не зависнуть в ожидании ответа
          const xhr = this;
          try {
            xhr.abort();
          } catch (_) {}
          setTimeout(() => {
            try {
              xhr.dispatchEvent(new Event("error"));
              xhr.dispatchEvent(new Event("loadend"));
            } catch (_) {}
          }, 0);
          return undefined;
        }
      } catch (_) {}
      return Reflect.apply(xhrSend, this, arguments);
    };
  }

  // ------------------------------------------------------------ sendBeacon
  if (typeof Navigator !== "undefined" && Navigator.prototype.sendBeacon) {
    const origBeacon = Navigator.prototype.sendBeacon;
    Navigator.prototype.sendBeacon = function legionBeacon(url, data) {
      try {
        if (shouldStop(url, bodyText(data), "beacon")) return false;
      } catch (_) {}
      return Reflect.apply(origBeacon, this, arguments);
    };
  }

  // ------------------------------------------------------------ WebSocket
  if (typeof WebSocket !== "undefined" && WebSocket.prototype.send) {
    const origWsSend = WebSocket.prototype.send;
    WebSocket.prototype.send = function legionWsSend(data) {
      try {
        if (typeof data === "string" && shouldStop(this.url, data, "ws")) return undefined;
      } catch (_) {}
      return Reflect.apply(origWsSend, this, arguments);
    };
  }
})();

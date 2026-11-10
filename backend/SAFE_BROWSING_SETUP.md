# Как получить ключ Google Safe Browsing для Legion

1. Зайди в https://console.cloud.google.com/
2. Создай проект (например `legion-antiphish`)
3. APIs & Services → Enable APIs → включи **Safe Browsing API**
4. Credentials → Create credentials → API key
5. (Желательно) Restrict key → только Safe Browsing API
6. Вставь ключ в `backend/.env`:

```
SAFE_BROWSING_API_KEY=твой_ключ
```

7. Перезапусти backend (`start.bat`)
8. В попапе Legion должно быть `SB on`

Без ключа этап 2 всё равно работает на локальном blacklist;
Safe Browsing просто не вызывается.

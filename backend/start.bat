@echo off
setlocal
cd /d "%~dp0"
title Legion backend

rem Порт занят — почти всегда это уже запущенный (или зависший) uvicorn
netstat -ano | findstr ":8787 " | findstr LISTENING >nul
if not errorlevel 1 (
  echo [!] Порт 8787 уже занят - backend, похоже, уже запущен.
  echo     Проверь в браузере: http://127.0.0.1:8787/health
  echo     Если это старая версия - закрой то чёрное окно и запусти этот файл снова.
  echo.
  pause
  exit /b 1
)

python --version >nul 2>&1
if errorlevel 1 (
  echo [!] Python не найден в PATH.
  echo     Поставь Python 3 и при установке включи "Add python.exe to PATH".
  echo.
  pause
  exit /b 1
)

rem Зависимости ставим только если их реально нет, иначе каждый запуск ждёт pip
python -c "import fastapi, uvicorn, dotenv" >nul 2>&1
if errorlevel 1 (
  echo Ставлю зависимости...
  python -m pip install -r requirements.txt
  if errorlevel 1 (
    echo.
    echo [!] pip не смог поставить зависимости - смотри ошибку выше.
    pause
    exit /b 1
  )
)

echo.
echo === Legion backend ===
echo Проверка:   http://127.0.0.1:8787/health
echo Остановить: Ctrl+C
echo Это окно должно остаться открытым.
echo.

python -m uvicorn app.main:app --host 127.0.0.1 --port 8787 --reload

echo.
echo [!] Сервер остановился. Причина - в сообщениях выше.
pause
endlocal

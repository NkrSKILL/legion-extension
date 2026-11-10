@echo off
setlocal
cd /d "%~dp0.."

set CHROME=%ProgramFiles%\Google\Chrome\Application\chrome.exe
if not exist "%CHROME%" set CHROME=%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe
if not exist "%CHROME%" set CHROME=%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe
if not exist "%CHROME%" (
  echo Chrome не найден — пропускаю проверки клиентской логики.
  goto :backend
)

echo === Поднимаю локальный сервер на 8791 ===
call :kill_port
start "legion-check-server" /min python -m http.server 8791
ping -n 3 127.0.0.1 >nul

echo.
echo === Синтаксис и загрузка модулей ===
"%CHROME%" --headless=new --disable-gpu --no-sandbox --virtual-time-budget=8000 --dump-dom "http://127.0.0.1:8791/demo/_syntax-check.html" 2>nul | findstr /R "^OK ^SYNTAX ^BADJSON ^TOTAL"

echo.
echo === Логика протокола (whitelist / красный / жёлтый / ложные срабатывания) ===
"%CHROME%" --headless=new --disable-gpu --no-sandbox --virtual-time-budget=10000 --dump-dom "http://127.0.0.1:8791/demo/_logic-check.html" 2>nul | findstr /R "^OK ^FAIL ^ERROR ^TOTAL"

call :kill_port

:backend
echo.
echo === Backend ===
cd backend
python tests\run_checks.py
cd ..

echo.
echo Готово.
endlocal
exit /b 0

:kill_port
rem Гасим сервер проверок по порту: по заголовку окна дочерний python не находился
for /f "tokens=5" %%p in ('netstat -ano ^| findstr ":8791 " ^| findstr LISTENING') do (
  taskkill /PID %%p /F >nul 2>&1
)
exit /b 0

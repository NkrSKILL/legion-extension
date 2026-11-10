@echo off
setlocal
cd /d "%~dp0"
title Legion stats
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0stats.ps1" %*
echo.
echo ------------------------------------------
pause
endlocal

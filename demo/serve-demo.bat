@echo off
cd /d "%~dp0"
echo Legion demo server: http://127.0.0.1:8765/
echo Open: http://127.0.0.1:8765/fake-phish.html
echo       http://127.0.0.1:8765/normal-login.html
echo Keep this window open.
python -m http.server 8765

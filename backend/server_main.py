"""Точка входа локального сервера Legion.

Используется в двух режимах:
  * из исходников:  cd backend && python server_main.py
  * установленная версия: legion-server.exe (собирается PyInstaller, см. installer/build.ps1)

В установленной версии сервер запускает native-host (installer/native-host) через
Chrome Native Messaging, поэтому у него нет консоли: stdout/stderr пишутся в лог.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

HOST = "127.0.0.1"
PORT = 8787

FROZEN = bool(getattr(sys, "frozen", False))


def _setup_frozen_runtime() -> None:
    """Готовит окружение для exe: writable-данные, лог вместо отсутствующего stdout."""
    base = Path(sys.executable).resolve().parent  # {app}\server
    data_dir = base / "data"
    log_dir = base.parent / "logs"  # {app}\logs
    data_dir.mkdir(parents=True, exist_ok=True)
    log_dir.mkdir(parents=True, exist_ok=True)

    # Windowed-сборка: sys.stdout / sys.stderr равны None — без этого uvicorn и traceback упадут
    if sys.stdout is None or sys.stderr is None:
        log = open(log_dir / "server.log", "a", encoding="utf-8", buffering=1)
        if sys.stdout is None:
            sys.stdout = log
        if sys.stderr is None:
            sys.stderr = log

    os.environ.setdefault("LEGION_DATA_DIR", str(data_dir))
    os.environ.setdefault("LEGION_BRANDS_PATH", str(data_dir / "brands.json"))

    # Необязательный файл с ключами (Safe Browsing / LLM) — кладётся пользователем вручную
    from dotenv import load_dotenv

    load_dotenv(data_dir / ".env")


def main() -> None:
    if FROZEN:
        _setup_frozen_runtime()

    import uvicorn

    from app.main import app

    uvicorn.run(
        app,
        host=HOST,
        port=PORT,
        log_level="warning",
        access_log=False,
        server_header=False,
    )


if __name__ == "__main__":
    main()

"""Native Messaging host для Legion (Chrome -> legion-host.exe -> legion-server.exe).

Chrome запускает этот процесс на каждое сообщение расширения, мы отвечаем и выходим.
Сервер стартует отсоединённым (DETACHED_PROCESS), поэтому он живёт дальше.

Протокол Chrome: на stdin/stdout — 4 байта длины (uint32 LE) + JSON в UTF-8.

Поддерживаемые действия:
  {"action": "start"}  — убедиться, что сервер работает; при необходимости запустить
  {"action": "status"} — только проверка, ничего не запускаем
  {"action": "ping"}   — проверка самого хоста
"""

from __future__ import annotations

import ctypes
import json
import msvcrt
import os
import struct
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

HOST_VERSION = "1"
SERVER_PORT = 8787
HEALTH_URL = f"http://127.0.0.1:{SERVER_PORT}/health"
START_TIMEOUT_SEC = 15.0
MAX_MESSAGE_BYTES = 1024 * 1024

# Windows process creation flags
DETACHED_PROCESS = 0x00000008
CREATE_NEW_PROCESS_GROUP = 0x00000200
CREATE_BREAKAWAY_FROM_JOB = 0x01000000

STD_INPUT_HANDLE = -10
STD_OUTPUT_HANDLE = -11

# {app}\host\legion-host.exe -> {app}
APP_DIR = Path(sys.executable).resolve().parent.parent
SERVER_EXE = APP_DIR / "server" / "legion-server.exe"
LOG_FILE = APP_DIR / "logs" / "host.log"
LOG_MAX_BYTES = 512 * 1024


def log(message: str) -> None:
    """Лог best-effort: ошибки записи не должны ломать протокол."""
    try:
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        if LOG_FILE.exists() and LOG_FILE.stat().st_size > LOG_MAX_BYTES:
            LOG_FILE.replace(LOG_FILE.with_suffix(".log.old"))
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        with open(LOG_FILE, "a", encoding="utf-8") as fh:
            fh.write(f"{stamp} {message}\n")
    except OSError:
        pass


def _std_fd(which: int, flags: int) -> int | None:
    """Файловый дескриптор стандартного потока.

    У windowed-exe sys.stdin/sys.stdout = None, поэтому берём хендл напрямую из WinAPI.
    Chrome передаёт каналы через STARTUPINFO, GetStdHandle их возвращает.
    """
    kernel32 = ctypes.windll.kernel32
    kernel32.GetStdHandle.restype = ctypes.c_void_p
    handle = kernel32.GetStdHandle(which)
    invalid = ctypes.c_void_p(-1).value
    if handle and handle != invalid:
        return msvcrt.open_osfhandle(handle, flags)
    stream = sys.stdin if which == STD_INPUT_HANDLE else sys.stdout
    if stream is not None:
        try:
            return stream.fileno()
        except (OSError, ValueError):
            return None
    return None


def _read_exact(fd: int, count: int) -> bytes:
    chunks: list[bytes] = []
    remaining = count
    while remaining > 0:
        chunk = os.read(fd, remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_message(fd: int) -> dict | None:
    header = _read_exact(fd, 4)
    if len(header) < 4:
        return None
    (length,) = struct.unpack("<I", header)
    if length == 0 or length > MAX_MESSAGE_BYTES:
        raise ValueError(f"bad message length {length}")
    body = _read_exact(fd, length)
    if len(body) < length:
        raise ValueError("truncated message")
    data = json.loads(body.decode("utf-8"))
    return data if isinstance(data, dict) else None


def write_message(fd: int, payload: dict) -> None:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    buf = struct.pack("<I", len(body)) + body
    while buf:
        written = os.write(fd, buf)
        buf = buf[written:]


def server_status() -> dict | None:
    """Вернуть /health сервера, если он отвечает и это именно Legion."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(HEALTH_URL, timeout=1.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (OSError, ValueError):
        return None
    if isinstance(data, dict) and data.get("ok") and data.get("service") == "legion-backend":
        return data
    return None


def _spawn_server() -> None:
    base_flags = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
    common = {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "close_fds": True,
        "cwd": str(SERVER_EXE.parent),
    }
    # Breakaway нужен, если Chrome запустил нас в job с KILL_ON_JOB_CLOSE.
    # Если job не разрешает breakaway, Windows вернёт ошибку — тогда запускаем без него.
    try:
        subprocess.Popen([str(SERVER_EXE)], creationflags=base_flags | CREATE_BREAKAWAY_FROM_JOB, **common)
        log("server spawned (breakaway)")
    except OSError as exc:
        log(f"breakaway spawn failed ({exc}), retry without")
        subprocess.Popen([str(SERVER_EXE)], creationflags=base_flags, **common)
        log("server spawned")


def start_server() -> dict:
    running = server_status()
    if running:
        return {"ok": True, "status": "running", "version": running.get("version")}

    if not SERVER_EXE.exists():
        log(f"server missing: {SERVER_EXE}")
        return {"ok": False, "status": "missing", "error": "server_not_installed"}

    _spawn_server()
    deadline = time.monotonic() + START_TIMEOUT_SEC
    while time.monotonic() < deadline:
        time.sleep(0.25)
        running = server_status()
        if running:
            return {"ok": True, "status": "started", "version": running.get("version")}
    log("server did not answer in time")
    return {"ok": False, "status": "timeout", "error": "server_timeout"}


def handle(message: dict) -> dict:
    action = str(message.get("action") or "")
    if action == "start":
        return start_server()
    if action == "status":
        running = server_status()
        return {"ok": bool(running), "status": "running" if running else "stopped"}
    if action == "ping":
        return {"ok": True, "status": "pong", "host_version": HOST_VERSION}
    return {"ok": False, "error": "unknown_action"}


def main() -> int:
    in_fd = _std_fd(STD_INPUT_HANDLE, os.O_RDONLY | os.O_BINARY)
    out_fd = _std_fd(STD_OUTPUT_HANDLE, os.O_WRONLY | os.O_BINARY)
    if in_fd is None or out_fd is None:
        log("no stdio channels")
        return 1

    try:
        message = read_message(in_fd)
    except (ValueError, UnicodeDecodeError) as exc:
        log(f"bad input: {exc}")
        write_message(out_fd, {"ok": False, "error": "bad_input"})
        return 1
    if message is None:
        return 0

    try:
        reply = handle(message)
    except Exception as exc:  # noqa: BLE001 - любая ошибка должна стать ответом, а не крэшем
        log(f"handler error: {exc!r}")
        reply = {"ok": False, "error": "host_error"}

    write_message(out_fd, reply)
    return 0


if __name__ == "__main__":
    sys.exit(main())

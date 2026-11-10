"""Запуск: python -m uvicorn app.main:app --host 127.0.0.1 --port 8787 --reload
из папки backend/
"""
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent / ".env")

# re-export
from app.main import app  # noqa: E402,F401

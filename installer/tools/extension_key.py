"""Ключ расширения Legion: стабильный ID и проверка манифеста.

Использование:
  python installer/tools/extension_key.py make   # один раз: создаёт keys/legion-extension.pem
  python installer/tools/extension_key.py id     # печатает ID по полю "key" из manifest.json

Закрытый ключ (keys/*.pem) в git не попадает. Его нужно хранить у себя: без него
ID расширения изменится, и нативный хост перестанет принимать запросы.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
KEY_PATH = ROOT / "keys" / "legion-extension.pem"
MANIFEST = ROOT / "manifest.json"


def extension_id_from_der(der_public_key: bytes) -> str:
    """Chrome: первые 32 hex-символа sha256(DER public key), 0-9a-f -> a-p."""
    digest = hashlib.sha256(der_public_key).hexdigest()[:32]
    return "".join(chr(ord("a") + int(ch, 16)) for ch in digest)


def make_key() -> None:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    if KEY_PATH.exists():
        print(f"Ключ уже есть: {KEY_PATH} (не перезаписываю)")
        return
    KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    KEY_PATH.write_bytes(pem)
    print(f"Ключ создан: {KEY_PATH}")
    print("Добавьте в manifest.json поле \"key\":")
    print(public_key_b64(key.public_key()))


def public_key_b64(public_key) -> str:
    from cryptography.hazmat.primitives import serialization

    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(der).decode("ascii")


def print_id() -> None:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    key_b64 = manifest.get("key")
    if not key_b64:
        raise SystemExit("В manifest.json нет поля key")
    der = base64.b64decode(key_b64)
    print(extension_id_from_der(der))


if __name__ == "__main__":
    command = sys.argv[1] if len(sys.argv) > 1 else "id"
    if command == "make":
        make_key()
    elif command == "id":
        print_id()
    else:
        raise SystemExit(f"Неизвестная команда: {command}")

"""
Криптографические примитивы для vpn-poller.

- Ключи шифрования и HMAC выводятся из общего preshared key (PSK) через HKDF.
- Payload шифруется AES-256-GCM (аутентифицированное шифрование).
- Дополнительно каждый HTTP-запрос подписывается HMAC-SHA256 от
  (client_id + timestamp + ciphertext), что защищает от подмены запросов
  и добавляет anti-replay проверку по времени на стороне сервера.
"""

import os
import hmac
import hashlib
import base64

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def derive_key(psk_b64: str, info: bytes = b"vpn-poller-enc") -> bytes:
    """Выводит 32-байтовый ключ шифрования из PSK (base64)."""
    psk = base64.b64decode(psk_b64)
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info)
    return hkdf.derive(psk)


def derive_hmac_key(psk_b64: str) -> bytes:
    """Выводит отдельный 32-байтовый ключ для HMAC (доменное разделение ключей)."""
    psk = base64.b64decode(psk_b64)
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"vpn-poller-hmac")
    return hkdf.derive(psk)


def encrypt(key: bytes, plaintext: bytes) -> bytes:
    """AES-256-GCM. Возвращает nonce(12 байт) + ciphertext(+tag)."""
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ct


def decrypt(key: bytes, blob: bytes) -> bytes:
    """Обратная операция к encrypt(). Бросает исключение при неверном ключе/подмене данных."""
    if len(blob) < 12:
        raise ValueError("blob too short")
    nonce, ct = blob[:12], blob[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None)


def sign(key: bytes, data: bytes) -> str:
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def verify(key: bytes, data: bytes, mac_hex: str) -> bool:
    try:
        expected = sign(key, data)
        return hmac.compare_digest(expected, mac_hex)
    except Exception:
        return False


def b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64u_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def generate_psk() -> str:
    """Генерирует новый случайный preshared key в base64 (32 байта энтропии)."""
    return base64.b64encode(os.urandom(32)).decode("ascii")


if __name__ == "__main__":
    # Утилита: python crypto_utils.py -> печатает новый PSK для config.yaml
    print(generate_psk())

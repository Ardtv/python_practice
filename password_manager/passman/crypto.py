"""Криптография: соль, получение ключа из пароля (PBKDF2), проверочный хэш, шифрование Fernet."""

import base64
import hashlib
import hmac
import os

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SALT_SIZE = 16
KEY_LENGTH = 32
DEFAULT_ITERATIONS = 600_000


class DecryptionError(Exception):
    """Не удалось расшифровать данные: неверный пароль или поврежденное хранилище"""


def make_verifier(key: bytes) -> str:
    """Проверочный хэш ключа: SHA-256 в hex"""
    return hashlib.sha256(key).hexdigest()


def check_verifier(key: bytes, verifier: str) -> bool:
    """Сравнивает хэш ключа с сохранённым за постоянное время"""
    return hmac.compare_digest(make_verifier(key), verifier)


def generate_salt() -> bytes:
    """Генерирует случайную соль для получения ключа из пароля"""
    return os.urandom(SALT_SIZE)


def derive_key(password: str, salt: bytes, iterations: int = DEFAULT_ITERATIONS) -> bytes:
    """Получает ключ Fernet из пароля через PBKDF2"""
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=KEY_LENGTH, salt=salt, iterations=iterations)
    raw_key = kdf.derive(password.encode("utf-8"))
    return base64.urlsafe_b64encode(raw_key)


def encrypt(data: bytes, key: bytes) -> bytes:
    """Шифрует данные ключом Fernet и возвращает токен"""
    fernet = Fernet(key)
    return fernet.encrypt(data)


def decrypt(token: bytes, key: bytes) -> bytes:
    """Расшифровывает токен; при неверном ключе или повреждённых данных бросает DecryptionError"""
    fernet = Fernet(key)
    try:
        return fernet.decrypt(token)
    except InvalidToken as e:
        raise DecryptionError("Неверный пароль или повреждённое хранилище") from e

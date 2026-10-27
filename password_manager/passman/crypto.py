import os
import base64

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

SALT_SIZE = 16
KEY_LENGTH = 32
DEFAULT_ITERATIONS = 600_000


class DecryptionError(Exception):
    """Не удалось расшифровать данные: неверный пароль или поврежденное хранилище"""


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
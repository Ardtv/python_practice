import json
import os

from passman import storage, crypto


class Vault:
    """Открытое хранилище: ключ и записи в памяти"""

    def __init__(self, path: str, key: bytes, salt: bytes, iterations: int, entries: list[dict]) -> None:
        self.path = path
        self.salt = salt
        self.key = key
        self.iterations = iterations
        self.entries = entries

    def save(self) -> None:
        """Шифрует записи и сохраняет хранилище на диск"""
        plaintext = json.dumps(self.entries, ensure_ascii=False).encode("utf-8")
        token = crypto.encrypt(plaintext, self.key)
        storage.write_vault(self.path, self.salt, self.iterations, token)


def create_vault(path: str, password: str) -> Vault:
    """Создаёт новое пустое хранилище; бросает VaultExistsError, если файл уже есть"""
    if os.path.exists(path):
        raise storage.VaultExistsError(f"Хранилище {path} уже существует")
    salt = crypto.generate_salt()
    iterations = crypto.DEFAULT_ITERATIONS
    key = crypto.derive_key(password, salt, iterations)
    vault = Vault(path, key, salt, iterations, [])
    vault.save()
    return vault


def open_vault(path: str, password: str) -> Vault:
    """Открывает хранилище; бросает FileNotFoundError, VaultCorruptedError или DecryptionError"""
    salt, iterations, token = storage.read_vault(path)
    key = crypto.derive_key(password, salt, iterations)
    plaintext = crypto.decrypt(token, key)
    entries = json.loads(plaintext.decode("utf-8"))
    return Vault(path, key, salt, iterations, entries)

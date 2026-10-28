import json
import os
from datetime import datetime

from passman import storage, crypto


def _now() -> str:
    """Текущее время в формате ISO с точностью до секунд"""
    return datetime.now().isoformat(timespec="seconds")


class EntryExistsError(Exception):
    """Запись с таким сервисом и логином уже существует"""


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

    def add_entry(self, service: str, login: str, password: str, note: str = "") -> None:
        """Добавляет запись и сохраняет хранилище; бросает EntryExistsError при дубликате"""
        for entry in self.entries:
            if entry["service"].lower() == service.lower() and entry["login"].lower() == login.lower():
                raise EntryExistsError(f"Запись {service} / {login} уже существует")
        now = _now()
        new_entry = {"service": service,
                     "login": login,
                     "password": password,
                     "note": note,
                     "created": now,
                     "updated": now}
        self.entries.append(new_entry)
        self.save()

    def find_entries(self, service: str) -> list[dict]:
        """Возвращает все записи с указанным сервисом (без учёта регистра)"""
        result = []
        for entry in self.entries:
            if entry["service"].lower() == service.lower():
                result.append(entry)
        return result

    def delete_entry(self, entry: dict) -> None:
        """Удаляет запись и сохраняет хранилище"""
        self.entries.remove(entry)
        self.save()

    def list_entries(self) -> list[dict]:
        """Возвращает записи, отсортированные по сервису и логину"""
        return sorted(self.entries, key=lambda e: (e["service"].lower(), e["login"].lower()))


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


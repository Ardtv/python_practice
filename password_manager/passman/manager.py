import json
import os
from datetime import datetime

from passman import storage, crypto


def _now() -> str:
    """Текущее время в формате ISO с точностью до секунд"""
    return datetime.now().isoformat(timespec="seconds")


class EntryExistsError(Exception):
    """Запись с таким сервисом и логином уже существует"""


class PasswordManager:
    """Менеджер паролей: создаётся заблокированным, открывается через unlock"""

    def __init__(self, path: str) -> None:
        self.path = path
        self.key: bytes | None = None
        self.salt = b""
        self.iterations = crypto.DEFAULT_ITERATIONS
        self.verifier = ""
        self.entries: list[dict] = []

    def init_master(self, password: str) -> None:
        """Создает хранилище и проверочный хэш мастер-пароля; VaultExistsError, если файл уже есть"""
        if os.path.exists(self.path):
            raise storage.VaultExistsError(f"Хранилище {self.path} уже существует")
        self.salt = crypto.generate_salt()
        self.iterations = crypto.DEFAULT_ITERATIONS
        self.key = crypto.derive_key(password, self.salt, self.iterations)
        self.verifier = crypto.make_verifier(self.key)
        self.entries = []
        self._persist()

    def unlock(self, password: str) -> bool:
        """Проверяет мастер-пароль по хэшу; True и загрузка записей, иначе False"""
        salt, iterations, verifier, token = self._load()
        key = crypto.derive_key(password, salt, iterations)
        if not crypto.check_verifier(key, verifier):
            return False
        try:
            plaintext = crypto.decrypt(token, key)
        except crypto.DecryptionError as e:
            raise storage.VaultCorruptedError("Данные хранилища повреждены") from e
        self.salt = salt
        self.iterations = iterations
        self.verifier = verifier
        self.key = key
        self.entries = json.loads(plaintext.decode("utf-8"))
        return True

    def _persist(self) -> None:
        """Шифрует записи и сохраняет хранилище на диск"""
        if self.key is None:
            raise RuntimeError("Хранилище заблокировано")
        plaintext = json.dumps(self.entries, ensure_ascii=False).encode("utf-8")
        token = crypto.encrypt(plaintext, self.key)
        storage.write_vault(self.path, self.salt, self.iterations, self.verifier, token)

    def _load(self) -> tuple[bytes, int, str, bytes]:
        """Читает заголовок и токен из файла"""
        return storage.read_vault(self.path)

    def add_entry(self, service: str, login: str, password: str, note: str = "") -> None:
        """Добавляет запись и сохраняет хранилище; бросает EntryExistsError при дубликате"""
        if self.has_entry(service, login):
            raise EntryExistsError(f"Запись {service} / {login} уже существует")
        now = _now()
        new_entry = {"service": service,
                     "login": login,
                     "password": password,
                     "note": note,
                     "created": now,
                     "updated": now}
        self.entries.append(new_entry)
        self._persist()

    def find_entries(self, service: str) -> list[dict]:
        """Возвращает все записи с указанным сервисом (без учёта регистра), отсортированные по логину"""
        result = []
        for entry in self.entries:
            if entry["service"].lower() == service.lower():
                result.append(entry)
        return sorted(result, key=lambda e: e["login"].lower())

    def delete_entry(self, entry: dict) -> None:
        """Удаляет запись и сохраняет хранилище"""
        self.entries.remove(entry)
        self._persist()

    def update_entry(self, entry: dict, login: str, password: str, note: str) -> None:
        """Изменяет запись и сохраняет хранилище; бросает EntryExistsError, если новый логин занят"""
        if self.is_login_taken(entry, login):
            raise EntryExistsError(f"Запись {entry['service']} / {login} уже существует")
        entry['login'] = login
        entry['password'] = password
        entry['note'] = note
        entry['updated'] = _now()
        self._persist()

    def list_entries(self) -> list[dict]:
        """Возвращает записи, отсортированные по сервису и логину"""
        return sorted(self.entries, key=lambda e: (e["service"].lower(), e["login"].lower()))

    def has_entry(self, service: str, login: str) -> bool:
        """Проверяет, есть ли запись с таким сервисом и логином (без учёта регистра)"""
        for entry in self.entries:
            if entry["service"].lower() == service.lower() and entry["login"].lower() == login.lower():
                return True
        return False

    def is_login_taken(self, entry: dict, login: str) -> bool:
        """Проверяет, занят ли новый логин другой записью того же сервиса"""
        return login.lower() != entry['login'].lower() and self.has_entry(entry['service'], login)

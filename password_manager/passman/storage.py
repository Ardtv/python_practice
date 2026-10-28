import json
import os
import base64

FORMAT_VERSION = 1
KDF_NAME = "pbkdf2-sha256"


class VaultExistsError(Exception):
    """При создании хранилища файл уже существует"""


class VaultCorruptedError(Exception):
    """Файл поврежден или имеет неизвестный формат"""


def write_vault(path: str, salt: bytes, iterations: int, token: bytes) -> None:
    """Атомарно записывает заголовок и токен в файл хранилища"""
    inform = {"version": FORMAT_VERSION,
              "kdf": KDF_NAME,
              "iterations": iterations,
              "salt": base64.b64encode(salt).decode("ascii"),
              "data": token.decode("ascii")
              }
    file_path = path + ".tmp"
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(inform, f, indent=2)

    os.chmod(file_path, 0o600)
    os.replace(file_path, path)


def read_vault(path: str) -> tuple[bytes, int, bytes]:
    """Читает файл хранилища; возвращает соль, число итераций и токен"""
    try:
        with open(path, "r", encoding="utf-8") as f:
            payload = json.load(f)
        if payload["version"] != FORMAT_VERSION or payload["kdf"] != KDF_NAME:
            raise VaultCorruptedError("Неподдерживаемый формат файла хранилища")
        salt = base64.b64decode(payload["salt"], validate=True)
        iterations = payload["iterations"]
        token = payload["data"].encode("ascii")
        return salt, iterations, token
    except (KeyError, ValueError, TypeError, AttributeError) as e:
        raise VaultCorruptedError(f"Файл хранилища {path} повреждён") from e

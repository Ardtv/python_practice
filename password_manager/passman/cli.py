import os
import sys
import time
import termios
from getpass import getpass

from passman import crypto, storage, vault

VAULT_PATH = "vault.dat"
MAX_ATTEMPTS = 3
MIN_PASSWORD_LENGTH = 8


def _create_new_vault() -> vault.Vault:
    """Создаёт хранилище при первом запуске: запрашивает мастер-пароль дважды"""
    print("Здравствуйте! Хранилище не найдено. Создаём новое")
    while True:
        password = getpass("Придумайте мастер-пароль: ")
        if len(password) < MIN_PASSWORD_LENGTH:
            print(f"Недостаточная длина мастер-пароля, минимальная длина: {MIN_PASSWORD_LENGTH}")
            continue
        confirm = getpass("Повторите пароль для подтверждения: ")
        if confirm != password:
            print("Пароли не совпадают")
            continue
        return vault.create_vault(VAULT_PATH, password)


def _login() -> vault.Vault:
    """Запрашивает мастер-пароль; после исчерпания попыток завершает программу"""
    for attempt in range(1, MAX_ATTEMPTS + 1):
        password = getpass("Введите мастер-пароль: ")
        try:
            return vault.open_vault(VAULT_PATH, password)
        except crypto.DecryptionError:
            remaining_attempts = MAX_ATTEMPTS - attempt
            if remaining_attempts > 0:
                print(f"Неверный пароль, осталось попыток: {remaining_attempts}")
                time.sleep(attempt)
                termios.tcflush(sys.stdin, termios.TCIFLUSH)
    print("Превышено число попыток")
    sys.exit(1)


def main() -> None:
    """Точка входа: создание или открытие хранилища"""
    try:
        if not os.path.exists(VAULT_PATH):
            v = _create_new_vault()
        else:
            v = _login()
        print(f"Хранилище открыто. Записей: {len(v.entries)}")
    except storage.VaultCorruptedError as e:
        print(f"Ошибка: {e}")
        sys.exit(1)
    except (KeyboardInterrupt, EOFError):
        print("\nВыход")
        sys.exit(0)


if __name__ == "__main__":
    main()
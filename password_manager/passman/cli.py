import cmd
import os
import sys
import termios
import time
from getpass import getpass

import pyperclip

from passman import crypto, storage, vault

VAULT_PATH = "vault.dat"
MAX_ATTEMPTS = 3
MIN_PASSWORD_LENGTH = 8
CLIPBOARD_TIMEOUT = 20


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


class Shell(cmd.Cmd):
    """Интерактивная оболочка менеджера паролей"""
    intro = "Введите help для списка команд"
    prompt = "passman> "

    def __init__(self, v: vault.Vault) -> None:
        super().__init__()
        self.vault = v

    def emptyline(self) -> None:
        pass

    def default(self, line: str) -> None:
        print(f"Неизвестная команда: {line}. Введите help")

    def do_list(self, arg: str) -> None:
        """Показать все записи (без паролей)"""
        entries = self.vault.list_entries()
        if not entries:
            print("Хранилище пусто")
            return
        for i, entry in enumerate(entries, start=1):
            print(f"{i}. {entry['service']} - {entry['login']}")

    def do_exit(self, arg: str) -> bool:
        """Выйти из программы"""
        print("До свидания")
        return True

    def do_EOF(self, arg: str) -> bool:
        """Выйти (Ctrl+D)"""
        print()
        return self.do_exit(arg)

    def do_add(self, arg: str) -> None:
        """Добавить запись: add <сервис>"""
        service = self._ask_service(arg)
        if service is None:
            return
        login = input("Логин: ").strip()
        if not login:
            print("Логин не может быть пустым")
            return
        if self.vault.has_entry(service, login):
            print(f"Запись {service} / {login} уже существует")
            return
        password = getpass("Пароль: ")
        if not password:
            print("Пароль не может быть пустым")
            return
        confirm = getpass("Повторите пароль для подтверждения: ")
        if confirm != password:
            print("Пароли не совпадают")
            return
        note = input("Заметка (необязательно): ").strip()
        try:
            self.vault.add_entry(service, login, password, note)
        except vault.EntryExistsError as e:
            print(e)
            return
        print(f"Запись добавлена: {service} - {login}")

    def _choose_entry(self, service: str) -> dict | None:
        """Находит запись по сервису; при нескольких вариантах спрашивает, какой выбрать"""
        entries = self.vault.find_entries(service)
        if not entries:
            print(f"Записи для {service} не найдены")
            return None
        elif len(entries) == 1:
            return entries[0]
        else:
            print("Найдено несколько записей:")
            for i, entry in enumerate(entries, start=1):
                print(f"{i}. {entry['login']}")
            choice = input("Номер записи: ").strip()
            if not choice.isdigit():
                print("Неверный номер")
                return None
            n = int(choice)
            if not 1 <= n <= len(entries):
                print("Неверный номер")
                return None
            return entries[n - 1]

    def _ask_service(self, arg: str) -> str | None:
        """Берёт сервис из аргумента или спрашивает; None, если пусто"""
        service = arg.strip()
        if not service:
            service = input("Сервис: ").strip()
            if not service:
                print("Сервис не может быть пустым")
                return None
        return service

    def do_get(self, arg: str) -> None:
        """Скопировать пароль в буфер: get <сервис>"""
        service = self._ask_service(arg)
        if service is None:
            return
        entry = self._choose_entry(service)
        if entry is None:
            return
        pyperclip.copy(entry['password'])
        print(f"Логин: {entry['login']}")
        if entry['note']:
            print(f"Заметка: {entry['note']}")
        print(f"Пароль скопирован в буфер обмена на {CLIPBOARD_TIMEOUT} секунд")


def main() -> None:
    """Точка входа: создание или открытие хранилища"""
    try:
        if not os.path.exists(VAULT_PATH):
            v = _create_new_vault()
        else:
            v = _login()
        print(f"Хранилище открыто. Записей: {len(v.entries)}")
        Shell(v).cmdloop()
    except storage.VaultCorruptedError as e:
        print(f"Ошибка: {e}")
        sys.exit(1)
    except (KeyboardInterrupt, EOFError):
        print("\nВыход")
        sys.exit(0)


if __name__ == "__main__":
    main()

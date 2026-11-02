"""Интерфейс командной строки: вход по мастер-паролю и интерактивное меню команд."""

import argparse
import cmd
import os
import sys
import termios
import threading
import time
from getpass import getpass

import pyperclip

from passman import generator, manager, storage

VAULT_PATH = "vault.dat"
MAX_ATTEMPTS = 3
MIN_PASSWORD_LENGTH = 8
CLIPBOARD_TIMEOUT = 20


def _create_new_vault() -> manager.PasswordManager:
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
        pm = manager.PasswordManager(VAULT_PATH)
        pm.init_master(password)
        return pm


def _login() -> manager.PasswordManager:
    """Запрашивает мастер-пароль; после исчерпания попыток завершает программу"""
    pm = manager.PasswordManager(VAULT_PATH)
    for attempt in range(1, MAX_ATTEMPTS + 1):
        password = getpass("Введите мастер-пароль: ")
        if pm.unlock(password):
            return pm
        remaining_attempts = MAX_ATTEMPTS - attempt
        if remaining_attempts > 0:
            print(f"Неверный пароль, осталось попыток: {remaining_attempts}")
            time.sleep(attempt)
            termios.tcflush(sys.stdin, termios.TCIFLUSH)
    print("Превышено число попыток")
    sys.exit(1)


def _build_parser() -> argparse.ArgumentParser:
    """Описывает аргументы командной строки"""
    parser = argparse.ArgumentParser(
        prog="password_manager.py", description="Консольный менеджер паролей"
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--init", action="store_true", help="создать хранилище и мастер-пароль")
    group.add_argument("--unlock", action="store_true", help="войти в хранилище")
    group.add_argument(
        "--generate", action="store_true", help="сгенерировать пароль без входа в хранилище"
    )
    parser.add_argument(
        "--length", type=int, default=generator.DEFAULT_LENGTH, help="длина пароля для --generate"
    )
    parser.add_argument("--no-symbols", action="store_true", help="без спецсимволов")
    parser.add_argument("--no-digits", action="store_true", help="без цифр")
    return parser


def _run_generate(args: argparse.Namespace) -> None:
    """Генерирует пароль по параметрам командной строки и печатает его"""
    try:
        password = generator.generate_password(
            args.length, use_digits=not args.no_digits, use_symbols=not args.no_symbols
        )
    except ValueError as e:
        print(f"Ошибка: {e}")
        sys.exit(1)
    print(password)


class Shell(cmd.Cmd):
    """Интерактивная оболочка менеджера паролей"""

    intro = "Введите help для списка команд"
    prompt = "passman> "

    def __init__(self, pm: manager.PasswordManager) -> None:
        super().__init__()
        self.manager = pm
        self._clipboard_timer: threading.Timer | None = None
        self._clipboard_value: str | None = None

    def emptyline(self) -> bool:
        """Пустая строка ничего не делает (по умолчанию cmd повторяет последнюю команду)"""
        return False

    def default(self, line: str) -> None:
        """При вводе некорректной команды пишет сообщение об ошибке"""
        print(f"Неизвестная команда: {line}. Введите help")

    def do_list(self, arg: str) -> None:
        """Показать все записи (без паролей)"""
        entries = self.manager.list_entries()
        if not entries:
            print("Хранилище пусто")
            return
        for i, name in enumerate(entries, start=1):
            print(f"{i}. {name}")

    def do_add(self, arg: str) -> None:
        """Добавить запись: add <сервис>"""
        service = self._ask_service(arg)
        if service is None:
            return
        login = input("Логин: ").strip()
        if not login:
            print("Логин не может быть пустым")
            return
        if self.manager.has_entry(service, login):
            print(f"Запись {service} / {login} уже существует")
            return
        password = self._ask_new_password()
        if password is None:
            return
        note = input("Заметка (необязательно): ").strip()
        try:
            self.manager.add_entry(service, login, password, note)
        except manager.EntryExistsError as e:
            print(e)
            return
        print(f"Запись добавлена: {service} / {login}")

    def do_get(self, arg: str) -> None:
        """Скопировать пароль в буфер: get <сервис>"""
        service = self._ask_service(arg)
        if service is None:
            return
        entry = self._choose_entry(service)
        if entry is None:
            return
        if not self._confirm_master():
            return
        login, pwd = self.manager.get_entry(entry["service"], entry["login"])
        self._copy_to_clipboard(pwd)
        print(f"Логин: {login}")
        if entry["note"]:
            print(f"Заметка: {entry['note']}")
        print(f"Пароль скопирован в буфер обмена на {CLIPBOARD_TIMEOUT} секунд")
        ans = input("Показать пароль на экране? [да/НЕТ]: ").strip().lower()
        if ans in ("д", "да", "y", "yes"):
            print(f"Пароль: {pwd}")

    def do_edit(self, arg: str) -> None:
        """Изменить запись: edit <сервис>"""
        service = self._ask_service(arg)
        if service is None:
            return
        entry = self._choose_entry(service)
        if entry is None:
            return
        login = input(f"Логин [{entry['login']}]: ").strip() or entry["login"]
        if self.manager.is_login_taken(entry, login):
            print(f"Запись {entry['service']} / {login} уже существует")
            return
        answer = input("Изменить пароль? [да/НЕТ]: ").strip().lower()
        if answer in ("д", "да", "y", "yes"):
            password = self._ask_new_password()
            if password is None:
                return
        else:
            password = entry["password"]
        note = input(f"Заметка [{entry['note']}] (- чтобы очистить): ").strip()
        if not note:
            note = entry["note"]
        elif note == "-":
            note = ""
        try:
            self.manager.update_entry(entry, login, password, note)
        except manager.EntryExistsError as e:
            print(e)
            return
        print(f"Запись обновлена: {entry['service']} / {entry['login']}")

    def do_delete(self, arg: str) -> None:
        """Удалить запись: delete <сервис>"""
        service = self._ask_service(arg)
        if service is None:
            return
        entry = self._choose_entry(service)
        if entry is None:
            return
        answer = input(f"Удалить {entry['service']} / {entry['login']}? [да/НЕТ]: ").strip().lower()
        if answer not in ("да", "yes", "д", "y"):
            print("Удаление отменено")
            return
        self.manager.delete_entry(entry["service"], entry["login"])
        print("Запись удалена")

    def do_exit(self, arg: str) -> bool:
        """Выйти из программы"""
        print("До свидания")
        return True

    def do_EOF(self, arg: str) -> bool:
        """Выйти (Ctrl+D)"""
        print()
        return self.do_exit(arg)

    def _confirm_master(self) -> bool:
        """Запрашивает мастер-пароль для подтверждения; False, если неверный"""
        password = getpass("Мастер-пароль для подтверждения: ")
        if not self.manager.check_password(password):
            print("Неверный мастер-пароль")
            return False
        return True

    def _ask_service(self, arg: str) -> str | None:
        """Берёт сервис из аргумента или спрашивает; None, если пусто"""
        service = arg.strip()
        if not service:
            service = input("Сервис: ").strip()
            if not service:
                print("Сервис не может быть пустым")
                return None
        return service

    def _choose_entry(self, service: str) -> manager.Entry | None:
        """Находит запись по сервису; при нескольких вариантах спрашивает, какой выбрать"""
        entries = self.manager.find_entries(service)
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

    def _ask_new_password(self) -> str | None:
        """Спрашивает новый пароль: сгенерировать или ввести вручную; None при ошибке ввода"""
        answer = input("Сгенерировать пароль? [ДА/нет]: ").lower().strip()
        if answer in ("", "д", "да", "y", "yes"):
            length_input = input(f"Длина [{generator.DEFAULT_LENGTH}]: ").strip()
            if not length_input:
                length = generator.DEFAULT_LENGTH
            elif not length_input.isdigit():
                print("Длина должна быть числом")
                return None
            else:
                length = int(length_input)
                if length < generator.MIN_LENGTH:
                    print(
                        f"Слишком маленькая длина. Минимальное количество символов - {generator.MIN_LENGTH}"
                    )
                    return None

            symbol_answer = input("Спецсимволы? [ДА/нет]: ").lower().strip()
            use_symbols = symbol_answer in ("", "д", "да", "y", "yes")
            digits_answer = input("Цифры? [ДА/нет]: ").lower().strip()
            use_digits = digits_answer in ("", "д", "да", "y", "yes")
            try:
                password = generator.generate_password(
                    length, use_digits=use_digits, use_symbols=use_symbols
                )
            except ValueError as e:
                print(e)
                return None
            self._copy_to_clipboard(password)
            print(f"Пароль сгенерирован и скопирован на {CLIPBOARD_TIMEOUT} секунд в буфер обмена")
        else:
            password = getpass("Пароль: ")
            if not password:
                print("Пароль не может быть пустым")
                return None
            confirm = getpass("Повторите пароль для подтверждения: ")
            if confirm != password:
                print("Пароли не совпадают")
                return None
        return password

    def _copy_to_clipboard(self, password: str) -> None:
        """Переносит пароль и запускает таймер автоочистки без вывода"""
        if self._clipboard_timer is not None:
            self._clipboard_timer.cancel()
        pyperclip.copy(password)
        self._clipboard_value = password
        timer = threading.Timer(CLIPBOARD_TIMEOUT, self._clear_clipboard)
        timer.daemon = True
        timer.start()
        self._clipboard_timer = timer

    def _clear_clipboard(self) -> None:
        """Очищает буфер, если там еще есть пароль"""
        if self._clipboard_value is not None and pyperclip.paste() == self._clipboard_value:
            pyperclip.copy("")
        self._clipboard_value = None

    def close(self) -> None:
        """Отменяет таймер и очищает буфер при выходе"""
        if self._clipboard_timer is not None:
            self._clipboard_timer.cancel()
        self._clear_clipboard()


def main(argv: list[str] | None = None) -> None:
    """Точка входа: разбор аргументов, создание или открытие хранилища"""
    args = _build_parser().parse_args(argv)
    if args.generate:
        _run_generate(args)
        return
    try:
        if args.init:
            if os.path.exists(VAULT_PATH):
                print("Хранилище уже существует. Войдите: python password_manager.py --unlock")
                sys.exit(1)
            pm = _create_new_vault()
        elif args.unlock:
            if not os.path.exists(VAULT_PATH):
                print("Хранилище не найдено. Создайте его: python password_manager.py --init")
                sys.exit(1)
            pm = _login()
        else:
            if not os.path.exists(VAULT_PATH):
                pm = _create_new_vault()
            else:
                pm = _login()
        print(f"Хранилище открыто. Записей: {len(pm.entries)}")
        shell = Shell(pm)
        try:
            shell.cmdloop()
        finally:
            shell.close()
    except (storage.VaultExistsError, storage.VaultCorruptedError) as e:
        print(f"Ошибка: {e}")
        sys.exit(1)
    except (KeyboardInterrupt, EOFError):
        print("\nВыход")
        sys.exit(0)


if __name__ == "__main__":
    main()

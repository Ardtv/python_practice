"""Тесты PasswordManager"""

import pytest

from passman import storage
from passman.manager import EntryNotFoundError, PasswordManager
from conftest import MASTER


def test_unlock_correct_password(pm: PasswordManager, vault_path: str) -> None:
    """unlock с верным паролем возвращает True"""
    other = PasswordManager(vault_path)
    assert other.unlock(MASTER) is True


def test_unlock_wrong_password(pm: PasswordManager, vault_path: str) -> None:
    """unlock с неверным паролем возвращает False"""
    other = PasswordManager(vault_path)
    assert other.unlock("wrong-password") is False
    assert other.key is None


def test_init_twice_raises(pm: PasswordManager) -> None:
    """Повторная инициализация не перезаписывает хранилище"""
    with pytest.raises(storage.VaultExistsError):
        pm.init_master("another-password")


def test_add_list_get(pm: PasswordManager) -> None:
    """add добавляет запись: list показывает имя, get возвращает логин и пароль"""
    pm.add_entry("github", "ard", "secret-pass")
    assert "github / ard" in pm.list_entries()
    assert pm.get_entry("github") == ("ard", "secret-pass")


def test_delete_remove_entry(pm: PasswordManager) -> None:
    """delete удаляет запись"""
    pm.add_entry("github", "asd", "111")
    pm.delete_entry("github")
    assert pm.list_entries() == []


def test_secrets_not_stored_in_plain_text(pm: PasswordManager, vault_path: str) -> None:
    """Пароли, мастер-пароль и названия не хранятся в файле открыто"""
    pm.add_entry("gmail", "abc", "VerySecret123")
    with open(vault_path, encoding="utf-8") as f:
        text = f.read()
    assert "VerySecret123" not in text
    assert MASTER not in text
    assert "gmail" not in text


def test_data_persists_after_reopen(pm: PasswordManager, vault_path: str) -> None:
    """Записи сохраняются в файл и читаются после повторного входа"""
    pm.add_entry("github", "aab", "123123")
    other = PasswordManager(vault_path)
    assert other.unlock(MASTER) is True
    assert other.get_entry("github") == ("aab", "123123")


def test_get_entry_ambiguous_and_missing(pm: PasswordManager) -> None:
    """get_entry: неоднозначный сервис и несуществующая запись дают EntryNotFoundError"""
    pm.add_entry("github", "ard", "p1")
    pm.add_entry("github", "work", "p2")
    with pytest.raises(EntryNotFoundError):
        pm.get_entry("github")
    with pytest.raises(EntryNotFoundError):
        pm.get_entry("insta")
    assert pm.get_entry("github", "work") == ("work", "p2")


def test_corrupted_file_raises(vault_path: str) -> None:
    with open(vault_path, "w", encoding="utf-8") as f:
        f.write("not json")
    with pytest.raises(storage.VaultCorruptedError):
        PasswordManager(vault_path).unlock(MASTER)

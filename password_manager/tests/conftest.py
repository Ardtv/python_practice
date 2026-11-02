"""Общие фикстуры тестов"""

from pathlib import Path

import pytest

from passman import crypto
from passman.manager import PasswordManager

MASTER = "correct-master-password"


@pytest.fixture(autouse=True)
def fast_kdf(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ускоряет KDF в тестах: 1000 итераций вместо 600 000"""
    monkeypatch.setattr(crypto, "DEFAULT_ITERATIONS", 1000)


@pytest.fixture
def vault_path(tmp_path: Path) -> str:
    """Путь к файлу хранилища во временной папке теста"""
    return str(tmp_path / "vault.dat")


@pytest.fixture
def pm(vault_path: str) -> PasswordManager:
    """Готовое хранилище с мастер-паролем MASTER"""
    manager = PasswordManager(vault_path)
    manager.init_master(MASTER)
    return manager

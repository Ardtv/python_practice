"""Тесты генератора паролей"""

import string

import pytest

from passman.generator import generate_password


def test_password_length_and_classes() -> None:
    """Пароль нужной длины и содержит все классы символов"""
    password = generate_password(20)
    assert len(password) == 20
    assert any(c in string.digits for c in password)
    assert any(c in string.ascii_lowercase for c in password)
    assert any(c in string.ascii_uppercase for c in password)


def test_password_without_digits_and_symbols() -> None:
    """Без цифр и спецсимволов пароль состоит только из букв"""
    password = generate_password(12, use_digits=False, use_symbols=False)
    assert len(password) == 12
    assert password.isalpha()


def test_too_short_raises() -> None:
    """Длина меньше минимальной даёт ValueError"""
    with pytest.raises(ValueError):
        generate_password(5)

import secrets
import string

DEFAULT_LENGTH = 20
MIN_LENGTH = 8
SYMBOLS = "!@#$%^&*()_-+=.,;:?~"


def generate_password(length: int = DEFAULT_LENGTH, use_digits: bool = True, use_symbols: bool = True) -> str:
    """Генерирует случайный пароль из secrets; гарантирует хотя бы один символ каждого выбранного набора"""
    groups = [string.ascii_lowercase, string.ascii_uppercase]
    if use_digits:
        groups.append(string.digits)
    if use_symbols:
        groups.append(SYMBOLS)
    if length < MIN_LENGTH:
        raise ValueError(f"Слишком маленькая длина. Минимальное количество символов - {MIN_LENGTH}")
    chars = [secrets.choice(g) for g in groups]
    alphabet = "".join(groups)
    for _ in range(length - len(chars)):
        chars.append(secrets.choice(alphabet))
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)

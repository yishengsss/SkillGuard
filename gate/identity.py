"""Identity components accepted consistently by publishing and installation."""
import unicodedata


def safe_identity_component(value: str, max_bytes: int) -> str | None:
    if not isinstance(value, str) or not value or value != value.strip() or value in ('.', '..'):
        return None
    if '/' in value or '\\' in value or any(unicodedata.category(c).startswith('C') for c in value):
        return None
    try:
        if len(value.encode('utf-8')) > max_bytes:
            return None
    except UnicodeError:
        return None
    return value

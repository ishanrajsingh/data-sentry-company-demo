import base64
import binascii
import re
import unicodedata
from urllib.parse import unquote


_CONFUSABLES = str.maketrans(
    {
        "А": "A", "а": "a", "В": "B", "Е": "E", "е": "e", "К": "K", "М": "M",
        "Н": "H", "О": "O", "о": "o", "Р": "P", "р": "p", "С": "C", "с": "c",
        "Т": "T", "Х": "X", "х": "x", "І": "I", "і": "i", "Ј": "J", "ј": "j",
    }
)
_CHAT_DELIMITERS = re.compile(
    r"<\|(?:im_start|im_end|system|assistant|user)\|>|\[/?INST\]|<<\/?SYS>>|(?:^|\n)(?:Human|Assistant):",
    re.IGNORECASE,
)
_BASE64_CANDIDATE = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{24,}={0,2}(?![A-Za-z0-9+/=_-])")
_HEX_CANDIDATE = re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{32,}(?![A-Fa-f0-9])")


def normalize_text(text: str) -> str:
    normalized = unicodedata.normalize("NFKC", text or "").translate(_CONFUSABLES)
    normalized = "".join(char for char in normalized if unicodedata.category(char) not in {"Cf", "Mn"})
    return _CHAT_DELIMITERS.sub(" ", normalized)


def inspection_variants(text: str, max_decoded_bytes: int = 4096) -> list[str]:
    normalized = normalize_text(text)
    variants = [normalized]
    url_decoded = normalize_text(unquote(normalized))
    if url_decoded != normalized:
        variants.append(url_decoded)

    for candidate in _BASE64_CANDIDATE.findall(normalized):
        if len(candidate) > ((max_decoded_bytes + 2) // 3) * 4 + 4:
            continue
        try:
            encoded = candidate.replace("-", "+").replace("_", "/")
            encoded += "=" * (-len(encoded) % 4)
            decoded = base64.b64decode(encoded, validate=True)
            if len(decoded) <= max_decoded_bytes:
                variants.append(normalize_text(decoded.decode("utf-8")))
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue

    for candidate in _HEX_CANDIDATE.findall(normalized):
        if len(candidate) % 2 or len(candidate) > max_decoded_bytes * 2:
            continue
        try:
            decoded = bytes.fromhex(candidate)
            variants.append(normalize_text(decoded.decode("utf-8")))
        except (UnicodeDecodeError, ValueError):
            continue
    return variants
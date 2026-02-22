"""Helpers for masking PII in metadata/log structures."""

from __future__ import annotations

import re


def _mask_email(value: str) -> str:
    if "@" not in value:
        return "[REDACTED:EMAIL_ADDRESS]"
    local, domain = value.split("@", 1)
    if not local:
        return f"***@{domain}"
    return f"{local[0]}***@{domain}"


def _mask_digits(value: str, keep_last: int = 4) -> str:
    digits = re.sub(r"\D", "", value)
    if not digits:
        return "[REDACTED]"
    if len(digits) <= keep_last:
        return "*" * len(digits)
    return f"{'*' * (len(digits) - keep_last)}{digits[-keep_last:]}"


def mask_pii_value(entity_type: str, value: str) -> str:
    """Mask raw entity text so metadata does not leak PII."""
    if not value:
        return ""

    kind = entity_type.upper()
    if kind == "EMAIL_ADDRESS":
        return _mask_email(value)
    if kind in {"CREDIT_CARD", "US_SSN", "PHONE_NUMBER", "POLISH_PESEL", "POLISH_NIP", "IBAN_CODE"}:
        return _mask_digits(value, keep_last=4)
    if kind == "IP_ADDRESS":
        parts = value.split(".")
        if len(parts) == 4:
            return ".".join(parts[:3] + ["xxx"])
        return "[REDACTED:IP_ADDRESS]"
    if kind == "CRYPTO":
        clean = value.strip()
        if len(clean) <= 8:
            return "****"
        return f"{clean[:4]}...{clean[-4:]}"

    compact = value.strip()
    if len(compact) <= 4:
        return "*" * len(compact)
    return f"{compact[0]}***{compact[-1]}"


def build_entity_text_fields(
    entity_type: str,
    raw_text: str,
    include_debug_raw: bool = False,
) -> dict[str, str]:
    """
    Build entity text payload fields.

    Always masks `text`. Optionally includes `debug_raw_text` for controlled debugging.
    """
    payload = {"text": mask_pii_value(entity_type, raw_text)}
    if include_debug_raw:
        payload["debug_raw_text"] = raw_text
    return payload

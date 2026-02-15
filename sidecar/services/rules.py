from ..models import Decision


def keyword_guard(text: str, blocked: list[str]) -> Decision:
    text_lower = text.lower()
    for phrase in blocked:
        if phrase.lower() in text_lower:
            return Decision(allowed=False, reason=f"blocked: {phrase.lower()}")
    return Decision(allowed=True, reason="clean")

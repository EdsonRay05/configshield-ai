"""Backend-only settings; process environment overrides the local .env file."""
import os
from pathlib import Path
from dataclasses import dataclass, field

FREE_MODEL = "gemini-3.1-flash-lite"
FREE_TIER_REVIEWED_ON = "2026-11-17"
ENV_FILE = Path(__file__).resolve().parents[1] / ".env"


def local_settings():
    allowed = {"AI_PROVIDER", "GEMINI_MODEL", "GEMINI_API_KEY", "GEMINI_FREE_TIER_CONFIRMED"}
    try:
        lines = ENV_FILE.read_text(encoding="utf-8-sig").splitlines()
    except (OSError, UnicodeError):
        return {}
    values = {}
    for line in lines:
        name, separator, value = line.strip().partition("=")
        if separator and name.strip() in allowed:
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
                value = value[1:-1]
            values[name.strip()] = value
    return values


@dataclass(frozen=True)
class AISettings:
    provider: str = "mock"
    model: str = FREE_MODEL
    api_key: str = field(default="", repr=False)
    free_tier_confirmed: bool = False


def get_ai_settings() -> AISettings:
    values = local_settings()
    def setting(name, default):
        return os.environ.get(name, values.get(name, default))
    return AISettings(
        provider=setting("AI_PROVIDER", "mock"),
        model=setting("GEMINI_MODEL", FREE_MODEL),
        api_key=setting("GEMINI_API_KEY", ""),
        free_tier_confirmed=setting("GEMINI_FREE_TIER_CONFIRMED", "false").lower() == "true",
    )

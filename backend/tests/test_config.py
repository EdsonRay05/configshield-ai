"""Local startup configuration without live requests or real credentials."""
from app import config
from app.services.ai_provider import ai_status


def clear_settings(monkeypatch):
    for name in ("AI_PROVIDER", "GEMINI_MODEL", "GEMINI_API_KEY", "GEMINI_FREE_TIER_CONFIRMED"):
        monkeypatch.delenv(name, raising=False)


def test_local_file_enables_configured_gemini_without_generation(monkeypatch):
    clear_settings(monkeypatch)
    config.ENV_FILE.write_text('AI_PROVIDER=gemini\nGEMINI_API_KEY="AQ.test-placeholder"\nGEMINI_FREE_TIER_CONFIRMED=true\n', encoding="utf-8")
    settings = config.get_ai_settings()
    assert settings.api_key == "AQ.test-placeholder"
    assert ai_status()["gemini_ready"] is True
    assert settings.api_key not in repr(settings)
    assert settings.api_key not in str(ai_status())


def test_environment_overrides_file_and_missing_confirmation_stays_disabled(monkeypatch):
    clear_settings(monkeypatch)
    config.ENV_FILE.write_text('AI_PROVIDER=gemini\nGEMINI_API_KEY=AQ.test-placeholder\n', encoding="utf-8")
    assert ai_status()["gemini_ready"] is False
    monkeypatch.setenv("AI_PROVIDER", "mock")
    assert config.get_ai_settings().provider == "mock"


def test_no_file_keeps_mock_default(monkeypatch):
    clear_settings(monkeypatch)
    assert config.get_ai_settings().provider == "mock"

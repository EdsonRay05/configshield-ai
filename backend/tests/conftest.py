"""Never read a developer's saved credentials during automated tests."""
import pytest
from app import config


@pytest.fixture(autouse=True)
def isolate_local_ai_settings(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "ENV_FILE", tmp_path / ".env")

# test/test_config.py
import os
from mpierce.config import Settings


def test_settings_defaults(monkeypatch):
    for var in ("LLM_PROVIDER", "LLM_MODEL_ID", "LLM_TEMPERATURE"):
        monkeypatch.delenv(var, raising=False)
    s = Settings.from_env()
    assert s.provider == "bedrock"
    assert s.model_id == "qwen.qwen3-next-80b-a3b"
    assert s.temperature == 0.2


def test_settings_from_env(monkeypatch):
    monkeypatch.setenv("LLM_MODEL_ID", "us.anthropic.claude-3-5-haiku-20241022-v1:0")
    monkeypatch.setenv("LLM_TEMPERATURE", "0.7")
    s = Settings.from_env()
    assert "claude" in s.model_id
    assert s.temperature == 0.7

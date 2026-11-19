"""Pinned artifact checks, CLI contracts, and real offline schema validation."""
import hashlib
import json
from pathlib import Path
import subprocess

import pytest
import yaml

from app.services import kubeconform_validator as validator

SAMPLE = Path(__file__).resolve().parents[2] / "samples" / "insecure-deployment.yaml"
REAL_TOOLS_AVAILABLE = validator.EXECUTABLE.is_file() and validator.SCHEMA_PATH.is_file()


def output(status="statusValid", counts=(1, 0, 0, 0), name="insecure-demo"):
    return json.dumps({"resources": [{"kind": "Deployment", "version": "apps/v1", "name": name,
                                     "status": status, "msg": "private raw manifest value"}],
                       "summary": dict(zip(("valid", "invalid", "errors", "skipped"), counts))})


@pytest.fixture
def artifacts(monkeypatch, tmp_path):
    binary, schema, lock = (tmp_path / name for name in ("kubeconform.exe", "schema.json", "lock.json"))
    binary.write_bytes(b"controlled binary")
    schema.write_bytes(b"{}")
    lock.write_text(json.dumps({"version": "v0.8.0", "kubernetes_version": "1.35.0",
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "schema_sha256": hashlib.sha256(schema.read_bytes()).hexdigest()}), encoding="utf-8")
    monkeypatch.setattr(validator, "EXECUTABLE", binary)
    monkeypatch.setattr(validator, "SCHEMA_PATH", schema)
    monkeypatch.setattr(validator, "LOCK_PATH", lock)
    return binary, schema, lock


@pytest.mark.parametrize("report,code,status", [
    (output(), 0, "passed"), (output("statusInvalid", (0, 1, 0, 0)), 1, "failed"),
    (output("statusSkipped", (0, 0, 0, 1)), 0, "unavailable"),
    (output("statusError", (0, 0, 1, 0)), 1, "unavailable"),
    ("bad JSON", 0, "unavailable"), ("{}", 0, "unavailable"),
    (output(name="another-resource"), 0, "unavailable"),
    (output(), 1, "unavailable"), (output("statusInvalid", (0, 1, 0, 0)), 0, "unavailable"),
    (output(counts=(0, 0, 0, 0)), 0, "unavailable"),
])
def test_schema_reports_never_confuse_failure_or_missing_checks_with_pass(report, code, status):
    result = validator.normalize_schema_report(report, code, "insecure-demo")
    assert result.status == status
    assert "private raw" not in result.message


@pytest.mark.parametrize("fault", ["binary_missing", "schema_missing", "binary_changed", "schema_changed", "lock_missing", "lock_invalid"])
def test_missing_or_changed_artifacts_never_pass(artifacts, fault):
    binary, schema, lock = artifacts
    if fault == "binary_missing": binary.unlink()
    elif fault == "schema_missing": schema.unlink()
    elif fault == "binary_changed": binary.write_bytes(b"changed")
    elif fault == "schema_changed": schema.write_bytes(b"changed")
    elif fault == "lock_missing": lock.unlink()
    elif fault == "lock_invalid": lock.write_text("{}", encoding="utf-8")
    assert validator.validate_schema(SAMPLE.read_bytes(), "insecure-demo").status == "unavailable"


@pytest.mark.parametrize("failure", [None, "timeout", "os_error", "invalid_output"])
def test_fixed_local_command_timeout_environment_and_cleanup(monkeypatch, artifacts, failure):
    observed = []
    monkeypatch.setenv("GEMINI_API_KEY", "private-key")
    monkeypatch.setenv("HTTPS_PROXY", "https://untrusted-proxy.invalid")
    def run(command, **kwargs):
        directory = Path(kwargs["cwd"])
        observed.append(directory)
        assert (directory / "candidate.yaml").read_bytes() == SAMPLE.read_bytes()
        assert command[0] == str(artifacts[0])
        assert command[command.index("-schema-location") + 1] == str(artifacts[1])
        assert "default" not in command and "-ignore-missing-schemas" not in command
        assert "-strict" in command and "-verbose" in command
        assert kwargs["timeout"] == 20 and kwargs["shell"] is False
        assert "GEMINI_API_KEY" not in kwargs["env"] and "HTTPS_PROXY" not in kwargs["env"]
        if failure == "timeout": raise subprocess.TimeoutExpired(command, 20)
        if failure == "os_error": raise OSError("private diagnostics")
        return subprocess.CompletedProcess(command, 0, "invalid" if failure else output(), "private diagnostics")
    monkeypatch.setattr(validator.subprocess, "run", run)
    result = validator.validate_schema(SAMPLE.read_bytes(), "insecure-demo")
    assert result.status == ("passed" if failure is None else "unavailable")
    assert observed and not observed[0].exists()
    assert "private" not in result.message


@pytest.mark.skipif(not REAL_TOOLS_AVAILABLE, reason="Run tools/install-kubeconform.ps1 for real offline schema integration")
@pytest.mark.parametrize("invalid", [False, True])
def test_real_offline_kubeconform(invalid):
    manifest = yaml.safe_load(SAMPLE.read_bytes())
    if invalid:
        manifest["spec"]["template"]["spec"]["containers"][0]["unknownProperty"] = "private-value"
    result = validator.validate_schema(yaml.safe_dump(manifest).encode(), "insecure-demo")
    assert result.status == ("failed" if invalid else "passed")
    assert result.kubernetes_version == "1.35.0"

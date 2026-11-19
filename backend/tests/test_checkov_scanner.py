"""CLI boundary tests and real scanner checks against controlled samples."""
import json
from pathlib import Path
import subprocess

from fastapi.testclient import TestClient
import pytest
import yaml

from app.main import app
from app.services import checkov_scanner as scanner
from app.services.yaml_parser import ManifestError, parse_deployment

SAMPLES = Path(__file__).resolve().parents[2] / "samples"
CONTENT = (SAMPLES / "insecure-deployment.yaml").read_bytes()


def report(failed=(), skipped=()):
    groups = {"passed_checks": [], "failed_checks": [], "skipped_checks": [], "parsing_errors": []}
    for check_id in scanner.SUPPORTED_CHECKS:
        group, status = ("failed_checks", "FAILED") if check_id in failed else (
            ("skipped_checks", "SKIPPED") if check_id in skipped else ("passed_checks", "PASSED"))
        groups[group].append({
            "check_id": check_id, "check_name": "A real scanner description",
            "resource": "Deployment.default.insecure-demo",
            "check_result": {"result": status, "evaluated_keys": ["spec/template/spec"]},
            "file_line_range": [2, 28], "code_block": [[1, "secret-not-returned"]],
            "file_abs_path": "private-temp-path",
        })
    return {"check_type": "kubernetes", "results": groups, "summary": {
        "passed": len(groups["passed_checks"]), "failed": len(groups["failed_checks"]),
        "skipped": len(groups["skipped_checks"]), "parsing_errors": 0, "checkov_version": "3.4.5",
    }}


def normalize(data, code=0):
    return scanner.normalize_report(json.dumps(data), code, parse_deployment(CONTENT, "demo.yaml"))


def test_exit_one_is_findings_not_execution_failure():
    result = normalize(report(failed=("CKV_K8S_16",)), 1)
    assert result.status == "completed"
    assert result.findings[0].check_id == "CKV_K8S_16"
    assert result.findings[0].category == "privileged_container"
    assert len(result.passed_checks) == 6
    assert "secret-not-returned" not in result.model_dump_json()
    assert "private-temp-path" not in result.model_dump_json()


def test_no_findings_and_single_report_list():
    result = normalize([report()])
    assert result.status == "completed"
    assert result.findings == []
    assert len(result.passed_checks) == 7


def test_suppression_is_incomplete_not_pass():
    result = normalize(report(skipped=("CKV_K8S_16",)))
    assert result.status == "incomplete"
    assert result.skipped_checks == ["CKV_K8S_16"]
    assert "CKV_K8S_16" not in result.passed_checks


@pytest.mark.parametrize("case", ["empty", "wrong_framework", "missing_check", "duplicate", "wrong_resource", "parse_errors", "bad_count", "wrong_status", "wrong_keys", "no_version", "wrong_exit", "unexpected_id"])
def test_invalid_reports_are_not_success(case):
    data = report(failed=("CKV_K8S_16",))
    code = 1
    if case == "empty":
        data = {}
    elif case == "wrong_framework":
        data["check_type"] = "terraform"
    elif case == "missing_check":
        data["results"]["passed_checks"].pop()
        data["summary"]["passed"] -= 1
    elif case == "duplicate":
        data["results"]["passed_checks"][0]["check_id"] = "CKV_K8S_16"
    elif case == "wrong_resource":
        data["results"]["failed_checks"][0]["resource"] = "Deployment.default.other"
    elif case == "parse_errors":
        data["results"]["parsing_errors"] = ["input.yaml"]
    elif case == "bad_count":
        data["summary"]["passed"] = 0
    elif case == "wrong_status":
        data["results"]["failed_checks"][0]["check_result"]["result"] = "PASSED"
    elif case == "wrong_keys":
        data["results"]["failed_checks"][0]["check_result"]["evaluated_keys"] = "wrong"
    elif case == "no_version":
        del data["summary"]["checkov_version"]
    elif case == "wrong_exit":
        code = 0
    elif case == "unexpected_id":
        data["results"]["passed_checks"][0]["check_id"] = "CKV_K8S_99999"
    with pytest.raises(scanner.ScannerError) as error:
        normalize(data, code)
    assert error.value.code == "scanner_invalid_output"


@pytest.mark.parametrize("output,code,expected", [("not JSON", 0, "scanner_invalid_output"), ("{}", 2, "scanner_execution_failed"), ("{}", -1, "scanner_execution_failed")])
def test_unusable_process_output(output, code, expected):
    with pytest.raises(scanner.ScannerError) as error:
        scanner.normalize_report(output, code, parse_deployment(CONTENT, "x.yaml"))
    assert error.value.code == expected


@pytest.fixture
def installed_scanner(monkeypatch, tmp_path):
    executable = tmp_path / "checkov.exe"
    executable.touch()
    monkeypatch.setattr(scanner, "SCANNER_EXECUTABLE", executable)
    return executable


@pytest.mark.parametrize("failure", [None, "timeout", "os_error", "invalid_json"])
def test_fixed_command_and_temporary_cleanup(monkeypatch, installed_scanner, failure):
    observed = []
    monkeypatch.setenv("BC_API_KEY", "must-not-inherit")
    monkeypatch.setenv("CKV_SKIP_CHECK", "CKV_K8S_16")
    monkeypatch.setenv("PYTHONPATH", "untrusted-module-location")

    def fake_run(command, **kwargs):
        directory = Path(kwargs["cwd"])
        observed.append(directory)
        assert (directory / "deployment.yaml").read_bytes() == CONTENT
        assert str(scanner.SCANNER_PYTHON) == command[0]
        assert str(installed_scanner) == command[1]
        assert command[command.index("--framework") + 1] == "kubernetes"
        assert command[command.index("--check") + 1] == ",".join(scanner.SUPPORTED_CHECKS)
        assert "--skip-download" in command
        assert "--quiet" not in command
        assert kwargs["shell"] is False
        assert kwargs["timeout"] == 60
        assert not {"BC_API_KEY", "CKV_SKIP_CHECK", "PYTHONPATH"} & set(kwargs["env"])
        if failure == "timeout":
            raise subprocess.TimeoutExpired(command, 60)
        if failure == "os_error":
            raise OSError("private diagnostics")
        return subprocess.CompletedProcess(command, 0, stdout="invalid" if failure else json.dumps(report()), stderr="private diagnostics")

    monkeypatch.setattr(scanner.subprocess, "run", fake_run)
    if failure:
        with pytest.raises(scanner.ScannerError) as error:
            scanner.scan_deployment(CONTENT, "uploaded.yaml")
        assert "private diagnostics" not in str(error.value)
    else:
        assert scanner.scan_deployment(CONTENT, "uploaded.yaml").status == "completed"
    assert observed and not observed[0].exists()
    # A failure must not leave the scanner slot locked.
    assert scanner._scan_slot.acquire(blocking=False)
    scanner._scan_slot.release()


def test_missing_tool_and_reject_before_process(monkeypatch, tmp_path):
    monkeypatch.setattr(scanner, "SCANNER_EXECUTABLE", tmp_path / "absent")
    with pytest.raises(scanner.ScannerError) as error:
        scanner.scan_deployment(CONTENT, "x.yaml")
    assert error.value.code == "scanner_not_installed"
    with pytest.raises(ManifestError):
        scanner.scan_deployment(b"kind: Pod", "x.yaml")


def test_busy_scanner(installed_scanner):
    scanner._scan_slot.acquire()
    try:
        with pytest.raises(scanner.ScannerError) as error:
            scanner.scan_deployment(CONTENT, "x.yaml")
        assert error.value.code == "scanner_busy"
    finally:
        scanner._scan_slot.release()


def test_scan_endpoint_error_and_findings(monkeypatch, installed_scanner):
    monkeypatch.setattr(scanner.subprocess, "run", lambda *args, **kwargs: subprocess.CompletedProcess([], 1, json.dumps(report(failed=("CKV_K8S_16",))), ""))
    with TestClient(app) as client:
        response = client.post("/api/scan?filename=x.yaml", content=CONTENT)
        assert response.status_code == 200
        assert response.json()["findings"][0]["check_id"] == "CKV_K8S_16"
        invalid = client.post("/api/scan?filename=x.yaml", content=b"kind: Pod")
        assert invalid.status_code == 422
        assert client.post("/api/scan?filename=x.yaml", content=b"x" * (256 * 1024 + 1)).status_code == 413
        monkeypatch.setattr(scanner, "SCANNER_EXECUTABLE", Path("absent-scanner"))
        missing = client.post("/api/scan?filename=x.yaml", content=CONTENT)
        assert missing.status_code == 503
        assert missing.json()["error"]["code"] == "scanner_not_installed"


@pytest.mark.skipif(not scanner.SCANNER_EXECUTABLE.is_file(), reason="Install scanner-requirements.txt for real CLI integration tests")
@pytest.mark.parametrize("sample,expected_failures", [("insecure-deployment.yaml", set(scanner.SUPPORTED_CHECKS)), ("secure-deployment.yaml", set())])
def test_real_checkov_samples(sample, expected_failures):
    content = (SAMPLES / sample).read_bytes()
    result = scanner.scan_deployment(content, sample)
    assert result.scanner_version == "3.4.5"
    assert result.status == "completed"
    assert {finding.check_id for finding in result.findings} == expected_failures
    assert len(result.passed_checks) + len(result.findings) == 7
    assert (SAMPLES / sample).read_bytes() == content


@pytest.mark.skipif(not scanner.SCANNER_EXECUTABLE.is_file(), reason="Install scanner-requirements.txt for real CLI integration tests")
def test_real_suppression_through_api():
    manifest = yaml.safe_load(CONTENT)
    manifest["metadata"]["annotations"] = {"checkov.io/skip1": "CKV_K8S_16=Controlled suppression test"}
    with TestClient(app) as client:
        response = client.post("/api/scan?filename=suppressed.yaml", content=yaml.safe_dump(manifest).encode())
    assert response.status_code == 200
    result = response.json()
    assert result["status"] == "incomplete"
    assert result["skipped_checks"] == ["CKV_K8S_16"]
    assert "CKV_K8S_16" not in result["passed_checks"]
    assert len(result["findings"]) == 6
    for finding in result["findings"]:
        assert finding["guidance"]["status"] == "available"
        assert finding["guidance"]["documents"]

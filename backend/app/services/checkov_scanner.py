"""Run the isolated Checkov CLI and accept only complete, expected reports."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading

from app.schemas import ScanResponse, SecurityFinding
from app.services.yaml_parser import parse_deployment

CHECK_CATEGORIES = {
    "CKV_K8S_16": "privileged_container",
    "CKV_K8S_20": "privilege_escalation",
    "CKV_K8S_23": "non_root",
    "CKV_K8S_28": "net_raw_capability",
    "CKV_K8S_31": "seccomp",
    "CKV_K8S_37": "capabilities",
    "CKV_K8S_38": "service_account_token",
}
SUPPORTED_CHECKS = tuple(CHECK_CATEGORIES)
SCANNER_TIMEOUT_SECONDS = 60
BACKEND_DIR = Path(__file__).resolve().parents[2]
SCANNER_EXECUTABLE = BACKEND_DIR / ".scanner-venv" / (
    "Scripts/checkov" if os.name == "nt" else "bin/checkov"
)
SCANNER_PYTHON = BACKEND_DIR / ".scanner-venv" / (
    "Scripts/python.exe" if os.name == "nt" else "bin/python"
)
_scan_slot = threading.BoundedSemaphore(1)


class ScannerError(RuntimeError):
    def __init__(self, code: str, message: str, status_code: int = 503):
        super().__init__(message)
        self.code = code
        self.status_code = status_code


def invalid_report():
    return ScannerError("scanner_invalid_output", "Checkov returned an incomplete or unexpected report. No successful scan is claimed.", 502)


def normalize_report(output: str, returncode: int, parsed) -> ScanResponse:
    """Convert JSON to safe metadata without returning code blocks or temp paths."""
    # Checkov normally returns 1 for findings; it is not an execution failure.
    if returncode not in (0, 1):
        raise ScannerError("scanner_execution_failed", "Checkov could not complete the scan.", 502)
    try:
        report = json.loads(output)
        if isinstance(report, list):
            if len(report) != 1:
                raise ValueError
            report = report[0]
        if not isinstance(report, dict) or report.get("check_type") != "kubernetes":
            raise ValueError
        results = report["results"]
        summary = report["summary"]
        if results.get("parsing_errors") or summary.get("parsing_errors", 0):
            raise ValueError
        version = summary["checkov_version"]
        if not isinstance(version, str) or not version:
            raise ValueError
        groups = {name: results[name] for name in ("passed_checks", "failed_checks", "skipped_checks")}
        for name, count_key in (("passed_checks", "passed"), ("failed_checks", "failed"), ("skipped_checks", "skipped")):
            if not isinstance(groups[name], list) or summary[count_key] != len(groups[name]):
                raise ValueError
        seen = set()
        findings = []
        ids = {name: [] for name in groups}
        expected_resource = f"Deployment.{parsed.deployment.namespace}.{parsed.deployment.name}"
        for name, records in groups.items():
            for record in records:
                check_id = record["check_id"]
                if check_id not in SUPPORTED_CHECKS or check_id in seen or record["resource"] != expected_resource:
                    raise ValueError
                seen.add(check_id)
                ids[name].append(check_id)
                expected_status = {"passed_checks": "PASSED", "failed_checks": "FAILED", "skipped_checks": "SKIPPED"}[name]
                if record["check_result"]["result"] != expected_status:
                    raise ValueError
                if name == "failed_checks":
                    description = record["check_name"]
                    lines = record.get("file_line_range") or []
                    keys = record["check_result"].get("evaluated_keys") or []
                    if not isinstance(description, str) or not description:
                        raise ValueError
                    if not isinstance(lines, list) or any(type(line) is not int for line in lines):
                        raise ValueError
                    if not isinstance(keys, list) or any(not isinstance(key, str) for key in keys):
                        raise ValueError
                    findings.append(SecurityFinding(
                        check_id=check_id, description=description,
                        category=CHECK_CATEGORIES[check_id], resource=expected_resource,
                        line_range=lines, evaluated_keys=keys,
                    ))
        if seen != set(SUPPORTED_CHECKS):
            raise ValueError
        if returncode == 0 and findings:
            # We do not request --soft-fail; unexpected exit policy is suspect.
            raise ValueError
        if returncode == 1 and not findings:
            raise ValueError
    except (ValueError, KeyError, TypeError, AttributeError):
        raise invalid_report() from None
    skipped = sorted(ids["skipped_checks"])
    warnings = ["Only the seven listed Checkov policies were evaluated. Kubernetes schema and runtime behavior have not been validated."]
    warnings.extend(parsed.warnings[1:])
    if skipped:
        warnings.append("Some checks were suppressed in the manifest. Scan coverage is incomplete; skipped checks did not pass.")
    return ScanResponse(
        status="incomplete" if skipped else "completed", scanner_version=version,
        deployment=parsed.deployment, supported_checks=list(SUPPORTED_CHECKS),
        passed_checks=sorted(ids["passed_checks"]), skipped_checks=skipped,
        findings=sorted(findings, key=lambda item: item.check_id), warnings=warnings,
    )


def scan_deployment(content: bytes, filename: str) -> ScanResponse:
    """Validate input, scan a controlled copy, and clean it up on every exit."""
    parsed = parse_deployment(content, filename)
    if not SCANNER_EXECUTABLE.is_file():
        raise ScannerError("scanner_not_installed", "Checkov is unavailable. Install backend/scanner-requirements.txt into backend/.scanner-venv.")
    if not _scan_slot.acquire(blocking=False):
        raise ScannerError("scanner_busy", "A scan is already running. Try again after it completes.")
    try:
        with tempfile.TemporaryDirectory(prefix="configshield-scan-") as temporary:
            directory = Path(temporary)
            manifest_path = directory / "deployment.yaml"
            manifest_path.write_bytes(content)
            config_path = directory / "checkov-config.yaml"
            config_path.write_text("{}\n", encoding="utf-8")
            # Prevent inherited credentials, external-check settings, PYTHONPATH,
            # and home-directory Checkov configuration from changing this scan.
            environment = {key: value for key, value in os.environ.items()
                           if key.upper() in {"PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP"}}
            environment.update({"HOME": temporary, "USERPROFILE": temporary,
                                "PYTHONIOENCODING": "utf-8", "LOG_LEVEL": "ERROR"})
            completed = subprocess.run(
                [str(SCANNER_PYTHON), str(SCANNER_EXECUTABLE), "--file", str(manifest_path),
                 "--framework", "kubernetes", "--check", ",".join(SUPPORTED_CHECKS),
                 "--output", "json", "--compact", "--skip-download",
                 "--config-file", str(config_path)],
                cwd=temporary, env=environment, shell=False, capture_output=True,
                text=True, encoding="utf-8", errors="replace", timeout=SCANNER_TIMEOUT_SECONDS,
            )
            return normalize_report(completed.stdout, completed.returncode, parsed)
    except subprocess.TimeoutExpired:
        raise ScannerError("scanner_timeout", "Checkov exceeded the 60-second scan limit. No successful scan is claimed.", 504) from None
    except OSError:
        raise ScannerError("scanner_execution_failed", "Checkov could not be started or its temporary files could not be prepared.") from None
    finally:
        _scan_slot.release()

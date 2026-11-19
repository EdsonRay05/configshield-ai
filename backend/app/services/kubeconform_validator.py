"""Strict schema validation using checksum-pinned local artifacts only."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

from app.schemas import SchemaValidation

BACKEND_DIR = Path(__file__).resolve().parents[2]
LOCK_PATH = BACKEND_DIR / "tools" / "kubeconform-lock.json"
EXECUTABLE = BACKEND_DIR / ".tools" / "kubeconform.exe"
SCHEMA_PATH = BACKEND_DIR / ".tools" / "schemas" / "deployment-apps-v1.json"
VALIDATOR_TIMEOUT_SECONDS = 20


def unavailable(code: str, message: str) -> SchemaValidation:
    return SchemaValidation(status="unavailable", code=code, message=message)


def normalize_schema_report(output: str, returncode: int, name: str) -> SchemaValidation:
    try:
        data = json.loads(output)
        resources, summary = data["resources"], data["summary"]
        if not isinstance(resources, list) or len(resources) != 1:
            raise ValueError
        counts = [summary[key] for key in ("valid", "invalid", "errors", "skipped")]
        if any(type(count) is not int or count < 0 for count in counts) or sum(counts) != 1:
            raise ValueError
        resource = resources[0]
        if resource["kind"] != "Deployment" or resource["version"] != "apps/v1" or resource["name"] != name:
            raise ValueError
        if resource["status"] == "statusValid" and counts == [1, 0, 0, 0] and returncode == 0:
            return SchemaValidation(status="passed", code="schema_valid", message="Deployment passed strict schema validation against Kubernetes 1.35.0.")
        if resource["status"] == "statusInvalid" and counts == [0, 1, 0, 0] and returncode == 1:
            return SchemaValidation(status="failed", code="schema_invalid", message="Deployment failed strict Kubernetes 1.35.0 schema validation. Check field types, required fields, and unsupported properties; raw manifest values are not returned.")
        if counts[2] or counts[3]:
            return unavailable("schema_unavailable", "Kubeconform could not validate the resource or skipped it. No schema pass is claimed.")
        raise ValueError
    except (ValueError, KeyError, TypeError, AttributeError):
        return unavailable("schema_invalid_report", "Kubeconform returned an unexpected or incomplete report. No schema pass is claimed.")


def validate_schema(content: bytes, name: str) -> SchemaValidation:
    if not EXECUTABLE.is_file():
        return unavailable("validator_missing", "Kubeconform is unavailable. Run backend/tools/install-kubeconform.ps1 to install the pinned validator.")
    if not SCHEMA_PATH.is_file():
        return unavailable("schema_missing", "The pinned local Deployment schema is unavailable. No download or schema pass was attempted.")
    try:
        lock = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
        if lock["version"] != "v0.8.0" or lock["kubernetes_version"] != "1.35.0":
            raise ValueError
        if (hashlib.sha256(EXECUTABLE.read_bytes()).hexdigest() != lock["binary_sha256"]
                or hashlib.sha256(SCHEMA_PATH.read_bytes()).hexdigest() != lock["schema_sha256"]):
            return unavailable("validator_integrity_error", "Validator or schema hashes differ from the reviewed lock file. Reinstall the pinned artifacts before verification.")
    except (OSError, ValueError, KeyError, TypeError):
        return unavailable("validator_setup_invalid", "Validator setup metadata could not be verified. No schema pass is claimed.")
    try:
        with tempfile.TemporaryDirectory(prefix="configshield-schema-") as temporary:
            path = Path(temporary) / "candidate.yaml"
            path.write_bytes(content)
            environment = {key: value for key, value in os.environ.items()
                           if key.upper() in {"PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP"}}
            environment.update({"HOME": temporary, "USERPROFILE": temporary})
            completed = subprocess.run(
                [str(EXECUTABLE), "-strict", "-summary", "-verbose", "-output", "json",
                 "-kubernetes-version", "1.35.0", "-schema-location", str(SCHEMA_PATH), str(path)],
                cwd=temporary, env=environment, shell=False, capture_output=True,
                text=True, encoding="utf-8", errors="replace", timeout=VALIDATOR_TIMEOUT_SECONDS,
            )
            return normalize_schema_report(completed.stdout, completed.returncode, name)
    except subprocess.TimeoutExpired:
        return unavailable("schema_timeout", "Kubeconform exceeded the 20-second validation limit. Verification is incomplete.")
    except OSError:
        return unavailable("schema_execution_error", "Kubeconform could not start or prepare temporary files. Verification is incomplete.")

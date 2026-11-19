"""Independent verification outcomes, regression detection, and real tool workflow."""
from copy import deepcopy
import hashlib
from pathlib import Path

from fastapi.testclient import TestClient
import pytest
import yaml

from app.main import app
from app.schemas import ApplicationRequirements, AIProposal, CandidateChange, SchemaValidation, ScanResponse, SecurityFinding, VerificationRequest
from app.services import checkov_scanner, kubeconform_validator, verifier
from app.services.patcher import DEFAULT_CHANGES, apply_allowlisted_changes
from app.services.yaml_parser import parse_manifest

SAMPLES = Path(__file__).resolve().parents[2] / "samples"
REAL_TOOLS_AVAILABLE = (checkov_scanner.SCANNER_EXECUTABLE.is_file()
                        and kubeconform_validator.EXECUTABLE.is_file() and kubeconform_validator.SCHEMA_PATH.is_file())


def request_data():
    original, _ = parse_manifest((SAMPLES / "secure-deployment.yaml").read_bytes(), "original.yaml")
    original["spec"]["template"]["spec"]["containers"][0]["securityContext"]["privileged"] = True
    path, value = DEFAULT_CHANGES["CKV_K8S_16"]
    proposal = AIProposal(check_id="CKV_K8S_16", explanation="Controlled proposal",
        candidates=[CandidateChange(path=path, value=value, rationale="Review")],
        source_document_ids=["pss-privileged"], limitations=["Runtime behavior is unverified"])
    candidate = apply_allowlisted_changes(original, "CKV_K8S_16", proposal.candidates)
    original_yaml = yaml.safe_dump(original, sort_keys=False)
    return VerificationRequest(filename="original.yaml", original_yaml=original_yaml,
        original_sha256=hashlib.sha256(original_yaml.encode()).hexdigest(),
        candidate_yaml=yaml.safe_dump(candidate, sort_keys=False), proposal=proposal,
        requirements=ApplicationRequirements(api_access="not_required", privileged_access="not_required", non_root_compatibility="compatible"))


def scan_result(content, filename, failed=(), skipped=(), version="3.4.5", lines=(1, 20)):
    _, parsed = parse_manifest(content, filename)
    resource = f"Deployment.{parsed.deployment.namespace}.{parsed.deployment.name}"
    return ScanResponse(status="incomplete" if skipped else "completed", scanner_version=version,
        deployment=parsed.deployment, supported_checks=list(checkov_scanner.SUPPORTED_CHECKS),
        passed_checks=[check for check in checkov_scanner.SUPPORTED_CHECKS if check not in failed and check not in skipped],
        skipped_checks=list(skipped), warnings=[],
        findings=[SecurityFinding(check_id=check, description="Controlled finding", category="test", resource=resource,
                  line_range=list(lines), evaluated_keys=[]) for check in failed])


@pytest.fixture
def mocked_checks(monkeypatch):
    settings = {"schema": "passed", "before": ("CKV_K8S_16",), "after": (),
                "original_error": False, "candidate_error": False, "skip": (), "version": "3.4.5", "calls": 0}
    def schema(*args):
        return SchemaValidation(status=settings["schema"], code="test", message="Controlled schema result")
    def scan(content, filename):
        index = settings["calls"]
        settings["calls"] += 1
        if settings["original_error" if index == 0 else "candidate_error"]:
            raise checkov_scanner.ScannerError("scanner_unavailable", "Controlled missing scanner")
        return scan_result(content, filename, settings["before"] if index == 0 else settings["after"],
            () if index == 0 else settings["skip"], "3.4.5" if index == 0 else settings["version"],
            (1, 20) if index == 0 else (40, 70))
    monkeypatch.setattr(verifier, "validate_schema", schema)
    monkeypatch.setattr(verifier, "scan_deployment", scan)
    return settings


def test_supported_checks_verified_without_claiming_runtime_compatibility(mocked_checks):
    result = verifier.verify_candidate(request_data())
    assert result.status == "verified_supported_checks"
    assert result.targeted_finding_resolved is True
    assert [finding.check_id for finding in result.resolved_findings] == ["CKV_K8S_16"]
    assert result.new_findings == result.remaining_findings == []
    assert result.manual_review_required is True
    assert any(check.name == "runtime_compatibility" and check.status == "manual_review" for check in result.checks)


@pytest.mark.parametrize('override,privileged,valid', [('Unconfined', False, False), ('RuntimeDefault', False, True), (None, False, True), (None, True, False)])
def test_effective_seccomp_can_block_a_scanner_pass(mocked_checks, override, privileged, valid):
    request = request_data()
    original = yaml.safe_load(request.original_yaml)
    pod = original['spec']['template']['spec']
    pod['securityContext']['seccompProfile'] = {'type':'Unconfined'}
    context = pod['containers'][0]['securityContext']
    context['privileged'] = privileged
    if override is not None:
        context['seccompProfile'] = {'type':override}
    else:
        context.pop('seccompProfile', None)
    path, value = DEFAULT_CHANGES['CKV_K8S_31']
    request.proposal.check_id = 'CKV_K8S_31'
    request.proposal.candidates = [CandidateChange(path=path,value=value,rationale='Review seccomp')]
    request.original_yaml = yaml.safe_dump(original)
    request.original_sha256 = hashlib.sha256(request.original_yaml.encode()).hexdigest()
    request.candidate_yaml = yaml.safe_dump(apply_allowlisted_changes(original,'CKV_K8S_31',request.proposal.candidates))
    mocked_checks.update(before=('CKV_K8S_31',),after=())
    report = verifier.verify_candidate(request)
    assert report.targeted_finding_resolved is valid
    assert next(check.status for check in report.checks if check.name=='effective_seccomp') == ('passed' if valid else 'failed')
    if not valid:
        assert report.status == 'failed_validation'


def test_new_findings_are_reported_separately_from_resolved_target(mocked_checks):
    mocked_checks["after"] = ("CKV_K8S_20",)
    result = verifier.verify_candidate(request_data())
    assert result.status == "new_security_findings"
    assert result.targeted_finding_resolved is True
    assert [finding.check_id for finding in result.new_findings] == ["CKV_K8S_20"]


def test_remaining_findings_prevent_broad_verified_status(mocked_checks):
    mocked_checks.update(before=("CKV_K8S_16", "CKV_K8S_20"), after=("CKV_K8S_20",))
    result = verifier.verify_candidate(request_data())
    assert result.status == "manual_review"
    assert result.targeted_finding_resolved is True
    assert [finding.check_id for finding in result.remaining_findings] == ["CKV_K8S_20"]
    assert result.new_findings == []  # Different line numbers are not a new finding.


def test_target_still_failed_is_not_claimed_resolved(mocked_checks):
    mocked_checks["after"] = ("CKV_K8S_16",)
    result = verifier.verify_candidate(request_data())
    assert result.status == "manual_review"
    assert result.targeted_finding_resolved is False
    assert result.resolved_findings == []


@pytest.mark.parametrize("fault", ["schema", "original_scanner", "candidate_scanner", "skipped", "different_version", "different_rules"])
def test_unavailable_or_incomparable_checks_are_incomplete(mocked_checks, monkeypatch, fault):
    if fault == "schema": mocked_checks["schema"] = "unavailable"
    elif fault == "original_scanner": mocked_checks["original_error"] = True
    elif fault == "candidate_scanner": mocked_checks["candidate_error"] = True
    elif fault == "skipped": mocked_checks["skip"] = ("CKV_K8S_16",)
    elif fault == "different_version": mocked_checks["version"] = "different"
    elif fault == "different_rules":
        original_scan = verifier.scan_deployment
        def incomplete_rules(content, filename):
            scan = original_scan(content, filename)
            scan.supported_checks = []
            return scan
        monkeypatch.setattr(verifier, "scan_deployment", incomplete_rules)
    result = verifier.verify_candidate(request_data())
    assert result.status == "incomplete"
    assert any(check.status == "unavailable" for check in result.checks)
    if fault != "schema":
        assert result.resolved_findings == []
        assert result.targeted_finding_resolved is None


def test_schema_failure_is_not_a_scanner_execution_error(mocked_checks):
    mocked_checks["schema"] = "failed"
    result = verifier.verify_candidate(request_data())
    assert result.status == "failed_validation"
    assert result.original_scan is not None and result.candidate_scan is not None
    assert result.schema_validation.status == "failed"


def test_requirement_conflicts_are_recomputed(mocked_checks):
    request = request_data()
    request.requirements.privileged_access = "required"
    result = verifier.verify_candidate(request)
    assert result.status == "requirement_conflict"
    assert result.constraint_report.status == "conflict"


def test_unknown_requirements_keep_manual_review_status(mocked_checks):
    request = request_data()
    request.requirements = ApplicationRequirements()
    result = verifier.verify_candidate(request)
    assert result.status == "manual_review"
    assert any(check.name == "requirement_checks" and check.status == "manual_review" for check in result.checks)


def test_unrelated_field_changes_fail_authorization(mocked_checks):
    request = request_data()
    candidate = yaml.safe_load(request.candidate_yaml)
    candidate["spec"]["replicas"] = 4
    request.candidate_yaml = yaml.safe_dump(candidate)
    result = verifier.verify_candidate(request)
    assert result.status == "failed_validation"
    assert result.unexpected_changed_paths == ["/spec/replicas"]


def test_no_op_does_not_claim_a_repair(mocked_checks):
    request = request_data()
    request.candidate_yaml = request.original_yaml
    mocked_checks["after"] = ("CKV_K8S_16",)
    result = verifier.verify_candidate(request)
    assert result.status == "failed_validation"
    assert result.targeted_finding_resolved is False


@pytest.mark.parametrize("target", ["original", "candidate"])
def test_malformed_yaml_stops_dependent_checks(mocked_checks, target):
    request = request_data()
    if target == "original":
        request.original_yaml = "metadata: ["
        request.original_sha256 = hashlib.sha256(request.original_yaml.encode()).hexdigest()
    else: request.candidate_yaml = "metadata: ["
    result = verifier.verify_candidate(request)
    assert result.status == "failed_validation"
    assert result.schema_validation is None
    assert mocked_checks["calls"] == 0
    assert all(check.status == "not_run" for check in result.checks if check.name in {"schema_validation", "original_security_scan", "finding_comparison"})


def test_verification_keeps_inputs_unchanged(mocked_checks):
    request = request_data()
    saved = deepcopy(request.model_dump())
    verifier.verify_candidate(request)
    assert request.model_dump() == saved


def test_verification_api_contract_and_stale_or_spoofed_input(mocked_checks):
    data = request_data().model_dump()
    with TestClient(app) as client:
        response = client.post("/api/verify", json=data)
        assert response.status_code == 200
        assert response.json()["status"] == "verified_supported_checks"
        stale = dict(data, original_yaml=data["original_yaml"] + "\n")
        assert client.post("/api/verify", json=stale).status_code == 409
        assert client.post("/api/verify", json=dict(data, checks=[{"status": "passed"}])).status_code == 422
        assert client.post("/api/verify", content=b"x" * (1024 * 1024 + 1)).status_code == 413


@pytest.mark.skipif(not REAL_TOOLS_AVAILABLE, reason="Install Checkov and the pinned local Kubeconform artifacts")
@pytest.mark.parametrize("invalid", [False, True])
def test_real_offline_verification_api(invalid):
    request = request_data()
    if invalid:
        candidate = yaml.safe_load(request.candidate_yaml)
        candidate["spec"]["template"]["spec"]["containers"][0]["unknownProperty"] = "private-raw-value"
        request.candidate_yaml = yaml.safe_dump(candidate)
    with TestClient(app) as client:
        response = client.post("/api/verify", json=request.model_dump())
    assert response.status_code == 200
    result = response.json()
    assert result["status"] == ("failed_validation" if invalid else "verified_supported_checks")
    assert result["schema_validation"]["status"] == ("failed" if invalid else "passed")
    assert result["targeted_finding_resolved"] is True
    assert "private-raw-value" not in response.text

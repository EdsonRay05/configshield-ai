"""Allowlisted copy construction and the human approval boundary."""
from copy import deepcopy
import hashlib
from pathlib import Path

from fastapi.testclient import TestClient
import pytest
import yaml

from app.main import app
from app.routers import analysis
from app.schemas import CandidateChange, ScanResponse, SecurityFinding
from app.services import ai_provider, checkov_scanner
from app.services.patcher import DEFAULT_CHANGES, PatchError, apply_allowlisted_changes, same_value, semantic_changed_paths
from app.services.retrieval import RULE_DOCUMENTS
from app.services.yaml_parser import parse_manifest

SAMPLES = Path(__file__).resolve().parents[2] / "samples"
CONTENT = (SAMPLES / "insecure-deployment.yaml").read_bytes()


def change(check_id):
    path, value = DEFAULT_CHANGES[check_id]
    return CandidateChange(path=path, value=deepcopy(value), rationale="Controlled candidate")


def payload(check_id="CKV_K8S_16", content=CONTENT):
    return {"filename": "sample.yaml", "original_yaml": content.decode("utf-8"),
            "original_sha256": hashlib.sha256(content).hexdigest(),
            "proposal": {"check_id": check_id, "explanation": "Controlled proposal",
                         "candidates": [change(check_id).model_dump()],
                         "source_document_ids": [RULE_DOCUMENTS[check_id][0]],
                         "limitations": ["Runtime behavior unverified"]},
            "requirements": {"api_access": "not_required", "privileged_access": "not_required", "non_root_compatibility": "compatible"},
            "approved": False, "acknowledge_manual_review": False}


@pytest.fixture
def fake_scanner(monkeypatch):
    def scan(content, filename):
        _, parsed = parse_manifest(content, filename)
        return ScanResponse(status="completed", scanner_version="3.4.5", deployment=parsed.deployment,
            supported_checks=list(DEFAULT_CHANGES), passed_checks=[], skipped_checks=[], warnings=[],
            findings=[SecurityFinding(check_id=check_id, description="Finding", category="test",
                       resource="Deployment.default.insecure-demo", line_range=[], evaluated_keys=[])
                       for check_id in DEFAULT_CHANGES])
    monkeypatch.setattr(analysis, "scan_deployment", scan)
    return scan


@pytest.mark.parametrize("check_id", list(DEFAULT_CHANGES))
def test_only_selected_field_changes_and_original_is_preserved(check_id):
    original, _ = parse_manifest(CONTENT, "sample.yaml")
    saved = deepcopy(original)
    candidate = apply_allowlisted_changes(original, check_id, [change(check_id)])
    assert same_value(original, saved)
    assert candidate is not original
    assert semantic_changed_paths(original, candidate) == [DEFAULT_CHANGES[check_id][0]]
    assert candidate["spec"]["template"]["spec"]["containers"][0]["image"] == "nginx:1.27"


def test_missing_security_parents_are_created_without_unrelated_changes():
    original, _ = parse_manifest(CONTENT, "sample.yaml")
    del original["spec"]["template"]["spec"]["containers"][0]["securityContext"]
    candidate = apply_allowlisted_changes(original, "CKV_K8S_37", [change("CKV_K8S_37")])
    assert semantic_changed_paths(original, candidate) == [DEFAULT_CHANGES["CKV_K8S_37"][0]]
    assert "securityContext" not in original["spec"]["template"]["spec"]["containers"][0]


@pytest.mark.parametrize("fault", ["unrelated_rule", "wrong_value", "wrong_type", "duplicate", "unsupported_rule", "malformed_parent"])
def test_unsupported_changes_rejected_without_mutation(fault):
    original, _ = parse_manifest(CONTENT, "sample.yaml")
    changes = [change("CKV_K8S_16")]
    check_id = "CKV_K8S_16"
    if fault == "unrelated_rule": changes = [change("CKV_K8S_38")]
    elif fault == "wrong_value": changes[0].value = True
    elif fault == "wrong_type": changes[0].value = "false"
    elif fault == "duplicate": changes *= 2
    elif fault == "unsupported_rule": check_id = "CKV_K8S_999"
    elif fault == "malformed_parent": original["spec"]["template"]["spec"]["containers"][0]["securityContext"] = None
    saved = deepcopy(original)
    with pytest.raises(PatchError): apply_allowlisted_changes(original, check_id, changes)
    assert same_value(original, saved)


def test_semantic_comparison_distinguishes_boolean_and_integer():
    assert not same_value({"value": True}, {"value": 1})
    assert semantic_changed_paths({"metadata": {"example.com/key": 1}}, {"metadata": {"example.com/key": 2}}) == ["/metadata/example.com~1key"]


def test_new_values_are_not_aliased_to_proposal():
    original, _ = parse_manifest(CONTENT, "sample.yaml")
    proposed = change("CKV_K8S_37")
    candidate = apply_allowlisted_changes(original, "CKV_K8S_37", [proposed])
    proposed.value.append("NET_RAW")
    assert candidate["spec"]["template"]["spec"]["containers"][0]["securityContext"]["capabilities"]["drop"] == ["ALL"]


def test_approval_and_manual_review_both_required(fake_scanner):
    data = payload()
    with TestClient(app) as client:
        response = client.post("/api/candidate", json=data)
        assert response.status_code == 200
        assert response.json()["status"] == "review_required"
        assert response.json()["candidate_yaml"] is None
        data["approved"] = True
        response = client.post("/api/candidate", json=data)
        assert response.json()["status"] == "review_required"
        assert response.json()["candidate_yaml"] is None
        data["acknowledge_manual_review"] = True
        response = client.post("/api/candidate", json=data)
        assert response.status_code == 200
        result = response.json()
        assert result["status"] == "candidate_created"
        assert result["semantic_changed_paths"] == [DEFAULT_CHANGES["CKV_K8S_16"][0]]
        assert result["change_details"] == [{"path": DEFAULT_CHANGES["CKV_K8S_16"][0],
            "original_present": True, "original_value": "true", "candidate_value": "false", "rationale": "Controlled candidate"}]
        candidate, _ = parse_manifest(result["candidate_yaml"].encode(), "candidate.yaml")
        assert candidate["spec"]["template"]["spec"]["containers"][0]["securityContext"]["privileged"] is False
    assert data["original_yaml"].encode() == CONTENT


def test_change_details_distinguish_absent_field_from_false(fake_scanner):
    original, _ = parse_manifest(CONTENT, "sample.yaml")
    del original["spec"]["template"]["spec"]["containers"][0]["securityContext"]["allowPrivilegeEscalation"]
    data = payload("CKV_K8S_20", yaml.safe_dump(original).encode())
    data.update(approved=True, acknowledge_manual_review=True)
    with TestClient(app) as client:
        response = client.post("/api/candidate", json=data)
    assert response.status_code == 200
    detail = response.json()["change_details"][0]
    assert detail["original_present"] is False
    assert detail["original_value"] == "Not set"
    assert detail["candidate_value"] == "false"


def test_conflict_cannot_be_overridden_by_approval(fake_scanner):
    data = payload()
    data.update(approved=True, acknowledge_manual_review=True)
    data["requirements"]["privileged_access"] = "required"
    with TestClient(app) as client:
        result = client.post("/api/candidate", json=data).json()
    assert result["status"] == "blocked"
    assert result["candidate_yaml"] is None
    assert result["constraint_report"]["status"] == "conflict"


def test_empty_candidate_is_not_a_created_fix(fake_scanner):
    data = payload()
    data["proposal"]["candidates"] = []
    with TestClient(app) as client:
        result = client.post("/api/candidate", json=data).json()
    assert result["status"] == "no_changes"
    assert result["candidate_yaml"] is None


@pytest.mark.parametrize("fault", ["stale_hash", "arbitrary_path", "unrelated_path", "wrong_value", "invented_source", "whole_yaml", "spoofed_checks", "nonboolean_approval", "bad_json", "oversized"])
def test_candidate_endpoint_rejects_tampering(fake_scanner, fault):
    data = payload()
    if fault == "stale_hash": data["original_yaml"] += "\n"
    elif fault == "arbitrary_path": data["proposal"]["candidates"][0]["path"] = "/metadata/name"
    elif fault == "unrelated_path": data["proposal"]["candidates"] = [change("CKV_K8S_38").model_dump()]
    elif fault == "wrong_value": data["proposal"]["candidates"][0]["value"] = True
    elif fault == "invented_source": data["proposal"]["source_document_ids"] = ["invented"]
    elif fault == "whole_yaml": data["candidate_yaml"] = "kind: Pod"
    elif fault == "spoofed_checks": data["constraint_report"] = {"status": "preserved"}
    elif fault == "nonboolean_approval": data["approved"] = "true"
    with TestClient(app) as client:
        if fault == "bad_json": response = client.post("/api/candidate", content=b"{")
        elif fault == "oversized": response = client.post("/api/candidate", content=b"x" * (512 * 1024 + 1))
        else: response = client.post("/api/candidate", json=data)
    assert response.status_code == (409 if fault == "stale_hash" else 413 if fault == "oversized" else 422)
    assert "candidate_yaml" not in response.json()


def test_changed_scanner_finding_blocks_candidate(fake_scanner, monkeypatch):
    def no_findings(content, filename):
        scan = fake_scanner(content, filename)
        scan.findings = []
        return scan
    monkeypatch.setattr(analysis, "scan_deployment", no_findings)
    with TestClient(app) as client:
        response = client.post("/api/candidate", json=payload())
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "finding_not_present"


def test_candidate_preserves_bom_crlf_and_private_values_in_original(fake_scanner):
    text = CONTENT.decode().replace("\n", "\r\n") + "# private original comment\r\n"
    content = b"\xef\xbb\xbf" + text.encode()
    data = payload(content=content)
    data.update(approved=True, acknowledge_manual_review=True)
    with TestClient(app) as client:
        response = client.post("/api/candidate", json=data)
    assert response.status_code == 200
    assert response.json()["status"] == "candidate_created"
    assert data["original_yaml"].encode("utf-8") == content
    assert (SAMPLES / "insecure-deployment.yaml").read_bytes() == CONTENT


@pytest.mark.skipif(not checkov_scanner.SCANNER_EXECUTABLE.is_file(), reason="Install the local scanner for real candidate integration")
def test_real_scan_mock_explanation_and_approved_candidate(monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "mock")
    with TestClient(app) as client:
        explanation = client.post("/api/explain?filename=sample.yaml&check_id=CKV_K8S_16&provider=mock&privileged_access=not_required&api_access=not_required&non_root_compatibility=compatible", content=CONTENT)
        assert explanation.status_code == 200
        result = explanation.json()
        assert result["usage"]["external_requests_this_action"] == 0
        data = payload()
        data.update(proposal=result["proposal"], requirements=result["requirements"],
                    original_sha256=result["original_sha256"], approved=True, acknowledge_manual_review=True)
        candidate = client.post("/api/candidate", json=data)
        assert candidate.status_code == 200
        assert candidate.json()["status"] == "candidate_created"


@pytest.mark.parametrize("check_id,requirement,value", [
    ("CKV_K8S_16", "privileged_access", "required"),
    ("CKV_K8S_38", "api_access", "required"),
    ("CKV_K8S_23", "non_root_compatibility", "incompatible"),
])
def test_mock_omits_known_requirement_conflicts(monkeypatch, check_id, requirement, value):
    data = payload(check_id)
    data["requirements"][requirement] = value
    guidance_id = RULE_DOCUMENTS[check_id][0]
    prompt = {"check_id": check_id, "requirements": data["requirements"], "guidance": [{"document_id": guidance_id}]}
    import json
    proposal = json.loads(ai_provider.MockProvider().generate(json.dumps(prompt)).text)
    assert proposal["candidates"] == []
    assert "conflict" in proposal["explanation"]


def test_provider_ignoring_requirements_is_still_flagged_independently(monkeypatch, fake_scanner):
    import json
    from app.schemas import ApplicationRequirements
    monkeypatch.setattr(ai_provider, "scan_deployment", fake_scanner)
    monkeypatch.setattr(ai_provider.MockProvider, "generate", lambda *args: ai_provider.ProviderReply(json.dumps(payload()["proposal"])))
    result = ai_provider.explain_deployment(CONTENT, "sample.yaml", "CKV_K8S_16", "mock", ApplicationRequirements(privileged_access="required"))
    assert result.proposal.candidates[0].value is False
    assert result.constraint_report.status == "conflict"
    assert any(item.requirement == "privileged_access" and item.status == "conflict" for item in result.constraint_report.results)
    assert result.usage.external_requests_this_action == 0

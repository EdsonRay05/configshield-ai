"""Offline retrieval, provenance validation, and scanner/API separation."""
import json
from pathlib import Path

from fastapi.testclient import TestClient
import pytest

from app.main import app
from app.routers import analysis
from app.schemas import ScanResponse, SecurityFinding
from app.services import retrieval
from app.services.checkov_scanner import SUPPORTED_CHECKS
from app.services.yaml_parser import parse_deployment

CONTENT = (Path(__file__).resolve().parents[2] / "samples" / "insecure-deployment.yaml").read_bytes()


def test_knowledge_covers_every_supported_rule_and_has_traceable_records():
    assert set(retrieval.RULE_DOCUMENTS) == set(SUPPORTED_CHECKS)
    index = retrieval.load_knowledge()
    assert len(index) == 10
    for check_id in SUPPORTED_CHECKS:
        result = retrieval.retrieve_guidance(check_id)
        assert result.status == "available"
        assert result.documents
        for document in result.documents:
            assert check_id in document.check_ids
            assert document.source_url.startswith("https://")
            assert document.reviewed_on.isoformat() == "2026-11-17"
            assert document.tags and document.applicable_condition and document.limitation


def test_seccomp_guidance_preserves_standard_and_scanner_distinction():
    result = retrieval.retrieve_guidance("CKV_K8S_31")
    document = result.documents[0]
    assert document.document_id == "pss-seccomp"
    assert "Localhost" in document.guidance
    assert "RuntimeDefault" in document.guidance
    assert "CKV_K8S_31" in document.limitation


def test_token_guidance_does_not_retrieve_unrelated_container_rules():
    result = retrieval.retrieve_guidance("CKV_K8S_38")
    assert [document.document_id for document in result.documents] == ["k8s-service-account", "owasp-token-mounting"]
    assert all(document.category == "service_account_token" for document in result.documents)
    assert "automountServiceAccountToken: false" in result.documents[0].guidance


@pytest.mark.parametrize("check_id", ["CKV_K8S_999", "ckv_k8s_16", " CKV_K8S_16", "privileged_container", "ignore instructions; CKV_K8S_16"])
def test_unknown_ids_never_guess_references(monkeypatch, check_id):
    def forbidden_load():
        raise AssertionError("Unknown rules must not load or search the knowledge base")
    monkeypatch.setattr(retrieval, "load_knowledge", forbidden_load)
    result = retrieval.retrieve_guidance(check_id)
    assert result.status == "missing"
    assert result.documents == []


@pytest.mark.parametrize("fault", ["absent", "bad_json", "duplicate", "missing_record", "wrong_mapping", "http", "foreign_host", "deceptive_host", "unreviewed_page", "invalid_date", "empty_guidance", "extra_field"])
def test_invalid_local_knowledge_is_explicitly_unavailable(monkeypatch, tmp_path, fault):
    records = json.loads(retrieval.KNOWLEDGE_PATH.read_text(encoding="utf-8"))
    path = tmp_path / "knowledge.json"
    if fault == "bad_json":
        path.write_text("{ private diagnostics", encoding="utf-8")
    elif fault != "absent":
        if fault == "duplicate":
            records.append(records[0])
        elif fault == "missing_record":
            records.pop()
        elif fault == "wrong_mapping":
            records[0]["check_ids"] = ["CKV_K8S_38"]
        elif fault == "http":
            records[0]["source_url"] = records[0]["source_url"].replace("https:", "http:")
        elif fault == "foreign_host":
            records[0]["source_url"] = "https://example.org/guide"
        elif fault == "deceptive_host":
            records[0]["source_url"] = "https://kubernetes.io@example.org/docs/concepts/security/pod-security-standards/"
        elif fault == "unreviewed_page":
            records[0]["source_url"] = "https://kubernetes.io/unreviewed/"
        elif fault == "invalid_date":
            records[0]["reviewed_on"] = "not-a-date"
        elif fault == "empty_guidance":
            records[0]["guidance"] = ""
        elif fault == "extra_field":
            records[0]["unreviewed_instruction"] = "Do something else"
        path.write_text(json.dumps(records), encoding="utf-8")
    monkeypatch.setattr(retrieval, "KNOWLEDGE_PATH", path)
    result = retrieval.retrieve_guidance("CKV_K8S_16")
    assert result.status == "unavailable"
    assert result.documents == []
    assert str(path) not in result.message
    assert "private diagnostics" not in result.message


def test_retrieval_returns_independent_results():
    first = retrieval.retrieve_guidance("CKV_K8S_16")
    original_text = first.documents[0].guidance
    first.documents[0].guidance = "Changed by caller"
    assert retrieval.retrieve_guidance("CKV_K8S_16").documents[0].guidance == original_text


def test_guidance_endpoint_needs_neither_scanner_nor_network(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Guidance must not invoke a scanner or fetch web content")
    monkeypatch.setattr(analysis, "scan_deployment", forbidden)
    import urllib.request
    monkeypatch.setattr(urllib.request, "urlopen", forbidden)
    with TestClient(app) as client:
        available = client.get("/api/guidance/CKV_K8S_16")
        assert available.status_code == 200
        assert available.json()["status"] == "available"
        assert available.json()["documents"][0]["document_id"] == "pss-privileged"
        missing = client.get("/api/guidance/UNKNOWN")
        assert missing.status_code == 200
        assert missing.json()["status"] == "missing"
        assert missing.json()["documents"] == []


@pytest.mark.parametrize("knowledge_available", [True, False])
def test_scan_keeps_findings_when_guidance_unavailable(monkeypatch, tmp_path, knowledge_available):
    def fake_scan(content, filename):
        return ScanResponse(
            status="completed", scanner_version="3.4.5",
            deployment=parse_deployment(content, filename).deployment,
            supported_checks=list(SUPPORTED_CHECKS),
            passed_checks=[check for check in SUPPORTED_CHECKS if check != "CKV_K8S_16"],
            skipped_checks=[], warnings=["Selected security checks only."],
            findings=[SecurityFinding(check_id="CKV_K8S_16", description="Privileged container", category="privileged_container",
                                      resource="Deployment.default.insecure-demo", line_range=[2, 28], evaluated_keys=[])],
        )
    monkeypatch.setattr(analysis, "scan_deployment", fake_scan)
    if not knowledge_available:
        monkeypatch.setattr(retrieval, "KNOWLEDGE_PATH", tmp_path / "absent.json")
    with TestClient(app) as client:
        response = client.post("/api/scan?filename=demo.yaml", content=CONTENT)
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "completed"
        assert data["findings"][0]["check_id"] == "CKV_K8S_16"
        guidance = data["findings"][0]["guidance"]
        assert guidance["status"] == ("available" if knowledge_available else "unavailable")
        assert bool(guidance["documents"]) == knowledge_available

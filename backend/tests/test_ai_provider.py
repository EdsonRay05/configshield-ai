"""All AI tests are offline: scanner and Gemini transport are controlled mocks."""
import json
from pathlib import Path
from types import SimpleNamespace

from fastapi.testclient import TestClient
from google import genai
import httpx2
import pytest
import yaml

from app.config import AISettings, FREE_MODEL
from app.main import app
from app.schemas import ApplicationRequirements, ScanResponse, SecurityFinding
from app.services import ai_provider as ai
from app.services import checkov_scanner
from app.services.yaml_parser import parse_deployment, parse_manifest

CONTENT = (Path(__file__).resolve().parents[2] / "samples" / "insecure-deployment.yaml").read_bytes()


def fake_scan(content, filename):
    return ScanResponse(status="completed", scanner_version="3.4.5",
        deployment=parse_deployment(content, filename).deployment,
        supported_checks=list(ai.DEFAULT_CHANGES), passed_checks=[], skipped_checks=[], warnings=[],
        findings=[SecurityFinding(check_id=check_id, description="Confirmed finding", category="test",
                  resource="Deployment.default.insecure-demo", line_range=[], evaluated_keys=[])
                  for check_id in ai.DEFAULT_CHANGES])


@pytest.fixture(autouse=True)
def isolated_settings(monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "mock")
    monkeypatch.setenv("GEMINI_MODEL", FREE_MODEL)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_FREE_TIER_CONFIRMED", raising=False)
    monkeypatch.setattr(ai, "usage_tracker", ai.UsageTracker())
    monkeypatch.setattr(ai, "scan_deployment", fake_scan)


def explain(provider="mock", content=CONTENT, requirements=None):
    return ai.explain_deployment(content, "sample.yaml", "CKV_K8S_16", provider,
                                 requirements or ApplicationRequirements())


def enable_live(monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "gemini")
    monkeypatch.setenv("GEMINI_API_KEY", "backend-test-key-do-not-send-in-prompt")
    monkeypatch.setenv("GEMINI_FREE_TIER_CONFIRMED", "true")


def test_mock_validates_and_never_constructs_gemini_client(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Mock mode must not construct a cloud client")
    monkeypatch.setattr(genai, "Client", forbidden)
    result = explain()
    assert result.status == "mock"
    assert result.provider == "mock"
    assert result.usage.external_requests_this_action == 0
    assert result.usage.process_requests_attempted == 0
    assert result.proposal.candidates[0].value is False
    assert result.requirements.api_access == "unknown"


@pytest.mark.parametrize("check_id", list(ai.DEFAULT_CHANGES))
def test_each_supported_mock_passes_output_validation(check_id):
    result = ai.explain_deployment(CONTENT, "sample.yaml", check_id, "mock", ApplicationRequirements())
    assert result.proposal.check_id == check_id
    assert result.proposal.source_document_ids
    assert len(result.proposal.candidates) == 1


def test_prompt_omits_free_text_and_keeps_requirements(monkeypatch):
    manifest = yaml.safe_load(CONTENT)
    marker = "private-value-DO-NOT-SEND"
    manifest["metadata"]["name"] = marker
    manifest["metadata"]["annotations"] = {"instruction": marker}
    container = manifest["spec"]["template"]["spec"]["containers"][0]
    container["image"] = marker
    container["env"] = [{"name": "PASSWORD", "value": marker}]
    container["command"] = ["sh", "-c", marker]
    container["args"] = [marker]
    container["securityContext"]["seccompProfile"] = {"type": "Localhost", "localhostProfile": marker}
    captured = []
    original = ai.MockProvider.generate
    def capture(self, prompt):
        captured.append(prompt)
        return original(self, prompt)
    monkeypatch.setattr(ai.MockProvider, "generate", capture)
    requirements = ApplicationRequirements(api_access="required", privileged_access="required", non_root_compatibility="incompatible")
    explain(content=yaml.safe_dump(manifest).encode(), requirements=requirements)
    assert marker not in captured[0]
    data = json.loads(captured[0])
    assert data["requirements"] == requirements.model_dump()
    assert data["evidence"]["container"]["securityContext"]["privileged"] is True
    assert data["evidence"]["container"]["securityContext"]["seccompProfile"] == {"type": "Localhost"}
    assert "untrusted" in ai.SYSTEM_INSTRUCTION


@pytest.mark.parametrize("field,value", [
    ("privileged", "secret-value"), ("runAsNonRoot", 1), ("runAsUser", "1234-password"),
    ("runAsUser", -1), ("runAsUser", True), ("capabilities", {"drop": ["secret-value"]}),
    ("capabilities", {"drop": "ALL"}), ("seccompProfile", {"type": ["secret"]}),
    ("seccompProfile", {"type": "private-value"}),
])
def test_unexpected_security_data_is_rejected_before_provider(monkeypatch, field, value):
    manifest, _ = parse_manifest(CONTENT, "sample.yaml")
    manifest["spec"]["template"]["spec"]["containers"][0]["securityContext"][field] = value
    def forbidden(*args, **kwargs):
        raise AssertionError("Unsafe evidence must be rejected before generating")
    monkeypatch.setattr(ai.MockProvider, "generate", forbidden)
    with pytest.raises(ai.AIError) as error:
        explain(content=yaml.safe_dump(manifest).encode())
    assert error.value.code == "ai_unsafe_evidence"


@pytest.mark.parametrize("case,expected", [
    ("disabled", "ai_live_disabled"), ("unconfirmed", "ai_free_tier_unconfirmed"),
    ("missing_key", "ai_key_missing"), ("paid_model", "ai_model_not_allowed"),
])
def test_live_configuration_blocks_before_scanning_or_requests(monkeypatch, case, expected):
    enable_live(monkeypatch)
    if case == "disabled": monkeypatch.setenv("AI_PROVIDER", "mock")
    elif case == "unconfirmed": monkeypatch.setenv("GEMINI_FREE_TIER_CONFIRMED", "false")
    elif case == "missing_key": monkeypatch.delenv("GEMINI_API_KEY")
    elif case == "paid_model": monkeypatch.setenv("GEMINI_MODEL", "unreviewed-pro-model")
    def forbidden(*args, **kwargs):
        raise AssertionError("Invalid configuration must block before scanner or Gemini")
    monkeypatch.setattr(ai, "scan_deployment", forbidden)
    monkeypatch.setattr(genai, "Client", forbidden)
    with pytest.raises(ai.AIError) as error:
        explain("gemini")
    assert error.value.code == expected
    assert ai.usage_tracker.attempted == 0


def test_missing_guidance_blocks_explanation(monkeypatch):
    monkeypatch.setattr(ai, "retrieve_guidance", lambda _: SimpleNamespace(status="unavailable"))
    with pytest.raises(ai.AIError) as error: explain()
    assert error.value.code == "ai_guidance_unavailable"


def test_stale_finding_blocks_explanation(monkeypatch):
    def no_findings(content, filename):
        result = fake_scan(content, filename)
        result.findings = []
        return result
    monkeypatch.setattr(ai, "scan_deployment", no_findings)
    with pytest.raises(ai.AIError) as error: explain()
    assert error.value.code == "ai_finding_not_present"


def valid_proposal_dict():
    return explain().proposal.model_dump()


@pytest.mark.parametrize("fault", ["bad_json", "extra_field", "wrong_check", "fake_source", "duplicate_source", "wrong_path", "wrong_value", "wrong_type", "duplicate_path", "full_yaml", "oversized"])
def test_malformed_or_unauthorized_output_rejected(fault):
    proposal = valid_proposal_dict()
    if fault == "extra_field": proposal["deploy_command"] = "kubectl apply"
    elif fault == "wrong_check": proposal["check_id"] = "CKV_K8S_38"
    elif fault == "fake_source": proposal["source_document_ids"] = ["invented-reference"]
    elif fault == "duplicate_source": proposal["source_document_ids"] *= 2
    elif fault == "wrong_path": proposal["candidates"][0]["path"] = "/spec/replicas"
    elif fault == "wrong_value": proposal["candidates"][0]["value"] = True
    elif fault == "wrong_type": proposal["candidates"][0]["value"] = "false"
    elif fault == "duplicate_path": proposal["candidates"] *= 2
    elif fault == "full_yaml": proposal["yaml"] = "apiVersion: apps/v1"
    text = "bad json" if fault == "bad_json" else ("x" * 24001 if fault == "oversized" else json.dumps(proposal))
    with pytest.raises(ai.AIError) as error:
        ai.validate_proposal(ai.ProviderReply(text), "CKV_K8S_16", {"pss-privileged", "owasp-least-privilege"})
    assert error.value.code == "ai_invalid_output"


def test_no_candidate_is_a_valid_review_outcome():
    proposal = valid_proposal_dict()
    proposal["candidates"] = []
    assert ai.validate_proposal(ai.ProviderReply(json.dumps(proposal)), "CKV_K8S_16", {"pss-privileged"}).candidates == []


def sdk_transport(monkeypatch, handler):
    real_client = genai.Client
    captured = []
    def factory(**kwargs):
        captured.append(kwargs)
        kwargs["http_options"].client_args["transport"] = httpx2.MockTransport(handler)
        return real_client(**kwargs)
    monkeypatch.setattr(genai, "Client", factory)
    return captured


def test_real_sdk_serializes_one_mocked_http_request_and_tracks_usage(monkeypatch):
    proposal = valid_proposal_dict()
    enable_live(monkeypatch)
    monkeypatch.setenv("GOOGLE_API_KEY", "unrelated-key-must-not-override-backend-key")
    observed = []
    def handler(request):
        observed.append(request)
        body = json.loads(request.content)
        assert request.url.host == "generativelanguage.googleapis.com"
        assert request.headers["x-goog-api-key"] == "backend-test-key-do-not-send-in-prompt"
        assert FREE_MODEL in request.url.path
        assert "backend-test-key-do-not-send-in-prompt" not in request.content.decode()
        assert body["generationConfig"]["responseMimeType"] == "application/json"
        assert body["generationConfig"]["maxOutputTokens"] == 2048
        assert not body.get("tools")
        return httpx2.Response(200, json={
            "candidates": [{"content": {"role": "model", "parts": [{"text": json.dumps(proposal)}]}, "finishReason": "STOP"}],
            "usageMetadata": {"promptTokenCount": 200, "candidatesTokenCount": 50, "totalTokenCount": 250},
            "modelVersion": FREE_MODEL,
        })
    captured = sdk_transport(monkeypatch, handler)
    result = explain("gemini")
    assert len(observed) == 1
    assert captured[0]["enterprise"] is False
    assert captured[0]["http_options"].retry_options.attempts == 1
    assert captured[0]["http_options"].timeout == 30000
    assert captured[0]["http_options"].client_args["trust_env"] is False
    assert result.status == "generated"
    assert result.usage.total_tokens == 250
    assert result.usage.process_reported_total_tokens == 250
    assert result.usage.process_requests_attempted == 1
    assert result.usage.process_requests_succeeded == 1
    assert result.usage.external_requests_this_action == 1


@pytest.mark.parametrize("status,expected", [(429, "ai_quota_exhausted"), (403, "ai_access_denied"), (404, "ai_model_unavailable"), (500, "ai_provider_error")])
def test_sdk_errors_are_not_retried_or_leaked(monkeypatch, status, expected):
    enable_live(monkeypatch)
    observed = []
    def handler(request):
        observed.append(request)
        return httpx2.Response(status, json={"error": {"code": status, "message": "private backend-test-key-do-not-send-in-prompt diagnostics", "status": "RESOURCE_EXHAUSTED"}})
    sdk_transport(monkeypatch, handler)
    with pytest.raises(ai.AIError) as error: explain("gemini")
    assert error.value.code == expected
    assert "private" not in str(error.value)
    assert "backend-test-key" not in str(error.value)
    assert len(observed) == 1
    assert ai.usage_tracker.failed == 1
    assert ai.usage_tracker.attempted == 1


def test_sdk_timeout_does_not_retry(monkeypatch):
    enable_live(monkeypatch)
    observed = []
    def handler(request):
        observed.append(request)
        raise httpx2.ReadTimeout("private timeout", request=request)
    sdk_transport(monkeypatch, handler)
    with pytest.raises(ai.AIError) as error: explain("gemini")
    assert error.value.code == "ai_provider_error"
    assert "private" not in str(error.value)
    assert len(observed) == 1


def test_failed_structured_output_still_counts_reported_tokens(monkeypatch):
    enable_live(monkeypatch)
    monkeypatch.setattr(ai.GeminiProvider, "generate", lambda *args: ai.ProviderReply("not-json", 10, 5, 15))
    with pytest.raises(ai.AIError): explain("gemini")
    assert ai.usage_tracker.failed == 1
    assert ai.usage_tracker.tokens == 15
    assert ai._provider_slot.acquire(blocking=False)
    ai._provider_slot.release()


def test_local_limits_and_cooldown_count_only_attempts(monkeypatch):
    monkeypatch.setattr(ai.time, "monotonic", lambda: 100)
    tracker = ai.UsageTracker()
    tracker.begin()
    with pytest.raises(ai.AIError) as error: tracker.begin()
    assert error.value.code == "ai_cooldown"
    assert tracker.attempted == 1
    for index in range(1, 5):
        monkeypatch.setattr(ai.time, "monotonic", lambda index=index: 100 + index * 16)
        tracker.begin()
    with pytest.raises(ai.AIError) as error: tracker.begin()
    assert error.value.code == "ai_local_limit"
    assert tracker.attempted == 5


def test_status_and_endpoint_contracts_hide_keys(monkeypatch):
    enable_live(monkeypatch)
    with TestClient(app) as client:
        status = client.get("/api/ai/status")
        assert status.json()["gemini_ready"] is True
        assert "backend-test-key" not in status.text
        response = client.post("/api/explain?filename=sample.yaml&check_id=CKV_K8S_16&provider=mock&privileged_access=required", content=CONTENT)
        assert response.status_code == 200
        assert response.json()["status"] == "mock"
        assert response.json()["requirements"]["privileged_access"] == "required"
        assert response.json()["usage"]["external_requests_this_action"] == 0
        assert "backend-test-key" not in response.text
        assert client.post("/api/explain?filename=x.yaml&check_id=CKV_K8S_16&provider=other", content=CONTENT).status_code == 422
        assert client.post("/api/explain?filename=x.yaml&check_id=CKV_K8S_16&api_access=maybe", content=CONTENT).status_code == 422
        assert client.post("/api/explain?filename=x.yaml&check_id=CKV_K8S_16", content=b"x" * (256 * 1024 + 1)).status_code == 413
        monkeypatch.delenv("GEMINI_API_KEY")
        missing = client.post("/api/explain?filename=x.yaml&check_id=CKV_K8S_16&provider=gemini", content=CONTENT)
        assert missing.status_code == 503
        assert missing.json()["error"]["code"] == "ai_key_missing"
        assert client.get("/health").json()["status"] == "ok"


def test_settings_repr_does_not_include_key():
    assert "very-private-key" not in repr(AISettings(api_key="very-private-key"))


@pytest.mark.skipif(not checkov_scanner.SCANNER_EXECUTABLE.is_file(), reason="Install the isolated scanner for real scanner integration")
def test_mock_endpoint_with_real_scanner_without_cloud(monkeypatch):
    monkeypatch.setattr(ai, "scan_deployment", checkov_scanner.scan_deployment)
    def forbidden(*args, **kwargs):
        raise AssertionError("A mock explanation must not construct a cloud client")
    monkeypatch.setattr(genai, "Client", forbidden)
    with TestClient(app) as client:
        response = client.post("/api/explain?filename=sample.yaml&check_id=CKV_K8S_16&provider=mock", content=CONTENT)
        assert response.status_code == 200
        result = response.json()
        assert result["status"] == "mock"
        assert result["proposal"]["source_document_ids"] == ["pss-privileged"]
        assert result["usage"]["external_requests_this_action"] == 0

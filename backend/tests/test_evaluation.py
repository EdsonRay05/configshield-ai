"""Evaluation contracts and metrics, with no live model or external tool calls."""
from copy import deepcopy
import hashlib
import json

import pytest
import yaml

from app.schemas import ApplicationRequirements, SchemaValidation, ScanResponse, SecurityFinding
from app.services.ai_provider import AIError, ProviderReply
from app.services.patcher import CONTAINER, DEFAULT_CHANGES
from app.services.yaml_parser import parse_manifest
from evaluation import runner
from evaluation.cases import DATASET_PATH, build_dataset, load_dataset
from evaluation.metrics import measured_rate, requirement_oracle, summarize


def case(check="16", variant="explicit"):
    return next(item for item in load_dataset()["cases"] if item["case_id"] == f"ckv_k8s_{check}-{variant}")


class FakeTools:
    def __init__(self): self.scan_calls = self.schema_calls = 0
    def schema(self, content, name):
        self.schema_calls += 1
        manifest = yaml.safe_load(content)
        replicas = manifest["spec"].get("replicas", 1)
        return SchemaValidation(status="passed" if type(replicas) is int else "failed", code="test", message="Mocked schema")
    def scan(self, content, filename):
        self.scan_calls += 1
        manifest, parsed = parse_manifest(content, filename)
        security = manifest["spec"]["template"]["spec"]["containers"][0]["securityContext"]
        failed = []
        if security.get("privileged") is True: failed.append("CKV_K8S_16")
        if security.get("allowPrivilegeEscalation") is True: failed.append("CKV_K8S_20")
        return ScanResponse(status="completed", scanner_version="test-version", deployment=parsed.deployment,
            supported_checks=list(DEFAULT_CHANGES), passed_checks=[check for check in DEFAULT_CHANGES if check not in failed],
            skipped_checks=[], warnings=[], findings=[SecurityFinding(check_id=check,description="Controlled finding",category="test",
                resource=f"Deployment.{parsed.deployment.namespace}.{parsed.deployment.name}", line_range=[], evaluated_keys=[]) for check in failed])


def test_dataset_is_reproducible_and_expectations_are_explicit():
    dataset = load_dataset()
    assert dataset == build_dataset()
    assert dataset["case_count"] == 42
    assert len({item["case_id"] for item in dataset["cases"]}) == 42
    assert sum(item["expected"]["model_eligible"] for item in dataset["cases"]) == 34
    assert sum(item["fixture_fault"] is not None for item in dataset["cases"]) == 7
    assert sum(not item["expected"]["target_present"] for item in dataset["cases"]) == 1
    for item in dataset["cases"]:
        assert hashlib.sha256(item["yaml"].encode()).hexdigest() == item["sha256"]
        parse_manifest(item["yaml"].encode(), "case.yaml")
        ApplicationRequirements(**item["requirements"])


def test_prompt_arms_differ_only_in_guidance_and_requirements():
    item = case(variant="intent")
    prompts = {arm: json.loads(runner.prompt_for(item, arm)) for arm in ("A", "B", "C")}
    assert "guidance" not in prompts["A"] and "requirements" not in prompts["A"]
    assert "guidance" in prompts["B"] and "requirements" not in prompts["B"]
    assert prompts["C"]["requirements"]["privileged_access"] == "required"
    assert prompts["A"]["evidence"] == prompts["B"]["evidence"] == prompts["C"]["evidence"]
    assert {key:value for key,value in prompts["C"].items() if key not in {"guidance","requirements"}} == prompts["A"]
    for prompt in prompts.values():
        assert not {"expected", "fixture_fault", "allowed_candidates", "yaml"} & prompt.keys()


def test_context_names_environment_values_and_labels_do_not_leak_into_prompts():
    prompt = runner.prompt_for(case(variant="context"), "C")
    assert "controlled-context" not in prompt
    assert "DEMO_MODE" not in prompt
    assert "ckv-k8s-16-context" not in prompt


def test_request_budget_never_permits_an_implicit_request():
    with pytest.raises(ValueError): runner.RequestBudget(0).consume()
    budget = runner.RequestBudget(3)
    for _ in range(3): budget.consume()
    with pytest.raises(ValueError): budget.consume()
    assert budget.attempted == 3
    for invalid in (-1, 4, True):
        with pytest.raises(ValueError): runner.RequestBudget(invalid)


def test_fixture_candidates_are_identical_across_arms():
    item = case()
    changes = [json.loads(runner.fixture_reply(item, arm))["candidates"] for arm in ("A","B","C")]
    assert changes[0] == changes[1] == changes[2]
    assert json.loads(runner.fixture_reply(item,"A"))["source_document_ids"] == []


def test_independent_oracle_catches_conflict_without_using_system_checker():
    item = case(variant="intent")
    manifest = yaml.safe_load(item["yaml"])
    manifest["spec"]["template"]["spec"]["containers"][0]["securityContext"]["privileged"] = False
    assert requirement_oracle(item,manifest) is False
    root_case = case("23","intent")
    root_manifest = yaml.safe_load(root_case["yaml"])
    root_manifest["spec"]["template"]["spec"]["containers"][0]["securityContext"]["runAsUser"] = 10001
    assert requirement_oracle(root_case,root_manifest) is False
    assert requirement_oracle(case("20","intent"),manifest) is None


def test_common_observer_keeps_raw_quality_separate_from_c_gate():
    item = case(variant="intent")
    tools = FakeTools()
    baseline = tools.scan(item["yaml"].encode(),"case.yaml")
    a = runner.assess(item,"A",runner.fixture_reply(item,"A"),tools,baseline)
    c = runner.assess(item,"C",runner.fixture_reply(item,"C"),tools,baseline)
    assert a["target_repaired"] is c["target_repaired"] is True
    assert a["requirements_preserved"] is c["requirements_preserved"] is False
    assert a["raw_reliable_candidate"] is c["raw_reliable_candidate"] is False
    assert a["decision"] == "candidate_returned" and c["decision"] == "blocked"


def test_fault_injection_records_schema_failure_and_new_findings():
    tools = FakeTools()
    for check, field in (("16","schema_valid"),("20","has_new_findings")):
        item = case(check,"fault")
        baseline = tools.scan(item["yaml"].encode(),"case.yaml")
        row = runner.assess(item,"A",runner.fixture_reply(item,"A"),tools,baseline)
        assert row[field] is (False if field == "schema_valid" else True)
        assert row["output_failure"] is True


def test_malformed_and_abstaining_outputs_stay_in_denominators():
    tools = FakeTools()
    item = case()
    baseline = tools.scan(item["yaml"].encode(),"case.yaml")
    bad = runner.assess(item,"A","not JSON",tools,baseline)
    proposal = json.loads(runner.fixture_reply(item,"A")); proposal["candidates"] = []
    abstain = runner.assess(item,"A",json.dumps(proposal),tools,baseline)
    summary = summarize([bad,abstain])["A"]
    assert summary["target_cases"] == 2
    assert summary["target_repair"]["true"] == 0
    assert summary["target_repair"]["measured"] == 2
    assert summary["candidate_coverage"]["true"] == 0
    assert summary["failure_or_unsupported_output_rate"]["true"] == 1


def test_unknown_is_not_a_schema_or_requirement_pass():
    result = measured_rate([{"value":True},{"value":False},{"value":None}],"value")
    assert result == {"true":1,"measured":2,"unknown":1,"rate":0.5}


def test_offline_run_never_constructs_a_cloud_provider(monkeypatch):
    monkeypatch.setattr(runner,"ToolCache",FakeTools)
    def forbidden(*args,**kwargs): raise AssertionError("Offline run must not construct Gemini")
    monkeypatch.setattr(runner,"GeminiProvider",forbidden)
    report = runner.run(load_dataset(),[case()],"fixtures",runner.RequestBudget(0),progress=lambda _:None)
    assert report["run_status"] == "complete"
    assert report["not_a_model_experiment"] is True
    assert report["external_requests_attempted"] == 0
    assert len(report["rows"]) == 3


def test_live_pilot_stops_after_quota_error_without_retry_or_fallback(monkeypatch):
    monkeypatch.setattr(runner,"ToolCache",FakeTools)
    monkeypatch.setattr(runner,"ensure_live_settings",lambda _:None)
    calls = []
    class Provider:
        def __init__(self,*args,**kwargs): pass
        def generate(self,prompt):
            calls.append(prompt)
            raise AIError("ai_quota_exhausted","Controlled quota error",429)
    monkeypatch.setattr(runner,"GeminiProvider",Provider)
    checkpoints = []
    report = runner.run(load_dataset(),[case()],"live",runner.RequestBudget(3),
                        checkpoint=lambda value:checkpoints.append(deepcopy(value)),progress=lambda _:None)
    assert len(calls) == report["external_requests_attempted"] == 1
    assert report["run_status"] == "incomplete"
    assert checkpoints[0]["pending_attempt"] is not None
    assert checkpoints[0]["external_requests_attempted"] == 1


def test_live_rejects_fault_fixtures_and_inadequate_budget(monkeypatch):
    monkeypatch.setattr(runner,"ensure_live_settings",lambda _:None)
    with pytest.raises(ValueError): runner.run(load_dataset(),[case(variant="fault")],"live",runner.RequestBudget(3))
    with pytest.raises(ValueError): runner.run(load_dataset(),[case()],"live",runner.RequestBudget(0))


@pytest.mark.parametrize("name",["../outside.json","C:\\outside.json","CON.json","report.txt","/tmp/results.json"])
def test_output_names_stay_in_generated_results_directory(name):
    with pytest.raises(ValueError): runner.output_path(name)


def test_real_tool_cache_is_keyed_by_actual_bytes_not_labels(monkeypatch):
    calls = []
    fake = FakeTools()
    monkeypatch.setattr(runner,"scan_deployment",lambda content,filename: (calls.append(content),fake.scan(content,filename))[1])
    cache = runner.ToolCache()
    content = case()["yaml"].encode()
    first = cache.scan(content,"case.yaml")
    first.findings.clear()
    assert cache.scan(content,"another-name.yaml").findings
    assert len(calls) == 1

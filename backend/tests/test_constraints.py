"""Known intent conflicts, uncertainty, and effective pod/container settings."""
from copy import deepcopy
from pathlib import Path

import pytest

from app.schemas import ApplicationRequirements
from app.services.constraint_checker import check_constraints
from app.services.patcher import DEFAULT_CHANGES, apply_allowlisted_changes
from app.schemas import CandidateChange
from app.services.yaml_parser import parse_manifest

CONTENT = (Path(__file__).resolve().parents[2] / "samples" / "insecure-deployment.yaml").read_bytes()


def assessment(check_id, requirements, mutate=None):
    original, _ = parse_manifest(CONTENT, "sample.yaml")
    if mutate: mutate(original["spec"]["template"]["spec"])
    path, value = DEFAULT_CHANGES[check_id]
    candidate = apply_allowlisted_changes(original, check_id, [CandidateChange(path=path, value=value, rationale="Test")])
    return check_constraints(original, candidate, requirements)


def statuses(report):
    return {result.requirement: result.status for result in report.results}


@pytest.mark.parametrize("check_id,requirements,conflict", [
    ("CKV_K8S_16", ApplicationRequirements(privileged_access="required"), "privileged_access"),
    ("CKV_K8S_38", ApplicationRequirements(api_access="required"), "api_access"),
    ("CKV_K8S_23", ApplicationRequirements(non_root_compatibility="incompatible"), "non_root_compatibility"),
])
def test_declared_requirements_independently_block_conflicting_changes(check_id, requirements, conflict):
    report = assessment(check_id, requirements)
    assert report.status == "conflict"
    assert statuses(report)[conflict] == "conflict"


def test_known_compatible_requirements_are_preserved_but_runtime_is_not_proven():
    report = assessment("CKV_K8S_16", ApplicationRequirements(api_access="not_required", privileged_access="not_required", non_root_compatibility="compatible"))
    result = statuses(report)
    assert result["api_access"] == result["privileged_access"] == result["non_root_compatibility"] == "preserved"
    assert result["runtime_compatibility"] == "unverifiable"
    assert report.status == "manual_review"


def test_unknown_requirements_are_never_reported_as_passed():
    report = assessment("CKV_K8S_16", ApplicationRequirements())
    assert all(result.status == "unverifiable" for result in report.results)
    assert report.status == "manual_review"


def test_existing_explicit_api_credentials_cannot_be_verified():
    report = assessment("CKV_K8S_16", ApplicationRequirements(api_access="required"), lambda pod: pod.update(automountServiceAccountToken=False))
    assert statuses(report)["api_access"] == "unverifiable"


def test_existing_privileged_requirement_preserved_when_unrelated_setting_changes():
    report = assessment("CKV_K8S_31", ApplicationRequirements(privileged_access="required"))
    assert statuses(report)["privileged_access"] == "preserved"
    assert statuses(report)["seccomp_compatibility"] == "unverifiable"
    assert any("overrides" in result.message for result in report.results)


def test_root_user_and_non_root_setting_are_a_conflict():
    def root_user(pod): pod["securityContext"] = {"runAsUser": 0}
    report = assessment("CKV_K8S_23", ApplicationRequirements(non_root_compatibility="compatible"), root_user)
    assert statuses(report)["execution_identity"] == "conflict"


def test_container_user_overrides_pod_user():
    def users(pod):
        pod["securityContext"] = {"runAsUser": 0}
        pod["containers"][0]["securityContext"]["runAsUser"] = 10001
    report = assessment("CKV_K8S_23", ApplicationRequirements(non_root_compatibility="compatible"), users)
    assert "execution_identity" not in statuses(report)
    assert report.status == "manual_review"


@pytest.mark.parametrize("check_id,key", [("CKV_K8S_28", "capability_compatibility"), ("CKV_K8S_37", "capability_compatibility"), ("CKV_K8S_31", "seccomp_compatibility"), ("CKV_K8S_20", "privilege_escalation_effectiveness")])
def test_additional_permission_effects_remain_manual_review(check_id, key):
    assert statuses(assessment(check_id, ApplicationRequirements()))[key] == "unverifiable"


def test_constraint_checker_does_not_modify_either_manifest():
    original, _ = parse_manifest(CONTENT, "sample.yaml")
    candidate = deepcopy(original)
    before_original, before_candidate = deepcopy(original), deepcopy(candidate)
    check_constraints(original, candidate, ApplicationRequirements())
    assert original == before_original and candidate == before_candidate

"""Reproducible, annotated synthetic Deployments; no model-generated ground truth."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import yaml

from app.schemas import ApplicationRequirements
from app.services.patcher import CONTAINER, DEFAULT_CHANGES

DATASET_PATH = Path(__file__).with_name("cases.json")
REFERENCE_PATH = Path(__file__).resolve().parents[2] / "samples" / "secure-deployment.yaml"
KNOWN_REQUIREMENTS = ApplicationRequirements(api_access="not_required", privileged_access="not_required", non_root_compatibility="compatible").model_dump()
VARIANTS = ("explicit", "omitted", "context", "intent", "combined", "fault")


def make_insecure(manifest, check_id, omitted=False, context=False):
    pod = manifest["spec"]["template"]["spec"]
    security = pod["containers"][0]["securityContext"]
    if check_id == "CKV_K8S_16":
        if omitted: security.pop("privileged", None)
        else: security["privileged"] = True
    elif check_id == "CKV_K8S_20":
        if omitted: security.pop("allowPrivilegeEscalation", None)
        else: security["allowPrivilegeEscalation"] = True
    elif check_id == "CKV_K8S_23":
        pod["securityContext"].pop("runAsUser", None)
        security.pop("runAsUser", None)
        if omitted:
            pod["securityContext"].pop("runAsNonRoot", None)
            security.pop("runAsNonRoot", None)
        else:
            pod["securityContext"]["runAsNonRoot"] = bool(context)
            security["runAsNonRoot"] = False
    elif check_id in {"CKV_K8S_28", "CKV_K8S_37"}:
        if omitted: security.pop("capabilities", None)
        else: security["capabilities"] = {"drop": ["CHOWN"] if check_id == "CKV_K8S_28" else ["NET_RAW"]}
    elif check_id == "CKV_K8S_31":
        if omitted or context: pod["securityContext"].pop("seccompProfile", None)
        else: pod["securityContext"]["seccompProfile"] = {"type": "Unconfined"}
        if context: security["seccompProfile"] = {"type": "Unconfined"}
    elif check_id == "CKV_K8S_38":
        if omitted: pod.pop("automountServiceAccountToken", None)
        else: pod["automountServiceAccountToken"] = True


def build_dataset():
    reference_bytes = REFERENCE_PATH.read_bytes()
    base = yaml.safe_load(reference_bytes)
    records = []
    for check_id in DEFAULT_CHANGES:
        for variant in VARIANTS:
            manifest = deepcopy(base)
            case_id = f"{check_id.lower()}-{variant}"
            manifest["metadata"]["name"] = case_id.replace("_", "-")
            make_insecure(manifest, check_id, omitted=variant == "omitted", context=variant == "context")
            requirements = deepcopy(KNOWN_REQUIREMENTS)
            forbidden = []
            needs_abstention = False
            if variant == "intent":
                if check_id == "CKV_K8S_16": requirements["privileged_access"] = "required"
                elif check_id == "CKV_K8S_23": requirements["non_root_compatibility"] = "incompatible"
                elif check_id == "CKV_K8S_38": requirements["api_access"] = "required"
                else: requirements = ApplicationRequirements().model_dump()
                if check_id in {"CKV_K8S_16", "CKV_K8S_23", "CKV_K8S_38"}:
                    path, value = DEFAULT_CHANGES[check_id]
                    forbidden = [{"path": path, "value": value}]
                    needs_abstention = True
            if variant == "context":
                manifest["metadata"]["annotations"] = {"example.org/preserve": "controlled-context"}
                manifest["spec"]["replicas"] = 2
                manifest["spec"]["template"]["spec"]["containers"][0]["env"] = [{"name": "DEMO_MODE", "value": "test"}]
            expected_failed = {check_id}
            if check_id == "CKV_K8S_16" and variant == "omitted": expected_failed = set()
            if check_id == "CKV_K8S_28" or (check_id == "CKV_K8S_37" and variant == "omitted"):
                expected_failed = {"CKV_K8S_28", "CKV_K8S_37"}
            if variant == "combined":
                secondary = "CKV_K8S_38" if check_id == "CKV_K8S_20" else "CKV_K8S_20"
                make_insecure(manifest, secondary)
                expected_failed.add(secondary)
            necessary_paths = [DEFAULT_CHANGES[check_id][0]]
            note = "Expected outcomes are annotations, not measurements. Runtime compatibility is not assessed."
            if check_id == "CKV_K8S_31" and variant == "context":
                necessary_paths = [CONTAINER + "seccompProfile/type"]
                note += " A container-owned profile must be reviewed at container level; a pod default alone does not override it. This probes selected-scanner coverage limits."
            fault = None
            if variant == "fault":
                fault = {"CKV_K8S_16": "invalid_replicas", "CKV_K8S_20": "new_privileged_finding",
                         "CKV_K8S_23": "unrelated_label", "CKV_K8S_28": "invalid_capability_type",
                         "CKV_K8S_31": "unrelated_image", "CKV_K8S_37": "malformed_json",
                         "CKV_K8S_38": "abstention"}[check_id]
            text = yaml.safe_dump(manifest, sort_keys=False)
            records.append({"case_id": case_id, "variant": variant, "check_id": check_id,
                            "yaml": text, "sha256": hashlib.sha256(text.encode()).hexdigest(),
                            "requirements": requirements,
                            "expected": {"failed_checks": sorted(expected_failed), "target_present": check_id in expected_failed,
                                         "model_eligible": variant != "fault" and check_id in expected_failed,
                                         "needs_abstention": needs_abstention, "forbidden_changes": forbidden,
                                         "necessary_paths": necessary_paths, "requirements_scorable": "unknown" not in requirements.values()},
                            "fixture_fault": fault, "notes": note})
    return {"dataset_version": 1, "seed": 20261117, "case_count": len(records),
            "reference_sha256": hashlib.sha256(reference_bytes).hexdigest(), "cases": records}


def load_dataset():
    data = json.loads(DATASET_PATH.read_text(encoding="utf-8"))
    if data != build_dataset():
        raise ValueError("Dataset differs from its reproducible generator/reference. Review and regenerate it explicitly.")
    return data


if __name__ == "__main__":
    data = build_dataset()
    DATASET_PATH.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {data['case_count']} controlled cases to {DATASET_PATH.name}")

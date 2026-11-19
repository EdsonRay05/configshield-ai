"""Allowlisted assignments on a copy; no arbitrary JSON Patch or whole-file replacement."""
from copy import deepcopy

from app.schemas import CandidateChange

CONTAINER = "/spec/template/spec/containers/0/securityContext/"
DEFAULT_CHANGES = {
    "CKV_K8S_16": (CONTAINER + "privileged", False),
    "CKV_K8S_20": (CONTAINER + "allowPrivilegeEscalation", False),
    "CKV_K8S_23": (CONTAINER + "runAsNonRoot", True),
    "CKV_K8S_28": (CONTAINER + "capabilities/drop", ["ALL"]),
    "CKV_K8S_31": ("/spec/template/spec/securityContext/seccompProfile/type", "RuntimeDefault"),
    "CKV_K8S_37": (CONTAINER + "capabilities/drop", ["ALL"]),
    "CKV_K8S_38": ("/spec/template/spec/automountServiceAccountToken", False),
}


class PatchError(ValueError):
    def __init__(self, code: str, message: str, status_code: int = 422):
        super().__init__(message)
        self.code = code
        self.status_code = status_code


def validate_changes(check_id: str, changes: list[CandidateChange]):
    if check_id not in DEFAULT_CHANGES or len(changes) > 3:
        raise PatchError("unsupported_patch", "The selected check or number of changes is unsupported.")
    path, value = DEFAULT_CHANGES[check_id]
    allowed_paths = {path}
    if check_id == "CKV_K8S_31":
        allowed_paths.add(CONTAINER + "seccompProfile/type")
    seen = set()
    for change in changes:
        if change.path not in allowed_paths or change.path in seen:
            raise PatchError("unsupported_patch", "A change is unrelated to the selected check or repeats a field.")
        if type(change.value) is not type(value) or change.value != value:
            raise PatchError("unsupported_patch", "The proposed value is outside the supported remediation values.")
        seen.add(change.path)


def same_value(left, right):
    """Keep YAML booleans distinct from integers during semantic comparison."""
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(same_value(left[key], right[key]) for key in left)
    if isinstance(left, list):
        return len(left) == len(right) and all(same_value(a, b) for a, b in zip(left, right))
    return left == right


def semantic_changed_paths(original, candidate, path="") -> list[str]:
    """Describe field changes independently of YAML comments or formatting."""
    if same_value(original, candidate):
        return []
    if isinstance(original, dict) and isinstance(candidate, dict):
        changed = []
        for key in sorted(original.keys() | candidate.keys()):
            child_path = path + "/" + key.replace("~", "~0").replace("/", "~1")
            if key not in original:
                if isinstance(candidate[key], dict) and candidate[key]:
                    changed.extend(semantic_changed_paths({}, candidate[key], child_path))
                else:
                    changed.append(child_path)
            elif key not in candidate:
                changed.append(child_path)
            else:
                changed.extend(semantic_changed_paths(original[key], candidate[key], child_path))
        return changed
    if path == "/spec/template/spec/containers" and isinstance(original, list) and isinstance(candidate, list) and len(original) == len(candidate):
        return [changed for index, (old, new) in enumerate(zip(original, candidate))
                for changed in semantic_changed_paths(old, new, f"{path}/{index}")]
    return [path]


def apply_allowlisted_changes(original: dict, check_id: str, changes: list[CandidateChange]) -> dict:
    """Simulate approved field assignments on a deepcopy; never mutate the input."""
    validate_changes(check_id, changes)
    candidate = deepcopy(original)
    for change in changes:
        parts = change.path.lstrip("/").split("/")
        node = candidate
        for part in parts[:-1]:
            if isinstance(node, list):
                if part != "0" or len(node) != 1:
                    raise PatchError("unsupported_patch_structure", "The candidate must target the single supported container.")
                node = node[0]
            elif isinstance(node, dict):
                if part not in node:
                    node[part] = {}
                node = node[part]
            else:
                raise PatchError("unsupported_patch_structure", "A patch parent is not a mapping. No candidate was created.")
        if not isinstance(node, dict):
            raise PatchError("unsupported_patch_structure", "The target parent must be a mapping.")
        node[parts[-1]] = deepcopy(change.value)
    changed = semantic_changed_paths(original, candidate)
    if not set(changed) <= {change.path for change in changes}:
        raise PatchError("unrelated_changes", "Unrelated configuration fields changed; the candidate was rejected.")
    return candidate

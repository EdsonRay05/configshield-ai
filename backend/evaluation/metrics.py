"""Common post-hoc scoring; expectations stay distinct from observed tool output."""
from app.services.patcher import same_value, semantic_changed_paths


def pointer_value(manifest, path):
    current = manifest
    try:
        for part in path.lstrip("/").split("/"):
            part = part.replace("~1", "/").replace("~0", "~")
            current = current[int(part)] if isinstance(current, list) else current[part]
        return current
    except (KeyError, IndexError, ValueError, TypeError):
        return None


def requirement_oracle(case, candidate):
    """Use the predeclared case oracle, not ConfigShield's constraint checker."""
    if candidate is None or not case["expected"]["requirements_scorable"]:
        return None
    for forbidden in case["expected"]["forbidden_changes"]:
        if same_value(pointer_value(candidate, forbidden["path"]), forbidden["value"]):
            return False
    # Cover alternate non-root assignments too, without consulting the system gate.
    if case["requirements"]["non_root_compatibility"] == "incompatible":
        pod = pointer_value(candidate, "/spec/template/spec")
        if not isinstance(pod, dict): return None
        containers = pod.get("containers", [])
        context = containers[0].get("securityContext", {}) if isinstance(containers, list) and containers and isinstance(containers[0], dict) else {}
        pod_context = pod.get("securityContext", {})
        if isinstance(context, dict) and isinstance(pod_context, dict):
            user = context.get("runAsUser", pod_context.get("runAsUser"))
            if context.get("runAsNonRoot", pod_context.get("runAsNonRoot")) is True or (type(user) is int and user > 0):
                return False
    return True


def unnecessary_changes(case, original, candidate):
    if candidate is None:
        return None
    necessary = set(case["expected"]["necessary_paths"])
    return [path for path in semantic_changed_paths(original, candidate) if path not in necessary]


def measured_rate(rows, field):
    values = [row[field] for row in rows if type(row.get(field)) is bool]
    return {"true": sum(values), "measured": len(values), "unknown": len(rows) - len(values),
            "rate": sum(values) / len(values) if values else None}


def summarize(rows):
    summaries = {}
    for arm in ("A", "B", "C"):
        all_rows = [row for row in rows if row["arm"] == arm]
        active = [row for row in all_rows if row["target_present"]]
        summaries[arm] = {
            "cases": len(all_rows), "target_cases": len(active),
            "negative_controls": len(all_rows) - len(active),
            "candidate_coverage": measured_rate(active, "candidate_produced"),
            "target_repair": measured_rate(active, "target_repaired"),
            "schema_validity": measured_rate(active, "schema_valid"),
            "new_finding_rate": measured_rate(active, "has_new_findings"),
            "declared_requirement_preservation": measured_rate(active, "requirements_preserved"),
            "raw_reliable_candidate_rate": measured_rate(active, "raw_reliable_candidate"),
            "failure_or_unsupported_output_rate": measured_rate(active, "output_failure"),
            "eligible_for_review": sum(row["decision"] == "eligible_for_review" for row in active),
            "returned_candidates": sum(row["candidate_produced"] for row in active),
            "exposed_unreliable_candidates": sum(row["decision"] in {"candidate_returned", "eligible_for_review"} and row["raw_reliable_candidate"] is False for row in active),
            "exposed_unknown_quality_candidates": sum(row["decision"] in {"candidate_returned", "eligible_for_review"} and row["raw_reliable_candidate"] is None for row in active),
            "blocked": sum(row["decision"] == "blocked" for row in active),
            "abstentions": sum(row["decision"] == "abstained" for row in active),
            "unnecessary_semantic_fields": sum(row.get("unnecessary_field_count") or 0 for row in active),
            "external_requests": sum(row["external_requests"] for row in all_rows),
            "reported_tokens": sum(row.get("total_tokens") or 0 for row in all_rows),
            "unknown_token_usage": sum(row["external_requests"] > 0 and row.get("total_tokens") is None for row in all_rows),
        }
    return summaries

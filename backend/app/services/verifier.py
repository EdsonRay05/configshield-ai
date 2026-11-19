"""Independent candidate checks; never generates AI output or deploys a manifest."""
import hashlib

from app.schemas import VerificationCheck, VerificationRequest, VerificationResponse
from app.services.checkov_scanner import SUPPORTED_CHECKS, ScannerError, scan_deployment
from app.services.constraint_checker import check_constraints
from app.services.kubeconform_validator import validate_schema
from app.services.patcher import PatchError, apply_allowlisted_changes, same_value, semantic_changed_paths
from app.services.yaml_parser import ManifestError, parse_manifest


def verify_candidate(request: VerificationRequest, *, scan_fn=None, schema_fn=None) -> VerificationResponse:
    # Evaluation may supply memoized real tools; application endpoints use defaults.
    run_scan = scan_fn if scan_fn is not None else scan_deployment
    run_schema = schema_fn if schema_fn is not None else validate_schema
    original_bytes = request.original_yaml.encode("utf-8")
    candidate_bytes = request.candidate_yaml.encode("utf-8")
    digest = hashlib.sha256(original_bytes).hexdigest()
    if digest != request.original_sha256:
        raise PatchError("original_changed", "The original bytes differ from the reviewed input. Re-scan before verification.", 409)
    checks = []
    report = VerificationResponse(
        status="incomplete", original_sha256=digest,
        candidate_sha256=hashlib.sha256(candidate_bytes).hexdigest(), checks=checks,
        resolved_findings=[], new_findings=[], remaining_findings=[],
        semantic_changed_paths=[], unexpected_changed_paths=[],
        warnings=["Verification covers the seven selected Checkov policies and a strict Kubernetes 1.35.0 Deployment schema only.",
                  "Runtime behavior, admission policies, credentials, images, volumes, and cluster compatibility are not tested.",
                  "The original and candidate are not deployed, persisted, or sent to an AI provider."],
    )

    def add(name, status, message):
        report.checks.append(VerificationCheck(name=name, status=status, message=message))

    add("original_binding", "passed", "Original bytes match the review hash.")
    manifests = {}
    for label, content, filename in (("original", original_bytes, request.filename), ("candidate", candidate_bytes, "candidate.yaml")):
        try:
            manifests[label], _ = parse_manifest(content, filename)
            add(f"{label}_structure", "passed", "YAML parses as one supported Linux Deployment with one application container.")
        except ManifestError as error:
            add(f"{label}_structure", "failed", str(error))
    if len(manifests) != 2:
        report.status = "failed_validation"
        for name in ("authorized_changes", "schema_validation", "original_security_scan", "candidate_security_scan", "finding_comparison", "requirement_checks", "targeted_repair"):
            add(name, "not_run", "Supported manifests are required before this check can run.")
        return report
    original, candidate = manifests["original"], manifests["candidate"]
    effective_seccomp_ok = True
    if request.proposal.check_id == "CKV_K8S_31":
        pod = candidate["spec"]["template"]["spec"]
        context = pod["containers"][0].get("securityContext", {})
        profile = context.get("seccompProfile", pod.get("securityContext", {}).get("seccompProfile"))
        effective_seccomp_ok = (isinstance(profile, dict) and profile.get("type") == "RuntimeDefault"
                                and context.get("privileged") is not True)
        add("effective_seccomp", "passed" if effective_seccomp_ok else "failed",
            "The effective container profile is RuntimeDefault and privileged mode is not enabled. Runtime syscall compatibility is untested." if effective_seccomp_ok else
            "The effective container profile is not RuntimeDefault, or privileged mode bypasses seccomp. A pod default cannot override a container profile; scanner success alone is insufficient.")
    report.semantic_changed_paths = semantic_changed_paths(original, candidate)
    try:
        expected = apply_allowlisted_changes(original, request.proposal.check_id, request.proposal.candidates)
        report.unexpected_changed_paths = semantic_changed_paths(expected, candidate)
        if not same_value(expected, candidate):
            add("authorized_changes", "failed", "Candidate differs from the supported proposal; unexpected changed paths are reported.")
        elif not report.semantic_changed_paths:
            add("authorized_changes", "failed", "No semantic change was made; no repair is claimed.")
        else:
            add("authorized_changes", "passed", "Candidate contains exactly the proposed allowlisted field assignments.")
    except PatchError as error:
        add("authorized_changes", "failed", str(error))
    report.schema_validation = run_schema(candidate_bytes, candidate["metadata"]["name"])
    add("schema_validation", report.schema_validation.status, report.schema_validation.message)

    for label, content, filename in (("original", original_bytes, request.filename), ("candidate", candidate_bytes, "candidate.yaml")):
        try:
            scan = run_scan(content, filename)
            setattr(report, f"{label}_scan", scan)
            if scan.status != "completed" or scan.skipped_checks:
                add(f"{label}_security_scan", "unavailable", "Some selected checks were skipped or incomplete; no complete scan is claimed.")
            else:
                add(f"{label}_security_scan", "passed", "Scanner completed the selected policies; failed security findings are listed separately.")
        except ScannerError as error:
            add(f"{label}_security_scan", "unavailable", str(error))
    original_scan, candidate_scan = report.original_scan, report.candidate_scan
    comparable = (original_scan is not None and candidate_scan is not None
                  and original_scan.status == candidate_scan.status == "completed"
                  and not original_scan.skipped_checks and not candidate_scan.skipped_checks
                  and original_scan.scanner_version == candidate_scan.scanner_version
                  and set(original_scan.supported_checks) == set(candidate_scan.supported_checks) == set(SUPPORTED_CHECKS))
    if comparable:
        old = {(finding.check_id, finding.resource): finding for finding in original_scan.findings}
        new = {(finding.check_id, finding.resource): finding for finding in candidate_scan.findings}
        report.resolved_findings = [old[key] for key in sorted(old.keys() - new.keys())]
        report.new_findings = [new[key] for key in sorted(new.keys() - old.keys())]
        report.remaining_findings = [new[key] for key in sorted(new.keys() & old.keys())]
        add("finding_comparison", "passed", "Findings were compared by check ID and resource identity, not line number.")
        target = request.proposal.check_id
        was_failed = any(finding.check_id == target for finding in original_scan.findings)
        report.targeted_finding_resolved = was_failed and target in candidate_scan.passed_checks and effective_seccomp_ok
        add("targeted_repair", "passed" if report.targeted_finding_resolved else "failed",
            "The targeted original failure now passes its selected check." if report.targeted_finding_resolved else "The targeted failure was absent originally or did not become a passing check.")
    else:
        add("finding_comparison", "unavailable", "A complete comparable pair of scans from the same scanner version and check set is required. No findings are claimed resolved.")
        add("targeted_repair", "not_run", "Comparable complete scans are unavailable.")
    report.constraint_report = check_constraints(original, candidate, request.requirements)
    uncertain = [result for result in report.constraint_report.results
                 if result.status == "unverifiable" and result.requirement != "runtime_compatibility"]
    constraint_status = "failed" if report.constraint_report.status == "conflict" else "manual_review" if uncertain else "passed"
    add("requirement_checks", constraint_status,
        "Potential declared requirement conflict detected." if constraint_status == "failed" else
        "Some declared requirements or permission effects remain unverifiable." if uncertain else
        "No contradiction was detected in the supported declared requirements. Runtime behavior is not proven.")
    add("runtime_compatibility", "manual_review", "No cluster or application runtime tests were performed.")

    by_name = {check.name: check.status for check in report.checks}
    if by_name.get("authorized_changes") == "failed" or report.schema_validation.status == "failed" or not effective_seccomp_ok:
        report.status = "failed_validation"
    elif constraint_status == "failed":
        report.status = "requirement_conflict"
    elif report.new_findings:
        report.status = "new_security_findings"
    elif any(by_name.get(name) != "passed" for name in ("schema_validation", "original_security_scan", "candidate_security_scan", "finding_comparison")):
        report.status = "incomplete"
    elif not report.targeted_finding_resolved or candidate_scan.findings or uncertain:
        report.status = "manual_review"
    else:
        report.status = "verified_supported_checks"
    return report

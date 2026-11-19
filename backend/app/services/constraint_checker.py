"""Static requirement checks independent of model explanations and assertions."""
from app.schemas import ApplicationRequirements, ConstraintReport, ConstraintResult
from app.services.patcher import semantic_changed_paths


def check_constraints(original: dict, candidate: dict, requirements: ApplicationRequirements) -> ConstraintReport:
    before = original["spec"]["template"]["spec"]
    after = candidate["spec"]["template"]["spec"]
    old_context = before["containers"][0].get("securityContext", {})
    context = after["containers"][0].get("securityContext", {})
    pod_context = after.get("securityContext", {})
    results = []

    def add(requirement, status, message):
        results.append(ConstraintResult(requirement=requirement, status=status, message=message))

    mounting_changed = before.get("automountServiceAccountToken") != after.get("automountServiceAccountToken")
    if requirements.api_access == "unknown":
        add("api_access", "unverifiable", "Kubernetes API credential requirements are unknown; no credential behavior is assumed.")
    elif requirements.api_access == "required" and mounting_changed and after.get("automountServiceAccountToken") is False:
        add("api_access", "conflict", "Potential conflict: this change disables automatic credentials although Kubernetes API access is required. Review explicit credentials before changing token mounting.")
    elif requirements.api_access == "required" and after.get("automountServiceAccountToken") is False:
        add("api_access", "unverifiable", "Automatic credentials were already disabled. Other credentials, RBAC, and API reachability cannot be verified here.")
    else:
        add("api_access", "preserved", "No supported change conflicts with the declared API access requirement; runtime credentials and authorization are not proven.")

    if requirements.privileged_access == "unknown":
        add("privileged_access", "unverifiable", "Privileged host/device access requirements are unknown.")
    elif requirements.privileged_access == "required" and context.get("privileged") is not True:
        add("privileged_access", "conflict", "Potential conflict: privileged host/device access is declared required, but the candidate does not enable privileged mode. Investigate narrower permissions with the application owner.")
    else:
        add("privileged_access", "preserved", "The supported settings do not contradict the declared privileged-access requirement; device behavior is not tested.")

    run_as_user = context.get("runAsUser", pod_context.get("runAsUser"))
    run_as_non_root = context.get("runAsNonRoot", pod_context.get("runAsNonRoot"))
    if requirements.non_root_compatibility == "unknown":
        add("non_root_compatibility", "unverifiable", "Non-root image and filesystem compatibility is unknown.")
    elif requirements.non_root_compatibility == "incompatible" and (run_as_non_root is True or (type(run_as_user) is int and run_as_user > 0)):
        add("non_root_compatibility", "conflict", "Potential conflict: the application is declared incompatible with non-root execution, but candidate settings require it.")
    else:
        add("non_root_compatibility", "preserved", "No supported setting contradicts the declared non-root compatibility; image and filesystem behavior remain untested.")

    if run_as_non_root is True and type(run_as_user) is int and run_as_user == 0:
        add("execution_identity", "conflict", "Candidate settings require non-root execution while the effective runAsUser is zero. These settings contradict each other.")
    elif run_as_non_root is not None and type(run_as_non_root) is not bool:
        add("execution_identity", "unverifiable", "The non-root setting is not a supported boolean; schema validation is required.")
    if run_as_user is not None and (type(run_as_user) is not int or run_as_user < 0):
        add("execution_identity", "unverifiable", "The user ID is not a supported non-negative integer; schema validation is required.")

    paths = semantic_changed_paths(original, candidate)
    if any(path.endswith("/capabilities/drop") for path in paths):
        add("capability_compatibility", "unverifiable", "Dropping capabilities can affect application behavior. Specific capability requirements are outside the current requirement controls and need manual review.")
    if any(path.endswith("/seccompProfile/type") for path in paths):
        add("seccomp_compatibility", "unverifiable", "Syscall compatibility cannot be established from this manifest. A privileged container also overrides seccomp restrictions." if context.get("privileged") is True else "Syscall compatibility with the proposed seccomp profile requires runtime review.")
    if old_context.get("allowPrivilegeEscalation") != context.get("allowPrivilegeEscalation") and context.get("privileged") is True:
        add("privilege_escalation_effectiveness", "unverifiable", "Privileged mode can override the intended privilege-escalation restriction; a changed field alone does not establish a repair.")
    add("runtime_compatibility", "unverifiable", "Static requirement checks do not prove runtime compatibility. Schema validation and security scan results are reported separately when available.")
    status = "conflict" if any(result.status == "conflict" for result in results) else (
        "manual_review" if any(result.status == "unverifiable" for result in results) else "preserved")
    return ConstraintReport(status=status, results=results)

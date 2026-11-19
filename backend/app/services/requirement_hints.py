"""Deterministic clues from YAML, separate from owner-confirmed requirements."""


def as_mapping(value):
    return value if isinstance(value, dict) else {}


def infer_requirement_hints(manifest):
    pod = manifest["spec"]["template"]["spec"]
    container = pod["containers"][0]
    pod_context = as_mapping(pod.get("securityContext"))
    context = as_mapping(container.get("securityContext"))
    annotations = as_mapping(manifest.get("metadata", {}).get("annotations"))
    hints = []
    for name, allowed in (
        ("api_access", {"required", "not_required"}),
        ("privileged_access", {"required", "not_required"}),
        ("non_root_compatibility", {"compatible", "incompatible"}),
    ):
        suggested = "unknown"
        evidence = []
        if name == "api_access":
            token = pod.get("automountServiceAccountToken")
            if type(token) is bool:
                evidence.append(f"spec.template.spec.automountServiceAccountToken is {str(token).lower()}; token mounting does not prove API usage.")
            if "serviceAccountName" in pod:
                evidence.append("spec.template.spec.serviceAccountName is present; its permissions and application usage are not known.")
            limitation = "YAML cannot establish whether application code calls the Kubernetes API. Confirm with the application owner or documentation."
        elif name == "privileged_access":
            privileged = context.get("privileged")
            if type(privileged) is bool:
                evidence.append(f"spec.template.spec.containers[0].securityContext.privileged is {str(privileged).lower()}; the current permission is not proof of necessity.")
            volumes = pod.get("volumes", [])
            if isinstance(volumes, list) and any(isinstance(volume, dict) and "hostPath" in volume for volume in volumes):
                evidence.append("spec.template.spec.volumes contains a hostPath; host filesystem access needs review but does not by itself require privileged mode.")
            limitation = "Host or device access requirements depend on application behavior. Do not infer Required solely from an insecure setting."
        else:
            non_root = context.get("runAsNonRoot", pod_context.get("runAsNonRoot"))
            uid = context.get("runAsUser", pod_context.get("runAsUser"))
            if type(non_root) is bool:
                location = "containers[0].securityContext" if "runAsNonRoot" in context else "securityContext"
                evidence.append(f"spec.template.spec.{location}.runAsNonRoot is {str(non_root).lower()}.")
            if type(uid) is int:
                location = "containers[0].securityContext" if "runAsUser" in context else "securityContext"
                evidence.append(f"spec.template.spec.{location}.runAsUser selects {'root (UID 0)' if uid == 0 else 'a positive UID' if uid > 0 else 'an invalid negative UID'}.")
            if (non_root is True or (type(uid) is int and uid > 0)) and not (type(uid) is int and uid <= 0):
                suggested = "compatible"
            limitation = "A configured non-root user suggests intent, not successful execution. Image, filesystem, and runtime compatibility still need confirmation."
        annotation = "configshield.ai/" + name.replace("_", "-")
        declared = annotations.get(annotation)
        if isinstance(declared, str) and declared in allowed:
            suggested = declared
            evidence.append(f"metadata.annotations[{annotation}] contains an explicit requirement declaration; confirm that it is current and accurate.")
        if not evidence:
            evidence.append("No decisive supported setting was found. Missing settings and image names do not establish application requirements.")
        hints.append({"requirement": name, "suggested_value": suggested, "evidence": evidence,
                      "limitation": limitation, "needs_confirmation": True})
    return hints

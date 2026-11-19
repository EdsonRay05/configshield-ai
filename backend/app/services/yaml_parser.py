"""Bounded safe parsing for the narrow MVP scope."""
import yaml
from yaml.events import AliasEvent
from app.schemas import DeploymentSummary, ParseResponse

MAX_FILE_BYTES = 256 * 1024


class ManifestError(ValueError):
    def __init__(self, code: str, message: str, status_code: int = 422):
        super().__init__(message)
        self.code = code
        self.status_code = status_code


class RestrictedSafeLoader(yaml.SafeLoader):
    """Retain safe constructors while bounding composition before construction."""
    def __init__(self, stream):
        super().__init__(stream)
        self.depth = 0
        self.nodes = 0

    def compose_node(self, parent, index):
        if self.check_event(AliasEvent):
            raise ManifestError("unsupported_yaml", "YAML aliases are not supported. Expand them before uploading.")
        self.depth += 1
        self.nodes += 1
        try:
            if self.depth > 40 or self.nodes > 20000:
                raise ManifestError("yaml_complexity", "YAML exceeds the supported nesting or node limit.")
            return super().compose_node(parent, index)
        finally:
            self.depth -= 1

    def construct_mapping(self, node, deep=False):
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str):
                raise ManifestError("unsupported_yaml", "YAML mapping keys must be strings.")
            if key in result:
                raise ManifestError("duplicate_key", "Duplicate YAML keys are not supported.")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def mapping(value, path):
    if not isinstance(value, dict):
        raise ManifestError("invalid_structure", f"{path} must be a mapping.")
    return value


def text_value(value, path):
    if not isinstance(value, str) or not value.strip():
        raise ManifestError("invalid_structure", f"{path} must be a non-empty string.")
    return value


def parse_manifest(content: bytes, filename: str) -> tuple[dict, ParseResponse]:
    """Return a supported manifest and summary; never save or execute content."""
    if len(content) > MAX_FILE_BYTES:
        raise ManifestError("file_too_large", "File exceeds the 256 KiB limit.", 413)
    if not filename.lower().endswith((".yaml", ".yml")):
        raise ManifestError("invalid_extension", "Choose a .yaml or .yml file.", 400)
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise ManifestError("invalid_encoding", "The file must use UTF-8 encoding.") from None
    if not text.strip():
        raise ManifestError("empty_yaml", "The YAML file is empty.")
    loader = None
    try:
        loader = RestrictedSafeLoader(text)
        manifest = loader.get_single_data()
    except yaml.YAMLError:
        # Never reflect uploaded lines (potential secrets) into error messages.
        raise ManifestError("invalid_yaml", "Malformed or unsupported YAML. Upload exactly one YAML document.") from None
    finally:
        if loader is not None:
            loader.dispose()
    manifest = mapping(manifest, "Document")
    if manifest.get("apiVersion") != "apps/v1" or manifest.get("kind") != "Deployment":
        raise ManifestError("unsupported_resource", "Only apps/v1 Deployment resources are supported.")
    metadata = mapping(manifest.get("metadata"), "metadata")
    name = text_value(metadata.get("name"), "metadata.name")
    namespace = text_value(metadata.get("namespace", "default"), "metadata.namespace")
    spec = mapping(manifest.get("spec"), "spec")
    replicas = spec.get("replicas", 1)
    if type(replicas) is not int or replicas < 0:
        raise ManifestError("invalid_structure", "spec.replicas must be a non-negative integer.")
    selector = mapping(spec.get("selector"), "spec.selector")
    if not selector.get("matchLabels") and not selector.get("matchExpressions"):
        raise ManifestError("invalid_structure", "spec.selector needs matchLabels or matchExpressions.")
    template = mapping(spec.get("template"), "spec.template")
    pod = mapping(template.get("spec"), "spec.template.spec")
    if "initContainers" in pod or "ephemeralContainers" in pod:
        raise ManifestError("unsupported_containers", "Init and ephemeral containers are not supported.")
    containers = pod.get("containers")
    if not isinstance(containers, list) or len(containers) != 1:
        raise ManifestError("unsupported_containers", "Exactly one application container is supported.")
    container = mapping(containers[0], "containers[0]")
    container_name = text_value(container.get("name"), "container.name")
    image = text_value(container.get("image"), "container.image")
    os_assumed = "os" not in pod
    if not os_assumed and mapping(pod["os"], "pod.os").get("name") != "linux":
        raise ManifestError("unsupported_os", "Only Linux Deployments are supported.")
    node_selector = mapping(pod.get("nodeSelector", {}), "pod.nodeSelector")
    if node_selector.get("kubernetes.io/os", "linux") != "linux":
        raise ManifestError("unsupported_os", "The node selector must not target a non-Linux OS.")
    for context in [pod.get("securityContext", {}), container.get("securityContext", {})]:
        if "windowsOptions" in mapping(context, "securityContext"):
            raise ManifestError("unsupported_os", "Windows security options are not supported.")
    warnings = ["Parsing checks supported structure only; Kubernetes schema and security validation have not run."]
    if os_assumed:
        warnings.append("Linux is assumed because pod.os is omitted; image compatibility is not verified.")
    from app.services.requirement_hints import infer_requirement_hints
    return manifest, ParseResponse(deployment=DeploymentSummary(
        name=name, namespace=namespace, replicas=replicas, container_name=container_name,
        image=image, os_assumed=os_assumed,
    ), warnings=warnings, requirement_hints=infer_requirement_hints(manifest))


def parse_deployment(content: bytes, filename: str) -> ParseResponse:
    return parse_manifest(content, filename)[1]

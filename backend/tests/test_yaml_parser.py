"""Safety, scope, and HTTP contract checks without AI or external tools."""
from copy import deepcopy
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from app.main import app
from app.services.yaml_parser import MAX_FILE_BYTES, ManifestError, parse_deployment

SAMPLE = Path(__file__).resolve().parents[2] / "samples" / "insecure-deployment.yaml"


@pytest.fixture
def manifest():
    return yaml.safe_load(SAMPLE.read_bytes())


def encode(manifest):
    return yaml.safe_dump(manifest).encode()


def test_supported_sample_and_original_unchanged(manifest):
    original = deepcopy(manifest)
    result = parse_deployment(encode(manifest), "demo.yaml")
    assert result.deployment.name == "insecure-demo"
    assert result.deployment.image == "nginx:1.27"
    assert result.deployment.os_assumed is False
    assert result.warnings
    assert manifest == original


def test_defaults_and_uppercase_extension(manifest):
    del manifest["spec"]["template"]["spec"]["os"]
    del manifest["spec"]["replicas"]
    result = parse_deployment(encode(manifest), "demo.YML")
    assert result.deployment.namespace == "default"
    assert result.deployment.replicas == 1
    assert result.deployment.os_assumed is True
    assert len(result.warnings) == 2


@pytest.mark.parametrize("content,code", [
    (b"", "empty_yaml"),
    (b"   \n", "empty_yaml"),
    (b"metadata: [", "invalid_yaml"),
    (b"\x00", "invalid_yaml"),
    (b"---\nkind: Deployment\n---\nkind: Deployment", "invalid_yaml"),
    (b"null", "invalid_structure"),
    (b"[]", "invalid_structure"),
    (b"kind: Pod", "unsupported_resource"),
    (b"a: 1\na: 2", "duplicate_key"),
    (b"a: &a [*a]", "unsupported_yaml"),
    (b"1: value", "unsupported_yaml"),
    (b"!!python/object/apply:os.system ['echo do-not-execute']", "invalid_yaml"),
    (b"\xff", "invalid_encoding"),
    (b"a: " + b"[" * 45 + b"0" + b"]" * 45, "yaml_complexity"),
    (b"[" + b"0," * 20001 + b"]", "yaml_complexity"),
])
def test_rejected_yaml(content, code):
    with pytest.raises(ManifestError) as error:
        parse_deployment(content, "demo.yaml")
    assert error.value.code == code


def test_file_limit_and_extension():
    with pytest.raises(ManifestError) as error:
        parse_deployment(b" " * (MAX_FILE_BYTES + 1), "demo.yaml")
    assert error.value.status_code == 413
    with pytest.raises(ManifestError) as error:
        parse_deployment(b"kind: Pod", "demo.txt")
    assert error.value.code == "invalid_extension"


@pytest.mark.parametrize("case", [
    "two_containers", "zero_containers", "init", "ephemeral", "windows",
    "windows_selector", "windows_context", "null_pod", "no_name", "no_image",
    "bool_replicas", "negative_replicas", "wrong_version", "null_os",
])
def test_unsupported_or_incomplete_manifest(manifest, case):
    pod = manifest["spec"]["template"]["spec"]
    if case == "two_containers":
        pod["containers"].append({"name": "sidecar", "image": "example"})
    elif case == "zero_containers":
        pod["containers"] = []
    elif case == "init":
        pod["initContainers"] = []
    elif case == "ephemeral":
        pod["ephemeralContainers"] = []
    elif case == "windows":
        pod["os"]["name"] = "windows"
    elif case == "windows_selector":
        pod["nodeSelector"] = {"kubernetes.io/os": "windows"}
    elif case == "windows_context":
        pod["securityContext"] = {"windowsOptions": {}}
    elif case == "null_pod":
        manifest["spec"]["template"]["spec"] = None
    elif case == "no_name":
        del manifest["metadata"]["name"]
    elif case == "no_image":
        del pod["containers"][0]["image"]
    elif case == "bool_replicas":
        manifest["spec"]["replicas"] = True
    elif case == "negative_replicas":
        manifest["spec"]["replicas"] = -1
    elif case == "wrong_version":
        manifest["apiVersion"] = "extensions/v1beta1"
    elif case == "null_os":
        pod["os"] = None
    with pytest.raises(ManifestError):
        parse_deployment(encode(manifest), "demo.yaml")


def test_http_contracts():
    with TestClient(app) as client:
        assert client.get("/health").json()["status"] == "ok"
        result = client.post("/api/parse?filename=sample.yaml", content=SAMPLE.read_bytes())
        assert result.status_code == 200
        assert result.json()["status"] == "parsed"
        assert result.json()["deployment"]["container_name"] == "web"
        invalid = client.post("/api/parse?filename=sample.yaml", content=b"metadata: [")
        assert invalid.status_code == 422
        assert invalid.json()["error"]["code"] == "invalid_yaml"
        assert client.post("/api/parse", content=b"x").status_code == 422
        oversized = client.post("/api/parse?filename=x.yaml", content=b"x" * (MAX_FILE_BYTES + 1))
        assert oversized.status_code == 413


def test_streamed_limit_without_content_length():
    with TestClient(app) as client:
        response = client.post("/api/parse?filename=x.yml", content=iter([b"x" * 131072] * 3))
        assert response.status_code == 413


def test_parser_errors_do_not_echo_uploaded_secrets():
    secret = "sensitive-example-value"
    with TestClient(app) as client:
        response = client.post("/api/parse?filename=x.yaml", content=f"key: [{secret}".encode())
        assert response.status_code == 422
        assert secret not in response.text

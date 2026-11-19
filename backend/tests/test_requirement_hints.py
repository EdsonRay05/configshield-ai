"""Automatic observations never turn an existing permission into a proven need."""
from pathlib import Path
import pytest
import yaml
from fastapi.testclient import TestClient
from app.main import app
from app.services.requirement_hints import infer_requirement_hints

SAMPLE = Path(__file__).resolve().parents[2] / 'samples' / 'insecure-deployment.yaml'


def manifest():
    return yaml.safe_load(SAMPLE.read_bytes())


def hints(data):
    return {hint['requirement']: hint for hint in infer_requirement_hints(data)}


def test_privileged_and_token_permissions_do_not_prove_requirements():
    result = hints(manifest())
    assert result['privileged_access']['suggested_value'] == 'unknown'
    assert result['api_access']['suggested_value'] == 'unknown'
    assert all(hint['needs_confirmation'] is True for hint in result.values())


@pytest.mark.parametrize('pod_setting,container_setting,expected', [
    ({'runAsNonRoot': True}, {}, 'compatible'),
    ({'runAsUser': 1000}, {}, 'compatible'),
    ({'runAsNonRoot': True}, {'runAsNonRoot': False}, 'unknown'),
    ({'runAsUser': 1000}, {'runAsUser': 0}, 'unknown'),
    ({'runAsUser': 0}, {'runAsUser': 1000}, 'compatible'),
    ({'runAsNonRoot': True, 'runAsUser': 0}, {}, 'unknown'),
    ({}, {'runAsUser': True}, 'unknown'),
    ({}, {}, 'unknown'),
])
def test_effective_nonroot_hints_respect_overrides_and_unknowns(pod_setting, container_setting, expected):
    data = manifest()
    pod = data['spec']['template']['spec']
    pod['securityContext'] = pod_setting
    pod['containers'][0]['securityContext'] = container_setting
    assert hints(data)['non_root_compatibility']['suggested_value'] == expected


def test_owner_annotation_is_an_unconfirmed_suggestion_not_an_instruction():
    data = manifest()
    data['metadata']['annotations'] = {
        'configshield.ai/api-access': 'not_required',
        'configshield.ai/privileged-access': 'required',
        'configshield.ai/non-root-compatibility': 'incompatible',
        'unrelated': 'private annotation text',
    }
    result = hints(data)
    assert result['api_access']['suggested_value'] == 'not_required'
    assert result['privileged_access']['suggested_value'] == 'required'
    assert result['non_root_compatibility']['suggested_value'] == 'incompatible'
    assert 'private annotation text' not in str(result)
    assert all(item['needs_confirmation'] for item in result.values())


def test_parser_returns_hints_without_echoing_names_or_environment_secrets():
    data = manifest()
    pod = data['spec']['template']['spec']
    pod['serviceAccountName'] = 'private-account-name'
    pod['containers'][0]['env'] = [{'name': 'SECRET', 'value': 'private-value'}]
    with TestClient(app) as client:
        response = client.post('/api/parse?filename=test.yaml', content=yaml.safe_dump(data), headers={'Content-Type': 'application/yaml'})
    assert response.status_code == 200
    result = response.json()['requirement_hints']
    assert len(result) == 3
    assert 'private-account-name' not in str(result)
    assert 'private-value' not in str(result)

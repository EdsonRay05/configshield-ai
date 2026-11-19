"""Catalog selection shares the real parser and never returns evaluation answers."""
import hashlib
import json
from fastapi.testclient import TestClient
from app.main import app
from app.services import datasets
from app.services.yaml_parser import parse_manifest


def test_all_catalog_cases_are_supported_and_omit_expected_answers():
    with TestClient(app) as client:
        response = client.get('/api/datasets')
        assert response.status_code == 200
        entries = response.json()['entries']
        assert len(entries) == 43
        assert len({entry['id'] for entry in entries}) == 43
        for entry in entries:
            content = client.get('/api/datasets/' + entry['id'])
            assert content.status_code == 200
            data = content.json()
            assert set(data) == {'id', 'filename', 'yaml', 'sha256'}
            assert hashlib.sha256(data['yaml'].encode()).hexdigest() == entry['sha256'] == data['sha256']
            parse_manifest(data['yaml'].encode(), data['filename'])
            assert 'expected' not in entry and 'requirements' not in entry


def test_external_import_provenance_and_checksum():
    record = json.loads((datasets.EXTERNAL_DIR / 'provenance.json').read_text())
    content = (datasets.EXTERNAL_DIR / 'kustomizegoat-base.yaml').read_bytes()
    assert hashlib.sha256(content).hexdigest() == record['file_sha256']
    assert record['modified'] is False


def test_unknown_ids_do_not_resolve_filesystem_paths():
    with TestClient(app) as client:
        for case_id in ['unknown', '.env', 'provenance.json']:
            assert client.get('/api/datasets/' + case_id).status_code == 404


def test_modified_external_case_is_not_served(monkeypatch, tmp_path):
    record = json.loads((datasets.EXTERNAL_DIR / 'provenance.json').read_text())
    (tmp_path / 'provenance.json').write_text(json.dumps(record))
    (tmp_path / 'kustomizegoat-base.yaml').write_text('modified')
    monkeypatch.setattr(datasets, 'EXTERNAL_DIR', tmp_path)
    with TestClient(app) as client:
        assert client.get('/api/datasets/kustomizegoat-base').status_code == 503

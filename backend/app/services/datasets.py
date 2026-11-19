"""Read-only, fixed-ID demo catalog; never imports a client-supplied path."""
import hashlib
import json
from pathlib import Path

from evaluation.cases import load_dataset
from app.services.yaml_parser import parse_manifest

EXTERNAL_DIR = Path(__file__).resolve().parents[3] / "samples" / "external"


def catalog():
    cases = load_dataset()["cases"]
    entries = [{"id": case["case_id"], "title": f'{case["check_id"]} / {case["variant"]}',
                "group": "Controlled synthetic cases", "source_url": None,
                "description": "Synthetic input; evaluation fault labels describe scripted proposals, not extra YAML defects.",
                "sha256": case["sha256"]} for case in cases]
    provenance = json.loads((EXTERNAL_DIR / "provenance.json").read_text(encoding="utf-8"))
    entries.append({"id": "kustomizegoat-base", "title": "KustomizeGoat / insecure base Deployment",
                    "group": "External examples", "source_url": provenance["source_url"],
                    "description": "Original downloaded example. Expected findings and application requirements are not annotated. Linux is assumed when undeclared.",
                    "sha256": provenance["file_sha256"]})
    return entries


def dataset_content(case_id):
    if case_id == "kustomizegoat-base":
        content = (EXTERNAL_DIR / "kustomizegoat-base.yaml").read_bytes()
        provenance = json.loads((EXTERNAL_DIR / "provenance.json").read_text(encoding="utf-8"))
        if hashlib.sha256(content).hexdigest() != provenance["file_sha256"]:
            raise ValueError("External dataset checksum mismatch")
        text = content.decode("utf-8")
    else:
        case = next((case for case in load_dataset()["cases"] if case["case_id"] == case_id), None)
        if case is None:
            raise KeyError(case_id)
        text = case["yaml"]
    parse_manifest(text.encode("utf-8"), "dataset.yaml")
    return {"id": case_id, "filename": f"{case_id}.yaml", "yaml": text,
            "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest()}

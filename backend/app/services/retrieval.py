"""Exact-ID retrieval from reviewed local JSON; no network or model calls."""
import json
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import TypeAdapter, ValidationError

from app.schemas import GuidanceDocument, GuidanceResult

KNOWLEDGE_PATH = Path(__file__).resolve().parents[1] / "knowledge" / "security_guidance.json"
# Explicit mappings avoid guessing relevance from user-controlled prose or tags.
RULE_DOCUMENTS = {
    "CKV_K8S_16": ("pss-privileged", "owasp-least-privilege"),
    "CKV_K8S_20": ("pss-escalation", "owasp-least-privilege"),
    "CKV_K8S_23": ("pss-non-root", "k8s-context-non-root", "owasp-least-privilege"),
    "CKV_K8S_28": ("pss-capabilities", "k8s-context-capabilities", "owasp-least-privilege"),
    "CKV_K8S_31": ("pss-seccomp", "owasp-least-privilege"),
    "CKV_K8S_37": ("pss-capabilities", "k8s-context-capabilities", "owasp-least-privilege"),
    "CKV_K8S_38": ("k8s-service-account", "owasp-token-mounting"),
}
TRUSTED_PAGES = {
    ("kubernetes.io", "/docs/concepts/security/pod-security-standards/"),
    ("kubernetes.io", "/docs/tasks/configure-pod-container/security-context/"),
    ("kubernetes.io", "/docs/tasks/configure-pod-container/configure-service-account/"),
    ("cheatsheetseries.owasp.org", "/cheatsheets/Kubernetes_Security_Cheat_Sheet.html"),
}


class KnowledgeError(ValueError):
    """The local knowledge file is missing or fails its contract."""


def load_knowledge() -> dict[str, GuidanceDocument]:
    """Load and validate the whole small knowledge base, without caching failures."""
    try:
        documents = TypeAdapter(list[GuidanceDocument]).validate_python(
            json.loads(KNOWLEDGE_PATH.read_text(encoding="utf-8"))
        )
        index = {}
        for document in documents:
            if document.document_id in index:
                raise ValueError("Duplicate document ID")
            url = urlsplit(document.source_url)
            if (url.scheme != "https" or url.netloc != url.hostname or url.query
                    or (url.hostname, url.path) not in TRUSTED_PAGES):
                raise ValueError("Unreviewed source URL")
            index[document.document_id] = document
        expected_ids = {document_id for ids in RULE_DOCUMENTS.values() for document_id in ids}
        if set(index) != expected_ids:
            raise ValueError("Knowledge records do not match the reviewed mapping")
        for document_id, document in index.items():
            expected_checks = {check for check, ids in RULE_DOCUMENTS.items() if document_id in ids}
            if len(document.check_ids) != len(set(document.check_ids)) or set(document.check_ids) != expected_checks:
                raise ValueError("Knowledge rule tags do not match the reviewed mapping")
        return index
    except (OSError, UnicodeError, ValueError, ValidationError) as error:
        raise KnowledgeError("Local reviewed guidance is unavailable or invalid.") from error


def retrieve_guidance(check_id: str) -> GuidanceResult:
    """Return ordered reviewed records for an exact rule ID, never a guessed citation."""
    document_ids = RULE_DOCUMENTS.get(check_id)
    if document_ids is None:
        return GuidanceResult(status="missing", documents=[],
                              message="No reviewed guidance is mapped to this check ID.")
    try:
        index = load_knowledge()
    except KnowledgeError:
        return GuidanceResult(status="unavailable", documents=[],
                              message="Local reviewed guidance is unavailable or invalid. Scanner results are separate from retrieval.")
    return GuidanceResult(status="available", documents=[index[document_id] for document_id in document_ids],
                          message="Retrieved reviewed local guidance by exact Checkov ID. Applicability still needs human review.")

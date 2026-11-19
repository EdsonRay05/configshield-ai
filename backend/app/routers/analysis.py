"""Bound upload transport before parsing; uploaded files are not saved."""
from typing import Literal
import hashlib
import yaml
from pydantic import ValidationError
from fastapi import APIRouter, Path, Query, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool
from app.schemas import AIExplanationResponse, ApplicationRequirements, CandidateRequest, CandidateResponse, GuidanceResult, ParseResponse, ScanResponse, VerificationRequest, VerificationResponse
from app.services.verifier import verify_candidate
from app.services.ai_provider import AIError, ProviderReply, ai_status, explain_deployment, validate_proposal
from app.services.patcher import PatchError, apply_allowlisted_changes, same_value, semantic_changed_paths, validate_changes
from app.services.constraint_checker import check_constraints
from app.services.retrieval import retrieve_guidance
from app.services.checkov_scanner import ScannerError, scan_deployment
from app.services.yaml_parser import MAX_FILE_BYTES, ManifestError, parse_deployment, parse_manifest

router = APIRouter(prefix="/api", tags=["analysis"])


@router.get("/datasets")
def list_datasets():
    from app.services.datasets import catalog
    try:
        return {"entries": catalog()}
    except (OSError, ValueError, KeyError):
        return JSONResponse(status_code=503, content={"error": {"message": "Local dataset catalog is unavailable. File upload remains available."}})


@router.get("/datasets/{case_id}")
def get_dataset(case_id: str):
    from app.services.datasets import dataset_content
    try:
        return dataset_content(case_id)
    except KeyError:
        return JSONResponse(status_code=404, content={"error": {"message": "Unknown dataset case."}})
    except (OSError, ValueError, ManifestError):
        return JSONResponse(status_code=503, content={"error": {"message": "Local dataset case is unavailable. File upload remains available."}})


async def read_upload(request: Request, limit: int = MAX_FILE_BYTES) -> bytes:
    content = bytearray()
    async for chunk in request.stream():
        if len(content) + len(chunk) > limit:
            raise ManifestError("file_too_large", f"Request exceeds the {limit // 1024} KiB limit.", 413)
        content.extend(chunk)
    return bytes(content)


def error_response(error):
    return JSONResponse(status_code=error.status_code,
                        content={"error": {"code": error.code, "message": str(error)}})


@router.post("/parse", response_model=ParseResponse)
async def parse_upload(request: Request, filename: str = Query(min_length=1, max_length=255)):
    try:
        return parse_deployment(await read_upload(request), filename)
    except ManifestError as error:
        return error_response(error)


@router.post("/scan", response_model=ScanResponse)
async def scan_upload(request: Request, filename: str = Query(min_length=1, max_length=255)):
    try:
        content = await read_upload(request)
        # Keep a CLI scan from blocking health and parsing requests.
        scan = await run_in_threadpool(scan_deployment, content, filename)
        for finding in scan.findings:
            finding.guidance = retrieve_guidance(finding.check_id)
        return scan
    except (ManifestError, ScannerError) as error:
        return error_response(error)


@router.get("/guidance/{check_id}", response_model=GuidanceResult)
def get_guidance(check_id: str = Path(min_length=1, max_length=64)):
    return retrieve_guidance(check_id)


@router.get("/ai/status")
def get_ai_status():
    return ai_status()


@router.post("/explain", response_model=AIExplanationResponse)
async def explain_upload(
    request: Request,
    filename: str = Query(min_length=1, max_length=255),
    check_id: str = Query(min_length=1, max_length=32),
    provider: Literal["mock", "gemini"] = "mock",
    api_access: Literal["unknown", "required", "not_required"] = "unknown",
    privileged_access: Literal["unknown", "required", "not_required"] = "unknown",
    non_root_compatibility: Literal["unknown", "compatible", "incompatible"] = "unknown",
):
    try:
        content = await read_upload(request)
        requirements = ApplicationRequirements(api_access=api_access, privileged_access=privileged_access,
                                               non_root_compatibility=non_root_compatibility)
        return await run_in_threadpool(explain_deployment, content, filename, check_id, provider, requirements)
    except (ManifestError, ScannerError, AIError) as error:
        return error_response(error)


def prepare_candidate(request: CandidateRequest) -> CandidateResponse:
    content = request.original_yaml.encode("utf-8")
    digest = hashlib.sha256(content).hexdigest()
    if digest != request.original_sha256:
        raise PatchError("original_changed", "The original bytes differ from the reviewed input. Re-scan and request a new proposal.", 409)
    manifest, _ = parse_manifest(content, request.filename)
    validate_changes(request.proposal.check_id, request.proposal.candidates)
    guidance = retrieve_guidance(request.proposal.check_id)
    if guidance.status != "available":
        raise AIError("ai_guidance_unavailable", "Reviewed guidance is unavailable; the candidate was not created.", 503)
    try:
        proposal = validate_proposal(ProviderReply(request.proposal.model_dump_json()), request.proposal.check_id,
                                     {document.document_id for document in guidance.documents})
    except AIError:
        raise PatchError("invalid_candidate_proposal", "The submitted proposal failed supported-field and source validation.") from None
    # The browser cannot assert that this rule failed or that constraints passed.
    scan = scan_deployment(content, request.filename)
    if proposal.check_id not in {finding.check_id for finding in scan.findings}:
        raise PatchError("finding_not_present", "The selected failed finding is no longer present. Re-scan and review the input.", 409)
    candidate = apply_allowlisted_changes(manifest, proposal.check_id, proposal.candidates)
    report = check_constraints(manifest, candidate, request.requirements)
    paths = semantic_changed_paths(manifest, candidate)
    warnings = ["Candidate construction checks supported settings only. Use the independent verification action for schema validation and candidate security re-scanning.",
                "Preserved means no detected contradiction in supported settings; runtime compatibility is not proven.",
                "The original YAML remains unchanged. YAML serialization can change comments and formatting."]
    status = "review_required"
    candidate_yaml = None
    if report.status == "conflict":
        status = "blocked"
    elif not paths:
        status = "no_changes"
    elif request.approved and (report.status != "manual_review" or request.acknowledge_manual_review):
        candidate_yaml = yaml.safe_dump(candidate, sort_keys=False, allow_unicode=True)
        reparsed, _ = parse_manifest(candidate_yaml.encode("utf-8"), "candidate.yaml")
        if not same_value(reparsed, candidate) or set(semantic_changed_paths(manifest, reparsed)) != set(paths):
            raise PatchError("serialization_changed_fields", "Serialization changed unrelated values. The candidate was rejected.")
        status = "candidate_created"
    details = []
    for change in proposal.candidates:
        if change.path not in paths:
            continue
        node = manifest
        present = True
        for part in change.path.lstrip("/").split("/"):
            part = part.replace("~1", "/").replace("~0", "~")
            if isinstance(node, list):
                node = node[int(part)]
            elif isinstance(node, dict) and part in node:
                node = node[part]
            else:
                present = False
                break
        display = lambda value: yaml.safe_dump(value, default_flow_style=True, allow_unicode=True).strip().removesuffix("\n...")
        details.append(dict(path=change.path, original_present=present,
                            original_value=display(node) if present else "Not set",
                            candidate_value=display(change.value), rationale=change.rationale))
    return CandidateResponse(status=status, original_sha256=digest, constraint_report=report,
                             semantic_changed_paths=paths, change_details=details, candidate_yaml=candidate_yaml, warnings=warnings)


@router.post("/candidate", response_model=CandidateResponse)
async def candidate_upload(request: Request):
    try:
        body = await read_upload(request, limit=2 * MAX_FILE_BYTES)
        try:
            candidate_request = CandidateRequest.model_validate_json(body)
        except ValidationError:
            raise PatchError("invalid_candidate_request", "The candidate request failed validation. Send the original YAML, its SHA-256, a supported proposal, structured requirements, and boolean approval flags.") from None
        return await run_in_threadpool(prepare_candidate, candidate_request)
    except (ManifestError, ScannerError, AIError, PatchError) as error:
        return error_response(error)


@router.post("/verify", response_model=VerificationResponse)
async def verification_upload(request: Request):
    try:
        body = await read_upload(request, limit=4 * MAX_FILE_BYTES)
        try:
            verification_request = VerificationRequest.model_validate_json(body)
        except ValidationError:
            raise PatchError("invalid_verification_request", "Send the original YAML and hash, candidate YAML, proposal, and structured requirements in the verification request.") from None
        return await run_in_threadpool(verify_candidate, verification_request)
    except (ManifestError, ScannerError, PatchError) as error:
        return error_response(error)

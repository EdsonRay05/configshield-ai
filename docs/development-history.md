# Historical development notes

These notes describe earlier phases and may contain superseded workflows. Use the current README for setup and behavior.

# ConfigShield AI

An intent-aware, RAG-grounded assistant for reviewing Kubernetes security configurations.

## Current scope: Phase 8

Implemented: a responsive review dashboard, bounded YAML parsing, selected Checkov checks, local guidance retrieval, mock/Gemini explanations, structured application requirements, approval-gated candidate construction, independent verification, original/candidate comparison, and explicit local YAML downloads. Runtime behavior is not tested. Nothing deploys Kubernetes configurations.

## Prerequisites

- Python 3.12 (tested with 3.12.3)
- Node.js (tested with 24.14.0) and npm (tested with 11.9.0)
- Git (tested with 2.52.0.windows.1)

Use `npm.cmd` in PowerShell if execution policy blocks `npm.ps1`. Virtual environment activation is optional; the commands below call its interpreter directly. Parsing, scanning, retrieval, and mock explanations need no API key. Optional live Gemini requires a backend-only key from a project without billing.

## Install

From the project root in PowerShell:

```powershell
cd C:\Users\eesj\Downloads\ai_hack\configshield-ai
# If python resolves to a broken Windows alias, use the working installation:
& "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe" -m venv backend\.venv
& .\backend\.venv\Scripts\python.exe -m pip install -r .\backend\requirements.txt
& .\backend\.venv\Scripts\python.exe -m venv .\backend\.scanner-venv
& .\backend\.scanner-venv\Scripts\python.exe -m pip install -r .\backend\scanner-requirements.txt
powershell -NoProfile -ExecutionPolicy Bypass -File .\backend\tools\install-kubeconform.ps1
cd frontend
npm.cmd ci
```

On another computer, replace the Python executable path with a working Python 3.12 interpreter. The top-level backend dependencies are pinned; frontend dependency resolutions are recorded in package-lock.json.

## Run

Terminal 1 — backend:

```powershell
cd C:\Users\eesj\Downloads\ai_hack\configshield-ai\backend
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Terminal 2 — frontend:

```powershell
cd C:\Users\eesj\Downloads\ai_hack\configshield-ai\frontend
npm.cmd run dev
```

Open http://127.0.0.1:5173 and click **Check connection**. Expected: `configshield-ai is connected and responding.` Use Ctrl+C in each terminal to stop.

## How the components connect

- `backend/app/main.py`: creates FastAPI; `health()` accepts no input and returns the Pydantic-validated service status.
- `frontend/vite.config.js`: forwards `/api/health` to `http://127.0.0.1:8000/health` and preserves `/api/parse` and `/api/scan` when forwarding to FastAPI. This development proxy keeps browser API calls on the same origin; CORS middleware is unnecessary for this setup.
- `frontend/src/api.js`: `checkHealth()` fetches the endpoint, enforces a five-second timeout, and validates the response shape. It returns health data or throws an error.
- `frontend/src/App.jsx`: `handleCheck()` calls that function after a button click and updates idle/loading/success/error UI state. It makes no AI requests.
- `frontend/src/main.jsx` mounts React; `index.css` loads Tailwind.

The health endpoint reports basic availability only, not scanner or AI readiness. The Vite proxy exists only in development. Production hosting and API routing are outside Phase 1; `vite preview` does not provide this proxy.

## YAML upload and parsing

Restart both development servers after updating Phase 1. Select `samples/insecure-deployment.yaml` in the interface and click **Parse deployment**. Expected: deployment `insecure-demo`, container `web`, image `nginx:1.27`, and a warning that security/schema checks have not run. This sample is deliberately insecure; do not deploy it.

The browser sends raw file bytes to `POST /api/parse?filename=example.yaml` (not multipart). `analysis.py` reads the request with a 256 KiB limit, calls `parse_deployment()` in `yaml_parser.py`, and returns the `schemas.py` response model. No uploaded file is written to disk, executed, or sent to AI. Uploaded content exists only for the request; selecting a new file clears the prior result.

Supported input: one UTF-8 `.yaml` or `.yml` document containing an `apps/v1` Deployment with a name, selector, pod template, and exactly one named container with an image. Linux must be declared or is assumed with a visible warning when omitted. OS declarations, node selectors, and Windows security options are checked for obvious unsupported Windows input. Container image/runtime compatibility cannot be established statically.

The parser uses PyYAML safe constructors with duplicate-key, alias, nesting-depth (40), and node-count (20,000) restrictions. Multiple documents, extra application containers, init/ephemeral container fields, and unsupported resources are rejected. These are supported-structure checks; strict schema validation runs separately through the Phase 7 verification action.

Successful responses contain `status`, `deployment`, and `warnings`. Parse errors contain `error.code` and `error.message`; invalid input returns 422, invalid extensions 400, and oversized content 413. Missing/invalid filename query parameters use FastAPI's standard 422 validation response.

### Phase 2 commands

Install the new backend dependencies and run tests:

```powershell
cd C:\Users\eesj\Downloads\ai_hack\configshield-ai\backend
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m pip check
```

With the backend running, test the endpoint directly:

```powershell
cd C:\Users\eesj\Downloads\ai_hack\configshield-ai
Invoke-RestMethod -Method Post -Uri 'http://127.0.0.1:8000/api/parse?filename=insecure-deployment.yaml' -ContentType 'application/yaml' -InFile .\samples\insecure-deployment.yaml
```

Manual browser checks: upload the sample, upload a malformed YAML file, upload a Pod resource, and try a file above 256 KiB. Only the sample should produce deployment details. No API key is needed.

Observed Phase 2 results on November 17, 2026: 34 backend tests passed, `pip check` reported no broken requirements, and the frontend production build passed. Tests covered parser safety and supported scope, direct API responses, oversized streamed requests, and avoiding secret reflection in parser errors. One Starlette deprecation warning recommends migrating its HTTPX test client integration in the future. Browser upload interactions have not been exercised through browser automation.

## Checkov security scanning (Phase 3)

Checkov 3.4.5 is pinned in `backend/scanner-requirements.txt` and installed separately in `backend/.scanner-venv/`. Its dependency tree does not modify the backend environment. No scanner API key, account, paid service, or Kubernetes cluster is needed.

### Install or update Phase 3

```powershell
cd C:\Users\eesj\Downloads\ai_hack\configshield-ai\backend
.\.venv\Scripts\python.exe -m venv .scanner-venv
.\.scanner-venv\Scripts\python.exe -m pip install -r scanner-requirements.txt
.\.scanner-venv\Scripts\python.exe .\.scanner-venv\Scripts\checkov --version
.\.venv\Scripts\python.exe -m pytest -q
```

The Windows Checkov package installs a Python launcher named `Scripts/checkov`. ConfigShield runs it using the scanner environment's Python, with a fixed argument list and `shell=False`; it never runs the `.cmd` launcher or commands from uploaded content.

Restart the backend and frontend using the Run commands above. Upload and parse `samples/insecure-deployment.yaml`, then click **Scan with Checkov**. Expected for the pinned scanner: seven failed selected checks. Select `samples/secure-deployment.yaml`, parse, and scan: expected seven passed selected checks. That reference file has not been run in a cluster and is not proof of runtime compatibility or complete security.

### Selected rules

| Checkov ID | Scope of the selected check |
| --- | --- |
| CKV_K8S_16 | Privileged container setting |
| CKV_K8S_20 | Privilege escalation setting |
| CKV_K8S_23 | Non-root settings, including runAsNonRoot/runAsUser |
| CKV_K8S_28 | Dropping NET_RAW or all capabilities |
| CKV_K8S_31 | RuntimeDefault seccomp profile (the rule also supports legacy annotations) |
| CKV_K8S_37 | Dropping all capabilities |
| CKV_K8S_38 | Disabling automatic service-account token mounting |

IDs were checked against the [official policy index](https://www.checkov.io/5.Policy%20Index/kubernetes.html) and installed Checkov source. These are the scanner's policy results, not a comprehensive security assessment. Independent static application-requirement checks are described in Phase 6 below.

### Scan processing and response

`scan_deployment(content, filename)` accepts the uploaded bytes, validates supported scope again, writes a fixed `deployment.yaml` in a controlled temporary directory, invokes Checkov, and returns `ScanResponse`. `normalize_report()` accepts scanner JSON and its exit code, checks all seven rule outcomes and resource identities, and produces findings with IDs, descriptions, categories, resource IDs, and line ranges. It excludes code blocks, raw logs, and absolute temporary paths from API responses.

`POST /api/scan?filename=example.yaml` uses the same bounded raw-file transport as parsing. The route runs the blocking scanner in a worker thread so the server can handle other requests. One scan per backend process is allowed at a time. There are no automatic retries.

The fixed command selects only the Kubernetes framework and seven check IDs, requests JSON, disables Prisma Cloud downloads with `--skip-download`, and uses an empty, controlled configuration file. The scanner receives a minimal environment without inherited API credentials, Checkov overrides, or PYTHONPATH. All scan copies/configuration are removed on success or failure. The scanner uses its installed local policies; no cloud scanning integration is configured.

Checkov exit code 1 can mean security findings; it is accepted when accompanied by a complete matching report. Exit code 0 means no failed selected checks only when report coverage is complete. This implementation intentionally does not use `--quiet`, because in the pinned release it omits passed/skipped JSON records. [CLI reference](https://www.checkov.io/2.Basics/CLI%20Command%20Reference.html)

Successful HTTP responses contain `status` (`completed` or `incomplete`), `scanner`, `scanner_version`, `deployment`, `supported_checks`, `passed_checks`, `skipped_checks`, `findings`, and `warnings`. Manifest suppressions are reported as skipped and make scan coverage incomplete. No skipped check is counted as passed.

Scanner errors use `error.code` and `error.message`: missing installation or busy scanner returns 503, execution or invalid/incomplete report errors return 502, and the 60-second process timeout returns 504. The frontend request timeout is 75 seconds. Input errors retain the Phase 2 error codes. No raw scanner diagnostics or uploaded YAML lines are returned in error messages.

Test directly with the backend running:

```powershell
cd C:\Users\eesj\Downloads\ai_hack\configshield-ai
$scanResult = Invoke-RestMethod -Method Post -Uri 'http://127.0.0.1:8000/api/scan?filename=insecure-deployment.yaml' -ContentType 'application/yaml' -InFile .\samples\insecure-deployment.yaml
$scanResult | ConvertTo-Json -Depth 8
```

In React, `scanDeployment(file)` sends the file after a button click; `handleScan()` manages loading/error/result state, and `FindingsList` displays completed/incomplete coverage separately from failed policies. Selecting or parsing another file clears previous scan results. AI suggestions and independent verification have not been implemented.

## Local guidance retrieval (Phase 4)

No new dependencies or API keys are needed. This phase implements the retrieval part of RAG: selecting relevant documentation before a future model request. It does not yet generate AI explanations or changes.

`backend/app/knowledge/security_guidance.json` contains ten short curated paraphrases covering all seven selected Checkov IDs. Sources are the official Kubernetes Pod Security Standards, security-context and service-account documentation, and OWASP Kubernetes Security Cheat Sheet. Each record has a stable document ID, title, category, Checkov IDs, tags, source URL, review date, applicability condition, guidance, and limitation. Review dates record when the source was consulted, not a guarantee that it will stay current. These are paraphrases, not direct source quotations.

`load_knowledge()` reads that fixed local file and validates its schema, unique record IDs, reviewed source pages, and consistency with the rule mapping. `retrieve_guidance(check_id)` accepts an exact Checkov ID and returns records in a fixed order. It does not search user text, fetch URLs, execute document content, or invoke an LLM. Unknown IDs return `missing` with no documents. A missing/invalid knowledge base returns `unavailable` with no fabricated replacement references. Changing the local file requires reviewing the guidance and re-running tests; URL validation alone does not establish factual accuracy.

The scan route attaches a `guidance` result to each failed finding. Knowledge failures do not erase findings or change scanner completion status. Passed and skipped checks do not receive finding guidance. The interface shows source links, applicable conditions, review notes, review dates, and document IDs under **Retrieved documentation**. Guidance is separate from scanner evidence and is not an approved fix or proof of compatibility. Later AI integration must treat this text and uploaded YAML as untrusted data.

### Check retrieval without Checkov

Restart FastAPI using the Run command above, then run:

```powershell
Invoke-RestMethod 'http://127.0.0.1:8000/api/guidance/CKV_K8S_31' | ConvertTo-Json -Depth 8
Invoke-RestMethod 'http://127.0.0.1:8000/api/guidance/UNKNOWN' | ConvertTo-Json -Depth 8
```

The first response should have `status: available` and two documents, including the seccomp policy record. The second should have `status: missing` and an empty document list. Both use HTTP 200 because they describe retrieval availability; no scan is claimed. The endpoint works without Checkov or AI credentials.

Run tests from `backend/`:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

For the browser check, restart the frontend, upload the insecure sample, parse it, and click **Scan with Checkov**. Each failed finding should include reviewed documentation with clickable sources. Browser rendering and clicks still need manual verification.

Guidance preserves differences between policies: for example, Restricted Pod Security Standards allow RuntimeDefault or Localhost seccomp, while the selected Checkov rule is narrower. The non-root record also distinguishes the standard's runAsNonRoot requirement from the scanner's acceptance of a positive runAsUser. Retrieval does not evaluate declared application requirements or apply any configuration changes.

Observed Phase 4 results on November 17, 2026: the full suite passed 86 tests with the existing Starlette test-client deprecation warning. After adding assertions for guidance on actual Checkov API findings, all 25 targeted retrieval/integration tests passed. The frontend production build passed. Tests cover all seven rule mappings, unknown IDs, source and record validation, corrupt or missing knowledge files, separate scanner/retrieval status, and the offline guidance endpoint. No browser automation was run.

Observed Phase 3 checks on November 17, 2026:

- 62 backend tests passed, with no skips. This includes real Checkov scans of both samples and a real API suppression test: the insecure sample failed seven selected checks, the reference passed seven, and suppressing one insecure-sample check produced six findings plus one skipped check with incomplete status.
- Mocked process tests covered missing tools, timeouts, process errors, malformed/incomplete reports, fixed arguments, environment filtering, temporary-file cleanup, and releasing the scan slot after failure.
- Four frontend API checks passed for upload transport, completed findings, incomplete coverage, scanner errors, and malformed output (transport and completed findings were checked together).
- Production frontend build passed, and both Python environments passed `pip check`.
- The existing Starlette HTTPX test-client deprecation warning remains; it did not fail tests. Browser scan-button interaction and visual rendering have not been tested through browser automation.

## Verify

### AI explanations and candidate suggestions (Phase 5)

The default is mock mode, with zero external AI requests. Live Gemini uses the pinned `google-genai==3.4.0` SDK. The only allowed live model is `gemini-3.1-flash-lite`, whose standard text input/output was verified as free-tier eligible in Google's [pricing documentation](https://ai.google.dev/gemini-api/docs/pricing#gemini-3.1-flash-lite) on November 17, 2026. The model documentation lists [structured-output support](https://aistudio.google.com/docs/models/gemini-3.1-flash-lite). Eligibility and quotas can change or vary by project. The app cannot inspect the key's billing tier and does not enable billing. Do not use a project with billing enabled. There is no paid-model or alternate-provider fallback.

#### Start with mock mode

No environment settings are needed. Restart FastAPI and Vite using the Run commands above. Upload and parse the insecure sample, scan it, select a failed finding, and click **Generate mock example**. Expected: a clearly labeled mock explanation, retrieved source references, candidate fields/values, limitations, and external request count zero. Candidates are not applied, downloaded, or deployed.

Test the backend from another PowerShell terminal while FastAPI is running:

```powershell
Invoke-RestMethod 'http://127.0.0.1:8000/api/ai/status' | ConvertTo-Json -Depth 6
cd C:\Users\eesj\Downloads\ai_hack\configshield-ai
Invoke-RestMethod -Method Post -Uri 'http://127.0.0.1:8000/api/explain?filename=insecure-deployment.yaml&check_id=CKV_K8S_16&provider=mock' -ContentType 'application/yaml' -InFile .\samples\insecure-deployment.yaml | ConvertTo-Json -Depth 10
```

#### Optional live Gemini setup (backend terminal only)

Create an API key in [Google AI Studio](https://aistudio.google.com/api-keys) using a project without billing, and check that the allowed model has free quota for that project. Do not enable billing or buy credits. Never paste the key into chat, frontend code, a command literal, or Git.

Stop the backend with Ctrl+C. In that same PowerShell terminal:

```powershell
cd C:\Users\eesj\Downloads\ai_hack\configshield-ai\backend
$env:AI_PROVIDER = 'gemini'
$env:GEMINI_MODEL = 'gemini-3.1-flash-lite'
# Set true only after confirming that the selected project has no billing.
$env:GEMINI_FREE_TIER_CONFIRMED = 'true'
$configShieldKey = Read-Host 'Gemini API key (hidden)' -AsSecureString
$env:GEMINI_API_KEY = [System.Net.NetworkCredential]::new('', $configShieldKey).Password
Remove-Variable configShieldKey
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

The backend automatically reads `backend/.env` using its absolute project path. Process environment variables take precedence. Copy the names from `.env.example`; set `AI_PROVIDER=gemini`, the allowed model, your key, and `GEMINI_FREE_TIER_CONFIRMED=true` only after confirming the project has no billing. Values support plain or matching quoted text; this small settings reader does not execute shell commands or expand variables. With no configured file or environment, mock mode remains the default. The key is not included in API responses, prompts, raw error messages, or frontend bundles. Scanning subprocesses also receive no inherited AI keys.

The header checks AI configuration automatically on page load and every 30 seconds. Step 4 also checks when it opens, enabling the Gemini action when settings are ready. The green **Gemini ready — backend connected** indicator describes local configuration readiness, not authenticated Google connectivity or available quota. Checks send no model requests. Generation still requires the explicit **Ask Gemini** button. Restart the backend after updating startup settings; existing terminal environment overrides can be removed or updated if they conflict with `.env`.

In the interface, click **Check AI configuration** (this makes no model call), then **Ask Gemini — one request**. Live responses are labeled AI-generated and unverified. Missing keys, unavailable models, quota/rate-limit errors, and malformed output produce explicit errors. The app does not retry automatically or silently switch providers. Mock mode remains a separate explicit action.

To disable live mode afterward, stop the backend and run:

```powershell
Remove-Item Env:GEMINI_API_KEY -ErrorAction SilentlyContinue
$env:AI_PROVIDER = 'mock'
$env:GEMINI_FREE_TIER_CONFIRMED = 'false'
```

#### Processing and contracts

- `config.py` reads settings only from the backend environment and exposes a fixed model allowlist. The free-tier confirmation is an operator assertion, not programmatic proof of account eligibility.
- `parse_manifest()` returns safely validated YAML plus its summary. `security_projection()` copies only selected security booleans, bounded user IDs, known capability names, and known seccomp types. It omits metadata, image names, commands, environment values, annotations, mounts, filenames, and raw YAML. Localhost profile filenames are omitted. Unsupported values in selected security fields block AI before a model request. This is an allowlisted projection, not a general-purpose secret detector.
- `explain_deployment()` re-scans the submitted bytes, confirms the selected failed finding, retrieves reviewed local guidance, and supplies typed requirements to the provider. It never trusts a finding submitted by the browser. The default requirements are `unknown`; Phase 6 adds requirement controls and independent static checks on the simulated candidate.
- `AIProvider` defines the provider interface. `MockProvider` returns a deterministic example; `GeminiProvider` makes one structured generation request using a fixed Developer API endpoint, no tools, a 30-second HTTP timeout, and `HttpRetryOptions(attempts=1)` to disable the SDK's default retries. Browser requests allow 105 seconds to cover re-scanning and generation.
- `validate_proposal()` validates JSON against strict Pydantic models, checks the selected finding ID, permits only retrieved document IDs, and restricts candidate paths and values to those supported for that finding. It rejects whole-manifest replacement, unrelated changes, invented source IDs, duplicate paths, and unexpected fields. This does not prove that an explanation is correct or that a candidate is compatible with the workload.
- `AIExplanationPanel` requests explanations only from button actions and displays mock/live provenance, usage, sources, candidates, and warnings. It disables upload/scan changes during an explanation.

`POST /api/explain?filename=example.yaml&check_id=CKV_K8S_16&provider=mock` accepts the same bounded raw-file body as parsing and scanning. Provider must be `mock` or `gemini`. Query parameters form `ApplicationRequirements`: `api_access` and `privileged_access` accept `unknown|required|not_required`; `non_root_compatibility` accepts `unknown|compatible|incompatible`. Phase 6 sends these declarations from the UI and checks candidates independently of provider prose. A mock remains a deterministic demonstration, not an actual model response.

Success returns `status` (`mock` or `generated`), `provider`, `model`, `proposal`, `requirements`, `usage`, and `warnings`. A proposal contains an explanation, candidate changes (possibly empty), referenced document IDs, and limitations. AI errors retain the `error.code`/`error.message` contract. Rejected output is not exposed as an accepted proposal. Existing scan and input errors remain separate.

#### Limits, usage, and privacy

One generation may run per backend process at a time. A conservative maximum of five live attempts per process and a 15-second minimum interval protect the demo quota. These local limits are not Google's quotas and reset on restart; use one backend worker. Do not restart to bypass provider limits. Provider 429 errors do not trigger retries or billing changes.

Usage reports external requests for a successful action, a rough character-based input token estimate, provider-reported token counts when available, and cumulative process attempt/success/failure/token totals. Attempts are conservative: SDK initialization failures can consume a local attempt without reaching Google. Unknown usage is left null; failed calls without usage are not assigned invented token counts. These counters are neither persistent nor authoritative billing totals. Refresh AI configuration to inspect counters after an error.

Google's free-tier terms permit submitted content to be used for product improvement; only minimized security context and reviewed guidance are sent. No tools, file upload API, web grounding, automatic function calls, or external document retrieval are enabled. Prompt instructions explicitly treat evidence and guidance as untrusted data. Strict output validation and the absence of any patch application limit what a model response can do.

#### Phase 5 verification

```powershell
cd C:\Users\eesj\Downloads\ai_hack\configshield-ai\backend
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m pip check
```

All automated Gemini tests use mocks, including the SDK's actual serialization through an in-memory HTTP transport. No live Gemini call is required. Observed results: 133 backend tests passed and `pip check` reported no broken requirements. After adding fixed finding descriptions and confirming that unrelated GOOGLE_API_KEY settings cannot override the explicitly configured backend key, all 47 AI tests passed again. Four frontend API checks and the final production build passed. Tests cover SDK one-attempt behavior, quota/access/model errors, timeouts, output validation, prompt privacy, safe configuration, process limits, usage, and a mock explanation through the real Checkov API workflow. The prior Starlette warning is no longer emitted after the SDK installed HTTPX2. Live account/model access has not been exercised. Browser explanation interactions need manual verification.

### Intent-aware candidate construction (Phase 6)

After parsing, step 2 automatically identifies requirement clues without AI requests. Each control shows the observed YAML paths and limitations. Effective pod/container non-root settings can produce a **Suggested: Yes, compatible (unconfirmed)** draft, but they do not prove successful execution. The owner must accept it or select another value; unconfirmed drafts remain Unknown in AI, candidate, and verification requests. Existing privileged access, mounted tokens, hostPath volumes, service account references, missing settings, and image names alone do not establish an application need. Users can change declarations at any time, which clears previous proposals and candidates.

Optional Deployment metadata annotations can supply explicit requirement suggestions: `configshield.ai/api-access` and `configshield.ai/privileged-access` accept `required` or `not_required`; `configshield.ai/non-root-compatibility` accepts `compatible` or `incompatible`. These remain unconfirmed local suggestions, not instructions or verified facts. Raw annotations, service account names, and environment values are not included in the generated evidence. Unknown remains appropriate when behavior is not documented or tested. `app/services/requirement_hints.py` implements these deterministic rules; `RequirementHint` extends the parse response, and `RequirementsPanel` keeps draft suggestions separate from declared values.

No dependencies, API keys, cluster, or external AI requests are needed for this phase's mock demonstration.

The three structured requirement controls collect Kubernetes API access, privileged host/device access, and non-root compatibility. Unknown remains a valid answer. Selecting a new file resets declarations to Unknown; editing requirements clears the previous explanation and candidate. The same declarations reach the provider prompt and the independent backend checker.

`patcher.py` owns the canonical selected-check path/value allowlist. `validate_changes()` accepts only supported assignments for the selected rule, rejects duplicate/unrelated fields and mismatched values, and never accepts a complete replacement YAML. `apply_allowlisted_changes()` copies the parsed manifest before assigning those fields, creating missing mapping parents only where needed. `semantic_changed_paths()` independently checks that no unrelated semantic field changed; booleans and integers are compared distinctly. Existing images, labels, commands, environment values, volumes, and unrelated settings remain unchanged. Output formatting/comments may change during serialization; the uploaded original is retained separately.

`check_constraints(original, candidate, requirements)` independently returns per-requirement `preserved`, `conflict`, or `unverifiable` results. Here, preserved means no contradiction detected in supported fields, not proven runtime compatibility. Disabling automatic credentials when API access is required, disabling privileged mode when privileged access is required, and forcing non-root execution for an incompatible application produce potential conflicts. Existing disabled automount with unknown alternative credentials remains unverifiable. Effective container user settings override pod defaults. Contradictory non-root/UID-zero settings are blocked. Capability drops, seccomp changes, and privilege restrictions that interact with privileged mode receive manual-review notes. Kubernetes documents [privileged-mode interactions](https://kubernetes.io/docs/concepts/security/linux-kernel-security-constraints/) separately from individual field syntax.

The checker always includes unresolved runtime compatibility. Therefore construction currently requires both approval and acknowledgement of manual review. An explicit approval cannot override a detected conflict. The mock provider omits its usual candidate for a declared direct conflict, while the backend still flags a provider that ignores the requirements. Unknown answers are never inferred from the YAML or marked verified.

#### Browser demonstration

Restart both servers using the Run commands above:

1. Upload and parse `samples/insecure-deployment.yaml`.
2. Declare API access **Not required**, privileged access **Not required**, and non-root compatibility **Yes, compatible**.
3. Scan, select `CKV_K8S_16`, and generate a mock explanation.
4. Review proposed fields and **Independent requirement checks**. Runtime compatibility remains unverified.
5. Tick the approval/uncertainty acknowledgement and click **Approve and build candidate YAML**.
6. Expected: a separate candidate with `privileged: false`, the unchanged original beside it, the one changed semantic field, and an independent verification action. Construction itself does not deploy or download; Phase 8 adds a final review/download panel.

For the conflict demonstration, upload `samples/needs-host-access.yaml`, explicitly declare privileged access **Required**, scan, select `CKV_K8S_16`, and generate the mock. Expected: an explanation of the declared conflict with no candidate proposed. Comments in this sample do not declare requirements for you; its image is a deliberately non-runnable placeholder. These are controlled demonstrations, not runtime tests.

#### Approval API and input binding

Explanation responses now include `original_sha256` and `constraint_report`. SHA-256 binds review to the original bytes; it is not a signed attestation of who generated the proposal.

`POST /api/candidate` accepts a JSON envelope up to 512 KiB with `filename`, `original_yaml`, `original_sha256`, `proposal`, `requirements`, `approved` (default false), and `acknowledge_manual_review` (default false). Original YAML remains limited to 256 KiB. The browser preserves a UTF-8 BOM and CRLF during submission so the byte hash matches.

The backend rechecks the digest, parses the original, validates allowed paths/values and source IDs, confirms the failed finding with a fresh original scan, and recomputes constraint results. Browser-supplied constraint reports and whole-file replacements are rejected. It does not trust prior UI checks. Candidate construction does not call any AI provider.

Responses include `status`, `original_sha256`, `constraint_report`, `semantic_changed_paths`, nullable `candidate_yaml`, and warnings:

- `review_required`: approval or uncertainty acknowledgement is absent; no candidate YAML is returned.
- `blocked`: an independent check found a potential conflict; no candidate YAML is returned.
- `no_changes`: there are no semantic changes to construct; no fix is claimed.
- `candidate_created`: approval was given and no supported conflict was detected. The separate YAML is safely serialized, reparsed for supported shape, and checked for unrelated changes. This is not Kubeconform validation or a candidate Checkov re-scan.

Stale bytes or a missing selected finding return 409. Invalid requests and unsupported changes return 422; oversized requests return 413. Existing scanner failures remain explicit. No backend manifest file is overwritten or persisted, and no approval bypasses the conflict gate. The Phase 8 dashboard provides the final review/download step.

Observed Phase 6 results on November 17, 2026: 184 backend tests passed with no warnings or skips. This includes real Checkov integration for the mock-explanation/approval/candidate workflow, independent rejection of provider proposals that ignore declared requirements, approval and acknowledgement gates, stale hashes, unsupported changes, original preservation, and BOM/CRLF handling. Four frontend API checks and the production build passed. The Python dependency check passed. A parser regression test also confirms NUL bytes return a structured invalid-YAML error. No live Gemini request or browser automation was used; browser controls still need a manual check.

```powershell
cd C:\Users\eesj\Downloads\ai_hack\configshield-ai\backend
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m pip check
```

### Independent verification (Phase 7)

Verification is a separate, explicit action after candidate construction. It does not call an AI provider, apply a candidate to a cluster, or download remote schemas at runtime.

#### Validator setup

The pinned setup uses Kubeconform **v0.8.0**, the Windows AMD64 executable, and the strict standalone **Kubernetes 1.35.0 apps/v1 Deployment schema**. This is a fixed validation target, not a detected cluster version. Schema source commit, download URLs, and SHA-256 hashes are recorded in `backend/tools/kubeconform-lock.json`.

Install or repair from the backend directory:

```powershell
cd C:\Users\eesj\Downloads\ai_hack\configshield-ai\backend
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\install-kubeconform.ps1
.\.tools\kubeconform.exe -v
```

The installer downloads the pinned Windows archive and schema into Git-ignored `backend/.tools/`. It verifies the archive hash from the official release, extracts only fixed executable/license entries, verifies the binary and schema hashes, and checks that the executable starts. It changes no machine-wide execution policy or PATH. Network access is needed for installation; existing matching downloads are reused. Runtime validation uses the local schema exclusively.

`kubeconform_validator.py` rechecks artifact hashes before each use, runs a fixed argument list with `-strict`, JSON output, verbose resource results, a summary, the pinned version, and the one local schema path. It enforces a 20-second timeout and removes its controlled temporary manifest on every exit. It passes no inherited AI key or proxy settings. No `default` remote schema location, skip policy, or ignore-missing-schema option is enabled. [Kubeconform documents local schemas and strict mode](https://github.com/yannh/kubeconform#overriding-schemas-location).

Missing tools/schemas, integrity mismatches, startup errors, timeouts, skipped resources, and inconsistent JSON reports return schema status `unavailable`. Actual schema violations return `failed`. A pass requires exactly one matching Deployment, valid counts, and a matching successful exit code. Raw validator logs and manifest values are not returned. Schema checks do not replace API-server admission, cross-field semantic validation, or workload runtime tests.

#### Verification workflow

`verify_candidate()` accepts the original bytes/hash, candidate YAML, supported proposal, and structured requirements. It:

1. Confirms the original SHA-256, then safely parses both manifests and checks supported shape.
2. Reconstructs the allowlisted proposal on a copy and compares the actual candidate to it, reporting unexpected semantic paths or no-op changes.
3. Validates candidate schema independently with local Kubeconform.
4. Runs fresh Checkov scans on original and candidate.
5. Compares findings by `(check_id, resource)` when both scans have complete, unskipped coverage from the same scanner version and selected check set. Line-number movement is ignored.
6. Reports resolved, newly introduced, and remaining findings; confirms whether the targeted original failure now passes.
7. Rechecks declared requirements independently and retains explicit runtime/manual-review limitations.

The scan step passing means the scanner executed its selected checks; failed security policies remain findings, not execution errors. A missing or incomplete scan never produces claimed resolved findings. A missing schema does not prevent collecting scanner/requirement evidence, but prevents a complete verification result.

`POST /api/verify` accepts a JSON envelope up to 1 MiB with `filename`, `original_yaml`, `original_sha256`, `candidate_yaml`, `proposal`, and `requirements`. Each manifest remains limited to 256 KiB. It rejects supplied `checks` or other extra fields. Verification is read-only and does not require a new generation or another approval flag. Stale original bytes return 409; invalid request envelopes return 422; oversized envelopes return 413.

Successful HTTP responses contain the overall `status`, original/candidate hashes, individual `checks`, `schema_validation`, original/candidate scan results, `resolved_findings`, `new_findings`, `remaining_findings`, nullable `targeted_finding_resolved`, recomputed `constraint_report`, semantic/unexpected paths, warnings, and `manual_review_required`.

| Status | Meaning |
| --- | --- |
| `failed_validation` | Unsupported/malformed input, an unauthorized/no-op candidate, or failed schema validation. |
| `requirement_conflict` | Independent requirement checks found a potential conflict. |
| `new_security_findings` | Complete comparable scans detected newly introduced selected findings. |
| `incomplete` | A required tool, schema, scan, or comparable result is unavailable. |
| `manual_review` | The target is unresolved, other selected findings remain, or supported requirements/permission effects remain uncertain. |
| `verified_supported_checks` | Schema and authorized changes pass, the targeted failure is resolved, all selected candidate security checks pass, and no supported requirement conflict/uncertainty was detected. Runtime behavior remains unverified. |

Known failures take precedence over unavailable checks in the overall status; individual checks still show all unavailable/incomplete results. Even `verified_supported_checks` retains `manual_review_required: true` because this application does not run workloads. It never means complete security.

#### Browser check

Restart both servers using the Run commands. Follow the Phase 6 mock/approval workflow, then click **Verify candidate** below the candidate YAML. The panel displays each independent check, schema target, target repair status, finding comparison, and requirement results. No AI request is made.

For the deliberately insecure sample, fixing privileged mode alone should resolve `CKV_K8S_16` while six selected findings remain; expect **Requires manual review**, not a broad verification pass. For a controlled all-selected-checks pass, the real integration tests start from the reference sample with only privileged mode changed to true and then repair that one field. Neither scenario is a runtime compatibility test.

Run repeatable verification tests:

```powershell
cd C:\Users\eesj\Downloads\ai_hack\configshield-ai\backend
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m pip check
```

Observed Phase 7 results on November 17, 2026: 227 backend tests passed with no warnings or skips, including 43 new validator/verifier cases. Real Kubeconform accepted supported input and rejected an unknown container property; real offline verification passed a controlled one-finding repair and rejected a schema-invalid candidate. Mocked cases covered new/remaining findings, skipped/incomparable scans, missing or changed artifacts, timeouts, malformed reports, requirement conflicts, unauthorized/no-op changes, and stale input. Four frontend verification API checks, the production build, and the Python dependency check passed. Browser controls have not been exercised through automation. No live Gemini call or cluster deployment was made.

### Complete review dashboard and downloads (Phase 8)

The responsive dashboard presents Upload → Requirements → Scan → Explain → Propose → Verify → Review → Download. Stage indicators reflect actual session actions; the summary shows no file, scan, explanation, or verification result until that result exists. There is no authentication, analytics, browser persistence, automatic AI request, or deployment integration.

`UploadPanel` keeps the current file, declarations, and session progress. Selecting a new file resets all downstream results and requirements to Unknown. Editing requirements clears prior proposals, candidates, verification, and final approval. Parsing or scanning again clears dependent results. Inputs are disabled during dependent operations. A completed scan with no failed selected findings does not invent a remediation candidate. Skipped/incomplete checks retain visible warnings.

`FindingsList` keeps Checkov findings separate from retrieved guidance, which expands on demand with original source links and review notes. `AIExplanationPanel` labels deterministic mock versus AI-generated suggestions, preserves explicit request buttons, and shows loading, missing-configuration, quota, and error messages without retries. `DiffViewer` displays read-only original/candidate YAML beside the semantic changed fields; it does not infer a misleading line diff from formatting changes. Verification remains independently labeled and reports unavailable checks and remaining findings.

`ReviewDownloadPanel` provides a distinct final acknowledgement after verification. `review.js` contains the shared decision/status labels, exact UTF-8 SHA-256 matching, safe filenames, and browser download helper. The current original and candidate bytes must match the verification hashes. Required validation/scan/comparison checks must all have passed, the targeted finding must be resolved, and no regression, unexpected change, or requirement conflict may remain. These checks supplement the backend; the browser download gate is a user-workflow safeguard, not authentication or an attestation of runtime compatibility.

Candidate downloads are blocked for failed validation, new findings, requirement conflicts, incomplete verification, missing evidence, or stale byte hashes. A `manual_review` candidate can be downloaded as a review draft when required checks are complete and no blocking conflict/regression exists; remaining findings and unresolved requirements stay visible and require acknowledgement. A `verified_supported_checks` candidate also requires final review because runtime behavior is untested. Mock/AI provenance remains visible at download time.

Original downloads use the selected File object, preserving its actual bytes (including BOM and line endings). Candidate downloads use the exact candidate text, with names ending `.candidate-review.yaml`; originals end `.original.yaml`. Filenames remove path segments and unsafe/reserved names. Browser object URLs are released after starting downloads, and temporary links are removed. Starting a fresh verification clears final approval; replacing/discarding the review cancels any in-flight candidate export. A download-start message does not claim that the browser or OS finished saving the file.

#### Run and test the dashboard

Restart FastAPI as documented above, then run the frontend:

```powershell
cd C:\Users\eesj\Downloads\ai_hack\configshield-ai\frontend
npm.cmd ci
npm.cmd run dev
```

Open http://127.0.0.1:5173. Upload the insecure sample, parse, declare requirements, scan, select `CKV_K8S_16`, generate a mock proposal, approve construction, and verify it. Expect one resolved finding and six remaining selected findings with **Requires manual review**. Review those limitations, acknowledge the final review, then download the candidate for investigation. The original is separately downloadable. Changing the requirements or file clears the old candidate/download approval.

Repeat frontend checks:

```powershell
cd C:\Users\eesj\Downloads\ai_hack\configshield-ai\frontend
npm.cmd test
npm.cmd run build
```

Frontend tests use Vitest, React Testing Library, and jsdom with mocked API responses and object URLs. They exercise real React controls and browser download logic without making Gemini calls or pretending that an actual browser saved a file. Compatible test package versions are pinned in package.json/package-lock.json; jsdom 29.1.1 supports the tested Node 24.14.0. No production runtime dependency was added for this phase.

Observed Phase 8 results on November 17, 2026: all 36 frontend tests passed, including the complete mocked workflow, separate approvals, error/quota handling, byte-bound downloads, stale-result invalidation, and export cancellation. The production build passed. npm installation reported zero known vulnerabilities. No AI request, deployment, or publication was made.

Browser layout, responsive appearance, source-link navigation, and the OS save dialog still need a manual check. The backend was unchanged in Phase 8; its 227-test Phase 7 baseline remains documented above.

Run backend tests from `backend/`. `pytest.ini` directs pytest's `tmp_path`
fixtures to the Git-ignored `.pytest-tmp/` folder under the current directory.
This avoids permission errors in the shared Windows
`AppData/Local/Temp/pytest-of-<user>` directory. Pytest clears `.pytest-tmp/`
before each run, so do not place source files or personal data there. Use a
different `--basetemp` directory for concurrent test runs.

With both services running, use another PowerShell terminal:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
Invoke-RestMethod http://127.0.0.1:5173/api/health
```

Both should return `status: ok` and `service: configshield-ai`.

Build the frontend:

```powershell
cd C:\Users\eesj\Downloads\ai_hack\configshield-ai\frontend
npm.cmd run build
```

Manual error check: stop the backend and click **Check connection** again. The interface should show an unavailable-backend message. Restart the backend and retry.

Never commit real `.env` files or API keys. `.gitignore` excludes environments, dependency folders, and generated builds. No repository has been pushed or published.

## Phase 9: evaluation harness

The upload step now includes a **Try a dataset example** picker: 42 controlled synthetic cases and one compatible external KustomizeGoat Deployment from the downloaded ZIP. Click **Load dataset case**, then parse and scan normally. Requirements reset to Unknown; loading sends no AI request. This supplies evaluation/demo inputs, not model training. Source records, observed external scan results, excluded patch files, and reproducibility details are in [the dataset guide](docs/datasets.md).

See [the evaluation guide](docs/evaluation.md) for the A/B/C design, metrics, limitations, and optional live pilot. The committed dataset has 42 synthetic cases: 34 ordinary positive cases, seven explicitly injected faults, and one negative control. Expected annotations and observed tool results are stored separately. Offline fixtures use identical assignments across arms, so they test measurement and filtering rather than model superiority.

Run from PowerShell with zero AI requests:

```powershell
cd C:\Users\eesj\Downloads\ai_hack\configshield-ai\backend
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m evaluation.runner --mode fixtures --output offline-user-results.json
.\.venv\Scripts\python.exe -m evaluation.runner --mode prompts --output user-prompts.json
```

Reports and the 102 inspectable prompts go to ignored `backend/evaluation/results/`. Choose a fresh output name on repeat runs, or explicitly use `--overwrite`. The CLI defaults to fixtures and a zero request budget. It does not silently enable Gemini. A live pilot is a separate explicit action described in the guide, limited to one eligible case and three attempts; no live model results are claimed.

Phase 9 automated verification: 246 backend tests passed, including 19 evaluation tests; `pip check` reported no broken requirements. Frontend code was unchanged from its passing Phase 8 checks. Production provider defaults remain unchanged; optional provider schema/instruction parameters support fair comparison, and optional verifier tool callbacks permit exact-content caching of real scanner/schema results.

The completed offline run recorded 126 rows, 80 real Checkov calls, 81 real schema checks, and zero AI requests. All original findings matched their annotations. C blocked three ordinary requirement conflicts and six injected faults; one injected fixture abstained. A seccomp container-override case still passed the selected scanner and entered manual review despite failing the curated quality oracle. See the guide for denominators and unknown results. This is an offline system evaluation; the research question about LLM quality remains open.

## Observed Phase 1 checks

On November 17, 2026:

- Frontend production build passed (Vite 7.3.8, React 19.3.1, Tailwind 4.3.5).
- Backend started successfully; direct `/health` returned the expected contract.
- Frontend HTML returned HTTP 200; `/api/health` through Vite returned the same contract.
- The frontend `checkHealth()` function passed a live-proxy check and rejected mocked invalid-response and HTTP-failure responses.
- `pip check` reported no broken requirements; npm installation reported zero known vulnerabilities.
- Git ignore checks confirmed exclusions for `.env`, `.venv`, `node_modules`, and `dist`.
- Browser rendering, button interaction, and the manual stopped-backend scenario have not been tested in a browser.

The initial sandboxed build failed because esbuild could not read parent directories; it passed when run with approved filesystem access. A first inline API check failed due to PowerShell argument quoting; the corrected stdin-based check passed without application changes. Development servers used for verification were stopped afterward.

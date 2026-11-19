# ConfigShield AI

An intent-aware assistant for reviewing Kubernetes security fixes with grounded guidance and independent verification. Local hackathon MVP; nothing deploys to a cluster.

## Current workflow

Upload a YAML file or select one of the 43 dataset entries. The app automatically parses supported structure, identifies requirement clues, runs Checkov, and retrieves reviewed local guidance. Review/edit application requirements, explicitly request a mock or Gemini suggestion, approve a candidate, inspect the change bullets and YAML, independently verify it, and acknowledge a permitted local download.

Only parsing, scanning, requirement clues, retrieval, and configuration status checks run automatically. Gemini generation, candidate construction, verification, and export need explicit actions. Draft requirements stay Unknown until accepted. Unknown runtime compatibility is never a pass.

## Supported input and policies

One UTF-8 `.yaml`/`.yml` document, up to 256 KiB: one `apps/v1` Deployment with one Linux application container. No extra/init/ephemeral containers, YAML aliases, duplicate keys, or excessive nesting. Undeclared Linux OS is an assumption shown to the user. Image compatibility is untested.

| Checkov ID | Selected policy |
| --- | --- |
| CKV_K8S_16 | Privileged containers |
| CKV_K8S_20 | Privilege escalation |
| CKV_K8S_23 | Non-root execution |
| CKV_K8S_28 | NET_RAW capability |
| CKV_K8S_31 | Seccomp profile |
| CKV_K8S_37 | Dropping capabilities |
| CKV_K8S_38 | Service-account token automount |

Verification uses a pinned strict Kubernetes 1.35.0 Deployment schema, fresh comparable selected-policy scans, allowed semantic differences, declared requirements, and an independent effective-seccomp check for seccomp repairs. It rejects pod defaults masked by insecure container overrides or bypassed by privileged mode. This does not test every Kubernetes policy, full admission compliance, or runtime behavior.

## Windows prerequisites

Tested with Python 3.12.3, Node.js 24.14.0, npm 11.9.0, and Git 2.52.0.windows.1. Use `npm.cmd` if PowerShell blocks npm.ps1. The backend and Checkov use separate virtual environments. Top-level Python requirements are pinned; npm has package-lock.json. Playwright uses installed Microsoft Edge for the optional browser check.

## Install

Clone the repository first. Replace `YOUR_USERNAME` with the owner's GitHub username (private repositories also require access):

```powershell
git clone https://github.com/YOUR_USERNAME/configshield-ai.git
cd configshield-ai
```

From that project root in PowerShell:

```powershell
py -3.12 -m venv backend\.venv
.\backend\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
.\backend\.venv\Scripts\python.exe -m venv backend\.scanner-venv
.\backend\.scanner-venv\Scripts\python.exe -m pip install -r backend\scanner-requirements.txt
powershell -NoProfile -ExecutionPolicy Bypass -File backend\tools\install-kubeconform.ps1
cd frontend
npm.cmd ci
cd ..
```

Install Python 3.12 if `py -3.12` cannot find it. If the launcher is unavailable but Python is installed, use its full executable path, for example `& "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe" -m venv backend\.venv`. Internet access is needed for initial dependency/tool installation and optional live Gemini. No Docker, Kubernetes cluster, dataset ZIP, or API key is needed for the local mock demonstration. The compatible external YAML and controlled cases are included; scanner and validator executables are installed separately by the commands above.

The validator installer verifies pinned download hashes and uses an existing matching local artifact when available. Review `backend/tools/kubeconform-lock.json` for provenance. Schema/scanner execution needs no runtime network. A clean install on another machine has not been claimed merely from checks on this workspace.

## Start locally

Open two PowerShell terminals in the cloned `configshield-ai` folder. Backend terminal:

```powershell
cd backend
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Frontend terminal:

```powershell
cd frontend
npm.cmd run dev
```

Open http://127.0.0.1:5173. Ctrl+C stops each server. Vite proxies `/api` to FastAPI, rewriting `/api/health` to `/health`. `CONFIGSHIELD_BACKEND_URL` can override the development proxy target. Vite preview serves built assets without this API proxy; production hosting is not included.

### First demonstration, with no API key

Select **CKV_K8S_16 / explicit** under **Try a dataset example**, then click **Load dataset case**. Wait for the automatic scan. For this controlled example only, declare API access and privileged access Not required, and non-root compatibility Yes. Click **Generate mock example**, review the proposed change, approve construction, and run verification. Review the YAML/bullets and acknowledge export before downloading. Mock output is labeled; this does not call Gemini. For real applications, confirm actual requirements or keep them Unknown.

### Troubleshooting

- Backend unavailable: keep the backend terminal running, check port 8000, and use `http://127.0.0.1:5173` through Vite.
- Checkov unavailable: install `scanner-requirements.txt` into `.scanner-venv`, not only the application environment.
- Verification incomplete: run the kubeconform installer and check the reported schema/scanner errors; do not treat missing tools as passes.
- Port already in use: close the server you started with Ctrl+C before restarting. Browser checks need separate unused 8001/5174.
- Gemini setup needed: inspection and mock mode still work. Follow the optional configuration below using your own backend key.
- Requirement conflict: review the declared need; do not change an accurate requirement merely to enable a candidate.

See [sharing and first-push commands](docs/github-sharing.md) for repository setup and the meaning of each Git step.

## Optional Gemini setup and zero-budget controls

No API key is needed for automatic inspection, guidance, or mock examples. For live Gemini, use a Google AI Studio project with billing disabled. This is an owner-confirmed condition; the app cannot inspect account billing. Free-tier quotas and model access still apply. Reviewed model: `gemini-3.1-flash-lite`; standard free input/output pricing was checked on November 18, 2026 in [Google's pricing documentation](https://aistudio.google.com/docs/pricing#gemini-3.1-flash-lite).

```powershell
# From the cloned project root:
cd backend
notepad .env
```

Save these settings, inserting your key privately and confirming billing is disabled before setting the last value true:

```dotenv
AI_PROVIDER=gemini
GEMINI_MODEL=gemini-3.1-flash-lite
GEMINI_API_KEY=YOUR_PRIVATE_KEY
GEMINI_FREE_TIER_CONFIRMED=true
```

The backend automatically reads only these named settings from its local `.env`, supporting plain or matching quoted values. It does not execute text or expand variables. Process environment variables take precedence. No settings file means mock mode by default. Use `AI_PROVIDER=mock` to explicitly disable live generation; update/remove any conflicting terminal environment override too. Keep `.env` out of Git and frontend code.

The green indicator means local Gemini configuration is ready and the backend responded, not that Google authentication or quota was tested. It refreshes every 30 seconds; step 4 also checks automatically. Gemini runs only from its explicit button. One attempt per action, no automatic retry, no tools/paid fallback; five-attempt process cap, 15-second minimum interval, 30-second SDK timeout, and 2,048-output-token limit. Caps are per process, not account-wide. API errors are sanitized.

Gemini receives a finite security projection, reviewed guidance, and confirmed requirements. Raw YAML, names, images, commands, environment values, mounts, and annotations are omitted. No projected input is claimed to be a complete secret detector. Mock/live provenance is shown through export.

## Requirement clues and review

Step 2 automatically shows observed settings and uncertainty. Non-root configuration can suggest compatibility, but it does not prove successful execution. Current privileged permissions and token mounts alone never establish a need. Accept a draft or select a value to declare it; unconfirmed drafts remain Unknown for AI/verification. Changes invalidate old proposals/candidates.

Optional Deployment annotations can supply unconfirmed owner intent: `configshield.ai/api-access` and `configshield.ai/privileged-access` accept `required`/`not_required`; `configshield.ai/non-root-compatibility` accepts `compatible`/`incompatible`. Arbitrary annotation text is not reflected into evidence or prompts. Device, syscall, image, filesystem, and actual API behavior still need owner/runtime review.

## Dataset, RAG, and evaluation

The dataset picker contains 42 synthetic evaluation entries and one original KustomizeGoat base Deployment. Entries are not necessarily unique YAML, and fault labels describe injected evaluation proposals rather than forcing model behavior. The external example has recorded source/checksums but no curated repair ground truth. Partial Kustomize overlays are unsupported. See [dataset contents and source notes](docs/datasets.md), including upstream reuse limitations.

The separate knowledge base contains reviewed Kubernetes/OWASP paraphrases retrieved by exact Checkov ID, with sources, dates, applicability, and limitations. This is lightweight retrieval augmentation, not model training or semantic search. See [architecture](docs/architecture.md).

The A/B/C evaluation compares basic, guidance-augmented, and requirement/verification-augmented pipelines. Offline fixtures deliberately use identical assignments across arms to test filtering, not model superiority. Synthetic expectations stay separate from observed measurements; unknowns are reported separately. See [evaluation methods and observed results](docs/evaluation.md) and the [current validation report](docs/verification.md).

## Repeat checks

```powershell
# From the cloned project root:
cd backend
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe -m evaluation.runner --mode fixtures --output my-offline-results.json
cd ..\frontend
npm.cmd test
npm.cmd run build
npm.cmd run test:browser
```

Use fresh evaluation filenames or explicitly `--overwrite` generated reports. Browser checks start isolated mock-only servers on unused 8001/5174, use installed Edge, compare real downloaded bytes, and write ignored screenshots/report under `frontend/browser-results/`. No live key is used. They are automated browser tests, not human usability testing. `pytest.ini` uses ignored backend `.pytest-tmp` to avoid shared Windows Temp permission problems; do not put personal files there.

## Project map and demo

- `backend/app/`: parser, requirement hints, retrieval, provider, constraints, patcher, verification, API contracts/routes.
- `backend/app/knowledge/`: reviewed guidance; `backend/evaluation/`: controlled cases and measurement runner.
- `backend/tools/`: pinned validator installer and lock; `.scanner-venv` isolates Checkov.
- `frontend/src/`: review UI, API client, export gates, component tests.
- `samples/`: synthetic examples; `samples/external/`: original imported example and provenance.
- [Architecture and trust boundaries](docs/architecture.md), [demo script](docs/demo.md), [draft Devpost content](docs/submission.md), [validation evidence](docs/verification.md).
- [Historical development notes](docs/development-history.md) retain earlier phase descriptions; they are not current setup instructions.

The project never deploys, publishes, or sends messages. API keys, venvs, node_modules, builds, browser artifacts, and generated evaluation reports are ignored. Review public redistribution terms and actual secrets before publishing; no repository or submission has been published by this work. Runtime/cluster compatibility, broader workload support, and a representative repeated model experiment remain future work.

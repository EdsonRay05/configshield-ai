# Validation record — November 18, 2026

This records observed checks on the local Windows workspace. It is not a claim of production readiness, exhaustive security, or runtime application compatibility.

## Automated and real-tool results

| Check | Observed result |
| --- | --- |
| Full backend suite | 269 passed, including four effective-seccomp regression variants |
| Frontend component/workflow suite | 46 passed, including automatic inspection, unconfirmed hints, dataset replacement, quota errors, and export gates |
| Vite production build | Passed |
| Backend dependency consistency | `pip check`: no broken requirements |
| npm dependency audit during Playwright install | Zero reported vulnerabilities across 153 packages at that time |
| Validator setup verification | Existing kubeconform 0.8.0 binary/hash and pinned Kubernetes 1.35.0 schema accepted |
| Targeted post-fix seccomp evaluation | Three fixture arms completed with zero AI requests; C blocked the masked pod-only repair |
| Live A/B/C pilot | Three external attempts; zero accepted candidates; 1,666 reported tokens; no retries/fallback |

The seccomp regression independently rejects an effective insecure container override even when the mocked/real selected scanner reports success. It also rejects privileged-mode bypass. Container and pod RuntimeDefault cases remain accepted by that static check. Runtime syscall compatibility is still untested. The full historical 42-case fixture report was not rerun after this fix; its results remain explicitly historical in the evaluation guide.

The pilot tested one synthetic case and returned unsupported outputs in A/B and a blocked output in C. No candidate was constructed, so schema/regression/requirement-preservation measurements were unknown. Rejected raw responses were not retained; the specific cause cannot be diagnosed from this report. Do not claim measured model superiority or general failure rates. Details and generated report names are in [evaluation.md](evaluation.md).

## Browser and download checks

The reproducible browser script is `frontend/tools/browser-check.mjs`. It starts its own mock-only API on 8001 and Vite on 5174, refuses occupied ports, uses installed headless Microsoft Edge via Playwright 1.65.1, and shuts down the child processes it created. Live Gemini is disabled in those servers. Its report and screenshots are ignored under `frontend/browser-results/`.

The final browser run **passed all six scenario groups** in Edge **157.0.4341.60**, with zero external AI requests: automatic inspection and real mock-provider build/verification/download equality; 390px layout with no horizontal page overflow; Unknown requirements retaining manual review; real API rejection of a requirement conflict; malformed YAML clearing the candidate and displaying an error; and a simulated quota response. Provider quota behavior in this browser check is simulated; the production API's provider behavior is tested separately. Screenshots and `report.json` record the local run.

Initial browser checks found requirement-card overflow at mobile width and exposed old proposal controls during replacement-dataset fetching. Both were corrected and regression coverage added. A test-script timing issue and a relative API URL were also corrected; failed attempts were not labeled successful.

## Source and secret review

`backend/tools/review_secrets.py` inspects Git-visible tracked/untracked source, checks for the actual local saved key and selected credential signatures, and verifies `.env` is ignored. It prints filenames only for matches, never secret values. The final review inspected 76 Git-visible files, found no credential-marker matches, and confirmed `backend/.env` is Git-ignored. This is a bounded check, not a complete secret detector.

No repository, Devpost draft, configuration, or video was published, pushed, or deployed. The user-provided key remains backend-only. The imported KustomizeGoat ZIP lacked a license file; review its reuse terms before public redistribution. No license was invented for that material or for the project.

## Installation and reproducibility limits

The current README consolidates the verified Windows interpreter/venv paths, requirements files, npm lockfile installation, validator installer, startup commands, automatic `.env` behavior, and troubleshooting. Existing dependency consistency and tool installation/hash reuse were checked in this workspace. A clean installation on a different machine was not performed, so it is not claimed. Generated evaluation records contain source/data/tool provenance; the repository has no committed HEAD yet.

A human should still inspect the presentation-monitor layout, keyboard navigation, external source links, and actual Windows save dialog. Headless downloaded-stream equality is not a human save-dialog test. No cluster execution, image behavior, application functionality, admission policies, credentials/RBAC, or availability testing was performed.

## Commands used for repeatable checks

```powershell
cd C:\Users\eesj\Downloads\ai_hack\configshield-ai\backend
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m pip check
powershell -NoProfile -ExecutionPolicy Bypass -File tools/install-kubeconform.ps1
.\.venv\Scripts\python.exe tools/review_secrets.py
cd ..\frontend
npm.cmd test
npm.cmd run build
npm.cmd run test:browser
```

The already-executed live pilot used `--mode live --case-id ckv_k8s_16-explicit --request-budget 3 --output live-pilot-20261118.json`. Repeating it would spend a new attempt budget; it is not part of the zero-request check commands above.

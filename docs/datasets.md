# Dataset inputs in the review workspace

Step 1 offers **Try a dataset example** alongside ordinary YAML upload. Select an entry and click **Load dataset case**. Loading automatically parses, scans, and retrieves reviewed guidance, just like selecting an uploaded file. It replaces the current input, resets requirements to Unknown/unconfirmed drafts, and discards old review results. No Gemini request is made until explicitly requested. Parse/scan buttons remain available for explicit retries.

The catalog has 43 entries:

- 42 controlled synthetic evaluation cases from `backend/evaluation/cases.json`. Variants can share identical YAML; a `fault` label describes the evaluation runner's injected response, not an injected fault in the UI. Loading a case does not simulate that response. The catalog does not return expected findings, forbidden changes, or requirement annotations as model inputs.
- One external KustomizeGoat base Deployment from the user-supplied `kustomizegoat-main.zip`. This is additional test input, not training data or a labeled benchmark. Requirements must be declared by the user; undeclared Linux OS is an assumption surfaced by the parser.

The imported file is `samples/external/kustomizegoat-base.yaml`, copied without modification from `kustomizegoat-main/kustomize/base/deployment.yaml`. `samples/external/provenance.json` records the source URL, archive-entry path, archive checksum, extracted-file checksum, and unknown source revision. No license file was found in that ZIP; provenance records this rather than inventing a license. Review upstream reuse terms before redistributing the imported example. The upstream source is https://github.com/bridgecrewio/kustomizegoat.

Only the complete base Deployment was imported. The `test` and `prod` Deployment files are partial Kustomize patches without a complete selector and cannot be directly uploaded to this MVP. Services, storage definitions, and Kustomization files are outside its Deployment scope. Nothing is rendered, executed, or deployed from the archive.

`backend/app/services/datasets.py` builds the catalog from fixed local sources. `GET /api/datasets` returns metadata; `GET /api/datasets/{case_id}` returns one input's YAML, filename, and checksum. IDs are looked up in a fixed catalog rather than interpreted as filesystem paths. A modified external file fails its checksum check; an unavailable dataset does not disable manual upload. The existing parser validates selected contents before serving them.

Observed on November 18, 2026: the imported external input passed the pinned Kubernetes 1.35.0 schema check. Real Checkov 3.4.5 completed all seven selected rules: six failed (20, 23, 28, 31, 37, 38), rule 16 passed, and none were skipped. These are scanner observations, not proof of complete security or runtime behavior. No model request was made. The 42 synthetic-case evaluation results remain a separate offline experiment documented in `evaluation.md`; this integration does not add the external example to its ground truth or fabricate model results.

Start the backend and frontend using the README instructions, then refresh the browser to use the picker. Repeat integration checks with:

```powershell
cd C:\Users\eesj\Downloads\ai_hack\configshield-ai\backend
.\.venv\Scripts\python.exe -m pytest -q tests/test_datasets.py
cd ..\frontend
npm.cmd test
npm.cmd run build
```

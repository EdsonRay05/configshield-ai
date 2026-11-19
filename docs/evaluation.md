# Phase 9: reproducible evaluation

The offline run tests the measurement pipeline and review gate. It does **not** measure Gemini quality or establish that retrieval or constraints improve model output. No model requests are needed for this run.

## Design

The synthetic dataset contains 42 annotated single-container Deployments: seven selected Checkov rules crossed with explicit, omitted, context, intent, combined, and injected-fault variants. One omitted-privileged case is a negative control: absence of that setting already passes the selected rule. There are 34 ordinary positive cases, seven injected fault cases, and one negative control. These are curated examples, not a representative sample of production workloads.

`backend/evaluation/cases.py` builds the dataset from the secure sample. `cases.json` records YAML, content hashes, declared requirements, expected findings, necessary paths, and forbidden assignments. `load_dataset()` checks reproducibility before use. Expected annotations remain separate from observed scanner results; a mismatch stops the run rather than relabeling it automatically.

The three arms share their system instruction, response schema, security evidence, model configuration, token limit, and scoring rules:

| Arm | Inputs and behavior |
| --- | --- |
| A | Security finding and minimized configuration evidence |
| B | A plus reviewed local guidance |
| C | B plus application requirements; candidate passes through the production verifier before review eligibility |

Expected answers, case IDs, fault labels, full YAML, names, and environment values are excluded from prompts. Offline fixtures deliberately propose the same field assignments across all arms. Consequently, offline differences demonstrate filtering behavior, not better generated repairs. Arm order is shuffled with a recorded seed.

## Measurements

All arms receive the same post-hoc schema validation, fresh selected-rule scanning, semantic field comparison, and independent declared-requirement oracle. Exact-content caching avoids repeating identical subprocess work; cached results are copied. The oracle uses curated forbidden assignments rather than the production constraint checker. This is still a limited synthetic oracle, not proof of application compatibility.

Reports include candidate coverage, target repair, schema validity, new findings, requirement preservation, unnecessary semantic fields, unsupported outputs, abstentions, review decisions, requests, token usage, and provenance. Boolean rates include true, measured, and unknown counts. Unknown values never count as passes. Missing or malformed output stays in the case denominator; quality among produced candidates must be interpreted alongside coverage. Negative controls and injected faults are reported separately. No candidate is deployed.

`raw_reliable_candidate` requires a repaired target, valid schema, no new selected findings, preserved scorable requirements, no unnecessary fields, and supported output. Unknown requirements yield unknown quality unless another criterion already fails. Review eligibility is a separate system decision and can retain uncertainty or unrelated existing findings. It is not a safety guarantee.

The seccomp context case probes an effective container override: adding a pod default can satisfy a scanner while leaving a container override. The curated necessary-path check exposes this limitation. Scanner success alone cannot establish runtime enforcement or application behavior.

## Run locally with zero AI requests

From PowerShell:

```powershell
cd C:\Users\eesj\Downloads\ai_hack\configshield-ai\backend
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m evaluation.runner --mode fixtures --output offline-user-results.json
.\.venv\Scripts\python.exe -m evaluation.runner --mode prompts --output user-prompts.json
```

Generated JSON stays in ignored `backend/evaluation/results/`. Existing outputs require a new filename or explicit `--overwrite`. Fixture mode defaults to a zero request budget and never constructs a Gemini provider. Prompt mode writes 102 inspectable prompts without sending them. Checkov and kubeconform must already be installed using the project setup instructions.

`metrics.py` computes common scores. `runner.py` builds prompts, enforces the request budget, invokes tools, records checkpoints, and summarizes ordinary versus injected cases. `tests/test_evaluation.py` checks dataset integrity, prompt isolation, independent scoring, cache behavior, failure denominators, and request-budget enforcement with mocked providers.

## Observed offline results, November 17, 2026

The complete fixture run produced 126 rows for 42 cases with zero external requests, zero model tokens, 80 distinct real Checkov calls, and 81 distinct real schema checks. Checkov was 3.4.5; kubeconform was 0.8.0 with the pinned Kubernetes 1.35.0 schema. All original findings matched the predeclared annotations. The backend suite passed 246 tests, including 19 evaluation tests; dependency checking passed.

For the 34 ordinary positive cases, these common raw-candidate scores were identical across A, B, and C **by construction**:

| Measurement | Observed fixture result per arm |
| --- | --- |
| Candidate produced | 34/34 |
| Selected scanner target passed | 34/34 |
| Schema passed | 34/34 |
| New selected findings | 0/34 |
| Declared requirements preserved | 27/30 measured; 4 unknown |
| Composite reliable candidate | 26/30 measured; 4 unknown |
| Unnecessary semantic changes | 1 field across the 34 cases |

A and B returned all 34 candidates, including three declared-requirement conflicts and the seccomp context limitation. C blocked the three conflicts and marked 31 candidates eligible for human review. Those 31 still included four unknown-quality cases and the seccomp limitation. In that limitation, the pod assignment passed Checkov while leaving the container `Unconfined`; the independent curated path oracle marked it unreliable. This is an unsuccessful case for automatic detection, not evidence of effective enforcement.

For the seven separately injected fault cases, five candidates were constructed, one response was malformed, and one abstained in every arm. Six outputs were unsupported or failed. C blocked those six and retained the abstention, exposing none of their candidates for review. These frequencies reflect deliberately selected fixtures, not observed LLM behavior. The negative control was excluded from repair-rate denominators.

The complete machine-readable evidence is in generated `backend/evaluation/results/offline-results.json`; prompts are in `prompts.json`. These ignored artifacts can be regenerated. This historical run supports a limited filtering demonstration and identified a scanner limitation. It predates the independent effective-seccomp guard described below. The broad research question needs a meaningful repeated model experiment; a tiny pilot cannot answer it.

## November 18 follow-up: seccomp guard and live pilot

The production verifier now independently checks the effective container profile for `CKV_K8S_31` repairs. It requires effective `RuntimeDefault` and rejects privileged mode that bypasses the restriction. An explicit container profile takes precedence over a pod profile. A failed effective check prevents targeted-resolution claims and returns `failed_validation`, blocking candidate export.

The targeted offline rerun `seccomp-regression-20261118.json` completed the context case for A/B/C with zero AI requests. Common raw scoring still found the pod-only assignment unreliable. A/B returned it; C now blocked it with `failed_validation`. The earlier full 42-case results above have not been silently replaced or presented as a post-fix rerun. Runtime syscall compatibility remains untested.

One explicitly authorized live pilot used `ckv_k8s_16-explicit`, the pinned free-tier model, a three-request cap, the same response schema/system instruction, and the fixed arm ordering seed. Google returned three responses; none passed the evaluation harness's supported-output checks. Observed results:

| Arm | Candidate produced | Accepted target repair | Reported tokens | Decision |
| --- | --- | --- | --- | --- |
| A | No | No | 416 | Unsupported output |
| B | No | No | 596 | Unsupported output |
| C | No | No | 654 | Blocked |

Total external attempts: **3**; total reported tokens: **1,666**. No retry, paid model, or provider fallback was used. Schema validity, new findings, requirement preservation, and field-change counts were not measurable because no candidate was produced. Missing measurements are not passes. The report is `live-pilot-20261118.json` in the ignored results directory. It records timestamps, versions, hashes, usage, and rejection codes. Rejected raw response text was not retained, so the precise rejection cause cannot be diagnosed from this pilot; the result must not be attributed to a specific model defect. This unsuccessful single-case pilot establishes neither superiority nor general model failure rates. A later experiment should retain bounded diagnostic evidence under an explicitly reviewed data policy and predefine a larger matched design.

## Optional live pilot — not performed automatically

A live comparison requires the existing Gemini free-tier configuration and confirmation. The runner permits one ordinary positive case and exactly three explicitly budgeted requests, one per arm. It waits at least 15 seconds between attempts, records an attempt before sending it, and stops on the first provider error without retry or fallback. A rerun is another independently budgeted pilot; the budget is not an account-wide spending control.

Only after deliberately configuring the free-tier project, this command requests the three-call pilot:

```powershell
.\.venv\Scripts\python.exe -m evaluation.runner --mode live --case-id ckv_k8s_16-explicit --request-budget 3 --output live-pilot-results.json
```

Do not treat one three-request pilot as evidence of superiority. A meaningful model experiment needs repeated matched cases, a predefined analysis, quota planning, uncertainty estimates, and independent human review of expected changes. No such results are claimed here. Estimates of input tokens are labeled estimates; actual usage comes from provider metadata when available. Interrupted reports retain pending attempts and incomplete status.

## Limits for a hackathon presentation

Supported claims: the local workflow parses, scans, retrieves reviewed guidance, proposes bounded edits, checks declared requirements, verifies candidates, and requires human review. Offline evaluation can demonstrate rejection of deliberately invalid or conflicting proposals.

Unsupported claims: production readiness, full Kubernetes security, preserved runtime behavior, measured Gemini accuracy, causal benefit from retrieval, or generalization beyond these synthetic examples. Tool versions, dataset/source hashes, timestamps, seed, and request counts are recorded for reproducibility; an uncommitted repository has no commit identifier.

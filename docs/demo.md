# Hackathon demonstration

Use synthetic inputs; do not upload real credentials. Start the backend and Vite using the README. Keep live Gemini optional so a quota limit cannot prevent the demonstration.

## Three-minute script

1. **Problem (20 seconds).** “Security scanners find risky Kubernetes settings. A suggested fix can still break an application's requirements. ConfigShield makes the change reviewable and independently checks it.”
2. **Automatic inspection (30 seconds).** In step 1 select `CKV_K8S_16 / explicit` and click **Load dataset case**. Parsing, scanning, and reviewed guidance appear automatically. Explain the seven-check scope and source links. Dataset cases are test inputs, not model training.
3. **Requirements (20 seconds).** For this controlled example, declare API access and privileged access Not required, and non-root compatibility Yes. Explain that automatic hints are unconfirmed drafts and genuine unknowns stay Unknown.
4. **Suggestion (30 seconds).** Click **Generate mock example**, openly identifying it as a deterministic demonstration. If deliberately using live mode, use **Ask Gemini — one request** once and show the actual response. Do not represent mock output as live AI.
5. **Review and verification (45 seconds).** Approve construction. Show the changed-field bullets, `privileged: true → false`, and original/candidate YAML. Run verification. For the single-finding controlled example, expect the selected target to pass while runtime review remains required.
6. **Download (15 seconds).** Acknowledge the review and download. Explain that the app never deploys it and the downloaded bytes are bound to the verification result.
7. **Honest results (20 seconds).** Show the verification report and evaluation guide. The broad evaluation is scripted and synthetic; a tiny live pilot is not a statistical comparison. Mention the effective-seccomp override regression and its independent guard.

## Alternate paths

- **Requirement conflict:** use `CKV_K8S_16 / intent` only as an input; its dataset annotation is not applied to the UI. Declare privileged access Required. The mock provider should abstain. If a real model proposes disabling it, independent constraint checks should block construction. Do not promise that a model will produce a particular response.
- **Unknowns:** load an input and leave controls Unknown/unconfirmed. Verification should retain manual-review uncertainty rather than claim application compatibility.
- **Multiple findings:** load `insecure-deployment.yaml` or KustomizeGoat. Repairing one finding does not resolve the rest; review remaining findings and restrictions on export.
- **Seccomp regression:** the evaluation `CKV_K8S_31 / context` input has a container override. A pod-only repair must be rejected by the independent effective-seccomp check even if Checkov passes.
- **Quota/offline fallback:** show the error without repeatedly clicking Gemini. Choose the mock action explicitly and label it. No paid model or automatic alternate provider is used.
- **Invalid input:** choose malformed YAML or a Service. Show the bounded parse error; no scan or generation should follow.

## Final human checks

The automated browser check runs headless Edge and checks a downloaded stream against the reviewed YAML, plus desktop/mobile layout overflow. A human should still confirm readability on the actual presentation monitor, keyboard navigation, external source links, and the Windows save-dialog experience. Cluster/runtime testing is outside this demo; no such result should be claimed.

Before presenting, close unrelated sensitive tabs, refresh the local page, verify the status indicator, and keep the controlled sample available. No repository, video, or submission is published by these instructions.

# Draft Devpost content — not published

## Project name

ConfigShield AI

## Tagline

Review Kubernetes security fixes with application intent, grounded guidance, and independent verification.

## Inspiration

A security finding tells developers that a setting deserves attention. It does not establish that changing the setting will preserve the application's needs. We wanted a small, understandable workflow that helps people examine a suggested repair before accepting it.

## What it does

ConfigShield inspects a supported Kubernetes Deployment, runs seven selected Checkov policies, retrieves reviewed Kubernetes/OWASP guidance, and helps explain one finding at a time. It derives conservative requirement clues from YAML for owner confirmation. A user can request a Gemini suggestion or choose an explicitly labeled mock demonstration. Proposed field edits are allowlisted, checked against declared needs, and constructed only after approval.

The workspace shows original/candidate YAML and bullet explanations of actual changes. Independent verification checks schema, selected findings, new regressions, declared requirements, and effective seccomp configuration. A final acknowledgement permits a local download when checks allow it. Nothing deploys to a cluster.

## How we built it

React, Vite, and Tailwind provide the interface. FastAPI and Pydantic validate contracts, PyYAML handles bounded parsing, and isolated Checkov/kubeconform processes supply deterministic checks. Lightweight RAG maps exact finding IDs to a curated, reviewed local knowledge base. Google Gemini is optional through a backend-only key and a restricted free-tier configuration. Dataset examples support testing; they are not used to train a model.

## Challenges

The project separates uncertainty from failure, owner intent from existing permissions, and generated suggestions from verified outcomes. One evaluation case showed a pod seccomp default passing a scanner despite an insecure container override. We added an independent effective-profile check rather than treating scanner success as sufficient. Other application behavior still requires runtime testing.

## Accomplishments

An end-to-end local review workflow, explicit human approvals, bounded field edits, real scanner/schema integration, readable change explanations, and a reproducible evaluation harness. The validation report records actual checks and their limitations. Do not add performance or model-superiority claims unless supported by the recorded experiment.

## What we learned

Security remediation needs more than plausible YAML. Provenance, constrained changes, independently recomputed results, and visible unknowns help users understand what they are approving. Static checks can still miss effective behavior, and a small model pilot cannot establish general reliability.

## What's next

Runtime validation, independently reviewed real-world benchmarks, more application-requirement categories, broader workload support, and stronger effective-policy checks. These are future work, not current features.

## Built with

Python, FastAPI, Pydantic, PyYAML, Checkov, kubeconform, Gemini API, JavaScript, React, Vite, Tailwind CSS, Vitest, Playwright.

## Before submitting

Add the actual team members, event/category, approved repository/demo/video links, and required disclosures. These details are not inferred. Check the current validation report for observed counts. Review upstream reuse terms for the imported KustomizeGoat file before public redistribution. No repository or Devpost entry has been published.

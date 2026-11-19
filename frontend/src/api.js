export async function getDatasetCatalog() {
  const response = await fetch('/api/datasets', { signal: AbortSignal.timeout(5000) });
  if (!response.ok) throw new Error('Dataset catalog unavailable. You can still upload a YAML file.');
  const data = await response.json();
  if (!Array.isArray(data.entries)) throw new Error('Unexpected dataset catalog response.');
  return data.entries;
}

export async function getDatasetCase(id) {
  const response = await fetch(`/api/datasets/${encodeURIComponent(id)}`, { signal: AbortSignal.timeout(5000) });
  if (!response.ok) throw new Error('Dataset case unavailable. Try another case or upload a YAML file.');
  const data = await response.json();
  if (data.id !== id || typeof data.yaml !== 'string' || typeof data.filename !== 'string' || data.yaml.length > 256 * 1024) throw new Error('Unexpected dataset case response.');
  return data;
}

export async function checkHealth() {
  const response = await fetch('/api/health', {
    signal: AbortSignal.timeout(5000),
    headers: { Accept: 'application/json' },
  });
  if (!response.ok) {
    throw new Error('Backend unavailable. Start FastAPI on port 8000 and try again.');
  }
  const data = await response.json();
  if (data.status !== 'ok' || data.service !== 'configshield-ai') {
    throw new Error('The backend returned an unexpected health response.');
  }
  return data;
}

export async function parseDeployment(file) {
  const response = await fetch(`/api/parse?filename=${encodeURIComponent(file.name)}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/yaml', Accept: 'application/json' },
    body: file,
    signal: AbortSignal.timeout(15000),
  });
  const data = await response.json().catch(() => null);
  if (!response.ok) {
    throw new Error(data?.error?.message || 'Upload failed. Check that the backend is running and try again.');
  }
  if (data?.status !== 'parsed' || !data.deployment || !Array.isArray(data.warnings)) {
    throw new Error('The backend returned an unexpected parse response.');
  }
  return data;
}

export async function scanDeployment(file) {
  const response = await fetch(`/api/scan?filename=${encodeURIComponent(file.name)}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/yaml', Accept: 'application/json' },
    body: file,
    signal: AbortSignal.timeout(75000),
  });
  const data = await response.json().catch(() => null);
  if (!response.ok) {
    throw new Error(data?.error?.message || 'Scan unavailable. Check that the backend and Checkov are installed and running.');
  }
  if (!['completed', 'incomplete'].includes(data?.status) || !Array.isArray(data.findings)
      || !Array.isArray(data.passed_checks) || !Array.isArray(data.skipped_checks)
      || !Array.isArray(data.warnings) || !Array.isArray(data.supported_checks)) {
    throw new Error('The backend returned an unexpected scan response.');
  }
  return data;
}

export async function getAIStatus() {
  const response = await fetch('/api/ai/status', { signal: AbortSignal.timeout(5000) });
  if (!response.ok) throw new Error('AI settings are unavailable. Check the backend connection.');
  const data = await response.json();
  if (typeof data.gemini_ready !== 'boolean') throw new Error('Unexpected AI status response.');
  return data;
}

export async function explainDeployment(file, checkId, provider, requirements = {}) {
  const query = new URLSearchParams({ filename: file.name, check_id: checkId, provider, ...requirements });
  const response = await fetch(`/api/explain?${query}`, {
    method: 'POST', headers: { 'Content-Type': 'application/yaml', Accept: 'application/json' },
    body: file, signal: AbortSignal.timeout(105000),
  });
  const data = await response.json().catch(() => null);
  if (!response.ok) throw new Error(data?.error?.message || 'Explanation unavailable. No automatic retry was made.');
  if (!['mock', 'generated'].includes(data?.status) || !data.proposal
      || !Array.isArray(data.proposal.candidates) || !Array.isArray(data.proposal.limitations)
      || !Array.isArray(data.proposal.source_document_ids) || !Array.isArray(data.warnings) || !data.usage
      || !data.original_sha256 || !Array.isArray(data.constraint_report?.results)) {
    throw new Error('The backend returned an unexpected explanation response.');
  }
  return data;
}

export async function buildCandidate(file, explanation, requirements, approved, acknowledgeManualReview) {
  // Preserve a UTF-8 BOM, if present, so the original byte hash still matches.
  const originalYaml = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(await file.arrayBuffer());
  const response = await fetch('/api/candidate', {
    method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ filename: file.name, original_yaml: originalYaml,
      original_sha256: explanation.original_sha256, proposal: explanation.proposal, requirements,
      approved, acknowledge_manual_review: acknowledgeManualReview }),
    signal: AbortSignal.timeout(75000),
  });
  const data = await response.json().catch(() => null);
  if (!response.ok) throw new Error(data?.error?.message || 'The candidate could not be prepared. No configuration was changed.');
  if (!['review_required', 'blocked', 'candidate_created', 'no_changes'].includes(data?.status)
      || !Array.isArray(data.constraint_report?.results) || !Array.isArray(data.semantic_changed_paths)
      || !Array.isArray(data.warnings) || (data.status === 'candidate_created' && typeof data.candidate_yaml !== 'string')) {
    throw new Error('The backend returned an unexpected candidate response.');
  }
  return { ...data, original_yaml: originalYaml };
}

export async function verifyCandidate(file, explanation, requirements, candidate) {
  const response = await fetch('/api/verify', {
    method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ filename: file.name, original_yaml: candidate.original_yaml,
      original_sha256: explanation.original_sha256, candidate_yaml: candidate.candidate_yaml,
      proposal: explanation.proposal, requirements }),
    signal: AbortSignal.timeout(180000),
  });
  const data = await response.json().catch(() => null);
  if (!response.ok) throw new Error(data?.error?.message || 'Verification could not complete. No successful result is claimed.');
  if (!['verified_supported_checks', 'failed_validation', 'new_security_findings', 'requirement_conflict', 'incomplete', 'manual_review'].includes(data?.status)
      || !Array.isArray(data.checks) || !Array.isArray(data.resolved_findings) || !Array.isArray(data.new_findings)
      || !Array.isArray(data.remaining_findings) || !Array.isArray(data.unexpected_changed_paths)
      || !Array.isArray(data.warnings)) {
    throw new Error('The backend returned an unexpected verification response.');
  }
  return data;
}

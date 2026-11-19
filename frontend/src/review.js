export const VERIFICATION_LABELS = {
  verified_supported_checks: 'Verified by supported checks',
  failed_validation: 'Failed validation',
  new_security_findings: 'New security findings detected',
  requirement_conflict: 'Requirement conflict detected',
  incomplete: 'Verification incomplete',
  manual_review: 'Requires manual review',
};

export const CHECK_LABELS = {
  effective_seccomp: 'Effective container seccomp profile',
  original_binding: 'Original matches this review',
  original_structure: 'Original YAML and supported structure',
  candidate_structure: 'Candidate YAML and supported structure',
  authorized_changes: 'Only approved fields changed',
  schema_validation: 'Kubernetes schema validation',
  original_security_scan: 'Original security scan execution',
  candidate_security_scan: 'Candidate security scan execution',
  finding_comparison: 'Comparable security findings',
  targeted_repair: 'Targeted finding resolved',
  requirement_checks: 'Declared application requirements',
  runtime_compatibility: 'Runtime compatibility',
};

export const REQUIREMENT_LABELS = {
  api_access: 'Kubernetes API access',
  privileged_access: 'Privileged host/device access',
  non_root_compatibility: 'Non-root compatibility',
  execution_identity: 'Execution identity',
  capability_compatibility: 'Capability compatibility',
  seccomp_compatibility: 'Seccomp compatibility',
  privilege_escalation_effectiveness: 'Privilege restriction effectiveness',
  runtime_compatibility: 'Runtime compatibility',
};

const REQUIRED_CHECKS = [
  'original_binding', 'original_structure', 'candidate_structure', 'authorized_changes',
  'schema_validation', 'original_security_scan', 'candidate_security_scan',
  'finding_comparison', 'targeted_repair',
];

export async function sha256(text) {
  if (!globalThis.crypto?.subtle) throw new Error('This browser cannot confirm the reviewed bytes. Use localhost or HTTPS.');
  const bytes = new TextEncoder().encode(text);
  const digest = await globalThis.crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

export async function verificationMatches(candidate, verification) {
  if (!candidate?.original_yaml || !candidate?.candidate_yaml || !verification) return false;
  const [originalHash, candidateHash] = await Promise.all([
    sha256(candidate.original_yaml), sha256(candidate.candidate_yaml),
  ]);
  return originalHash === verification.original_sha256 && candidateHash === verification.candidate_sha256;
}

export function downloadDecision(candidate, verification, hashesMatch) {
  const blocked = (reason) => ({ allowed: false, reason });
  if (candidate?.status !== 'candidate_created' || !candidate.candidate_yaml) return blocked('Build an approved candidate first.');
  if (!verification) return blocked('Run independent verification before downloading the candidate.');
  if (!['verified_supported_checks', 'manual_review'].includes(verification.status)) {
    return blocked(`${VERIFICATION_LABELS[verification.status] || 'Verification unavailable'}. Resolve the failed or incomplete checks before downloading this candidate.`);
  }
  if (!hashesMatch) return blocked('The current YAML must match the verification result before downloading.');
  const checks = verification.checks || [];
  if (REQUIRED_CHECKS.some((name) => {
    const matches = checks.filter((check) => check.name === name);
    return matches.length !== 1 || matches[0].status !== 'passed';
  })) {
    return blocked('Required validation or comparison checks have not passed.');
  }
  if (verification.schema_validation?.status !== 'passed' || verification.targeted_finding_resolved !== true
      || !Array.isArray(verification.new_findings) || verification.new_findings.length
      || !Array.isArray(verification.unexpected_changed_paths) || verification.unexpected_changed_paths.length) {
    return blocked('The candidate has unresolved validation, regression, or unauthorized-change results.');
  }
  const scans = [verification.original_scan, verification.candidate_scan];
  if (scans.some((scan) => scan?.status !== 'completed' || !Array.isArray(scan.skipped_checks) || scan.skipped_checks.length
      || !Array.isArray(scan.findings) || !Array.isArray(scan.supported_checks) || scan.supported_checks.length !== 7)
      || scans[0].scanner_version !== scans[1].scanner_version
      || !Array.isArray(verification.remaining_findings)
      || (verification.status === 'verified_supported_checks' && scans[1].findings.length)) {
    return blocked('Complete comparable security scans are required before downloading.');
  }
  if (!verification.constraint_report || verification.constraint_report.status === 'conflict'
      || !Array.isArray(verification.constraint_report.results)
      || verification.constraint_report.results.some((item) => item.status === 'conflict')) {
    return blocked('A declared requirement conflict must be resolved first.');
  }
  if (!['passed', 'manual_review'].includes(checks.find((check) => check.name === 'requirement_checks')?.status)) {
    return blocked('Independent requirement checks are unavailable.');
  }
  return { allowed: true, reason: verification.status === 'manual_review'
    ? 'Download is available for manual review. Remaining findings and uncertainties still apply.'
    : 'The selected checks passed. Review and runtime testing are still your responsibility.' };
}

export function downloadName(filename, variant = 'candidate') {
  const basename = String(filename || 'deployment.yaml').split(/[\\/]/).pop();
  let stem = basename.replace(/\.ya?ml$/i, '').replace(/[^a-zA-Z0-9._-]/g, '-').replace(/^\.+/, '').slice(0, 80);
  if (!stem || /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(stem)) stem = 'deployment';
  return `${stem}.${variant === 'original' ? 'original' : 'candidate-review'}.yaml`;
}

export function startDownload(blob, filename) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  try {
    document.body.append(anchor);
    anchor.click();
  } finally {
    anchor.remove();
    // Give the browser time to consume the object URL before releasing it.
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
}

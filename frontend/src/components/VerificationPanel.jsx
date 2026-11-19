import { useState } from 'react';
import { verifyCandidate } from '../api.js';
import { CHECK_LABELS, REQUIREMENT_LABELS, VERIFICATION_LABELS as LABELS } from '../review.js';

export default function VerificationPanel({ file, explanation, requirements, candidate, disabled, onBusyChange, onResultChange }) {
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  async function verify() {
    if (busy || disabled) return;
    setBusy(true); setResult(null); setError(''); onBusyChange(true);
    onResultChange?.(null);
    try { const response = await verifyCandidate(file, explanation, requirements, candidate); setResult(response); onResultChange?.(response); }
    catch (failure) { setError(failure.name === 'TimeoutError' ? 'Verification request timed out. No successful result is claimed.' : failure.message); }
    finally { setBusy(false); onBusyChange(false); }
  }

  const comparable = result?.checks.some((check) => check.name === 'finding_comparison' && check.status === 'passed');
  return (
    <section id="verification" aria-labelledby="verification-title" className="mt-6 border-t border-slate-600 pt-5">
      <p className="eyebrow">06 / Verify</p>
      <h3 id="verification-title" className="mt-2 text-xl font-semibold">Independent verification</h3>
      <p className="mt-2 text-sm text-slate-300">Validate the candidate schema, re-scan both configurations, compare findings, and recheck requirements. This makes no AI request and does not deploy anything.</p>
      <button type="button" disabled={busy || disabled} onClick={verify} className="mt-4 rounded-lg border border-emerald-300 px-4 py-3 text-sm font-semibold text-emerald-300 disabled:opacity-50">{busy ? 'Verifying...' : 'Verify candidate'}</button>
      {busy && <p role="status" className="mt-3 text-sm text-slate-300">Running independent checks. Two security scans can take up to two minutes.</p>}
      {error && <p role="alert" className="mt-3 text-rose-300">{error}</p>}
      {result && <div className="mt-5">
        <p role="status" className={`font-semibold ${result.status === 'verified_supported_checks' ? 'text-emerald-200' : 'text-amber-200'}`}>{LABELS[result.status]}</p>
        <p className="mt-2 text-sm text-slate-300">Targeted finding: {result.targeted_finding_resolved === true ? 'resolved by its selected check' : result.targeted_finding_resolved === false ? 'not confirmed resolved' : 'not verified'}.</p>
        {result.schema_validation && <p className="mt-2 text-sm text-slate-400">Schema target: Kubernetes {result.schema_validation.kubernetes_version} · Kubeconform {result.schema_validation.validator_version} · {result.schema_validation.status}</p>}
        <ul className="mt-5 space-y-3 text-sm">{result.checks.map((check) => <li key={check.name} className="rounded border border-slate-700 p-3">
          <p className="font-semibold">{CHECK_LABELS[check.name] || 'Additional check'}: <span className={check.status === 'passed' ? 'text-emerald-200' : check.status === 'failed' ? 'text-rose-300' : 'text-amber-200'}>{check.status.replaceAll('_', ' ')}</span></p>
          <p className="mt-1 text-slate-300">{check.message}</p>
        </li>)}</ul>
        {comparable ? <div className="mt-5 space-y-4">
          {[['Resolved findings', result.resolved_findings], ['New findings', result.new_findings], ['Remaining findings', result.remaining_findings]].map(([title, findings]) => <div key={title}>
            <h6 className="text-sm font-semibold">{title}: {findings.length}</h6>
            <ul className="mt-2 space-y-2 text-sm text-slate-300">{findings.map((finding) => <li key={`${finding.check_id}-${finding.resource}`}><span className="font-medium">{finding.check_id}</span> — {finding.description}</li>)}</ul>
          </div>)}
        </div> : <p className="mt-5 text-sm text-amber-200">Finding comparison is unavailable. No resolved-finding count is claimed.</p>}
        {result.unexpected_changed_paths.length > 0 && <p className="mt-5 break-all text-sm text-rose-300">Unexpected fields: {result.unexpected_changed_paths.join(', ')}</p>}
        {result.constraint_report && <div className="mt-5">
          <h6 className="text-sm font-semibold">Rechecked requirements</h6>
          <ul className="mt-2 space-y-2 text-sm text-slate-300">{result.constraint_report.results.map((item, index) => <li key={`${item.requirement}-${index}`}>{REQUIREMENT_LABELS[item.requirement] || 'Additional requirement'}: {item.status === 'unverifiable' ? 'needs review' : item.status}. {item.message}</li>)}</ul>
        </div>}
        <ul className="mt-5 list-disc space-y-2 pl-5 text-xs text-amber-200">{result.warnings.map((warning) => <li key={warning}>{warning}</li>)}</ul>
        <p className="mt-3 text-sm text-slate-300">Human review is still required before using any candidate. No runtime compatibility is claimed.</p>
      </div>}
    </section>
  );
}

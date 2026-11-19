import { useEffect, useRef, useState } from 'react';
import { downloadDecision, downloadName, startDownload, verificationMatches, VERIFICATION_LABELS } from '../review.js';

export default function ReviewDownloadPanel({ file, candidate, verification, provenance, disabled, onDownloaded, onReviewed }) {
  const [acknowledged, setAcknowledged] = useState(false);
  const [binding, setBinding] = useState('pending');
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [exporting, setExporting] = useState(false);
  const revision = useRef(0);

  useEffect(() => {
    let current = true;
    revision.current += 1;
    setAcknowledged(false); setBinding('pending'); setError(''); setMessage(''); setExporting(false);
    if (verification) {
      verificationMatches(candidate, verification).then((matched) => {
        if (current) setBinding(matched ? 'matched' : 'mismatch');
      }).catch((failure) => { if (current) { setBinding('mismatch'); setError(failure.message); } });
    }
    return () => { current = false; revision.current += 1; };
  }, [candidate, verification]);

  const decision = downloadDecision(candidate, verification, binding === 'matched');
  const remaining = verification?.remaining_findings?.length || 0;

  function downloadOriginal() {
    setError('');
    try { startDownload(file, downloadName(file.name, 'original')); setMessage('Original download started.'); }
    catch { setError('The browser could not start the download. Try again.'); }
  }

  async function downloadCandidate() {
    if (disabled || exporting || !acknowledged || !decision.allowed) return;
    const actionRevision = revision.current;
    setError(''); setExporting(true);
    try {
      // Re-check immediately before exporting, not only when rendering the panel.
      const matches = await verificationMatches(candidate, verification);
      if (actionRevision !== revision.current) return;
      if (!matches) {
        setAcknowledged(false); setBinding('mismatch');
        throw new Error('The YAML no longer matches its verification result. Run verification again.');
      }
      startDownload(new Blob([candidate.candidate_yaml], { type: 'application/yaml;charset=utf-8', endings: 'transparent' }), downloadName(file.name));
      setMessage('Candidate download started. Review it before using it in any environment.');
      onDownloaded?.();
    } catch (failure) {
      if (actionRevision === revision.current) setError(failure.message || 'The browser could not start the download.');
    } finally { if (actionRevision === revision.current) setExporting(false); }
  }

  return (
    <section id="download" aria-labelledby="download-title" className="mt-7 rounded-xl border border-slate-600 bg-slate-950/50 p-5 sm:p-6">
      <p className="eyebrow">Final step / Your decision</p>
      <h3 id="download-title" className="mt-2 text-xl font-semibold">Review &amp; download</h3>
      <p className="mt-3 text-xs font-medium text-slate-400">{provenance === 'mock' ? 'Mock-generated candidate' : provenance === 'generated' ? 'AI-generated candidate' : 'Candidate proposal'} · Verification results are independent of the proposal source.</p>
      <p className="mt-3 text-sm text-slate-300">{verification ? VERIFICATION_LABELS[verification.status] : 'Verification has not run.'} {decision.reason}</p>
      {remaining > 0 && <p className="notice mt-4">This candidate still has {remaining} selected security {remaining === 1 ? 'finding' : 'findings'}. Downloading does not mark them resolved.</p>}
      {verification?.status === 'manual_review' && <p className="mt-3 text-sm text-amber-200">Review the verification panel for remaining findings and unknown requirements. This is a candidate for investigation, not a deployment recommendation.</p>}
      <label className="mt-5 flex items-start gap-3 text-sm text-slate-200">
        <input type="checkbox" checked={acknowledged} disabled={disabled || exporting || !decision.allowed} onChange={(event) => { setAcknowledged(event.target.checked); onReviewed?.(event.target.checked); }} className="mt-1 accent-emerald-300" />
        <span>I reviewed the changes and verification results. I understand the remaining findings and uncertainties, and want to download this candidate for my own review.</span>
      </label>
      <div className="mt-5 flex flex-wrap gap-3">
        <button type="button" disabled={disabled || exporting || !decision.allowed || !acknowledged} onClick={downloadCandidate} className="btn-primary">{exporting ? 'Preparing download...' : 'Download candidate YAML'}</button>
        <button type="button" disabled={disabled} onClick={downloadOriginal} className="btn-secondary">Download original YAML</button>
      </div>
      {binding === 'pending' && verification && <p role="status" className="mt-3 text-xs text-slate-400">Matching the current YAML to the verification result...</p>}
      {error && <p role="alert" className="mt-3 text-sm text-rose-300">{error}</p>}
      {message && <p role="status" className="mt-3 text-sm text-emerald-200">{message}</p>}
      <p className="mt-4 text-xs text-slate-400">Downloads happen in your browser. ConfigShield does not deploy configurations or overwrite your uploaded file.</p>
    </section>
  );
}

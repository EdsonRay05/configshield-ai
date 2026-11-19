import { useEffect, useState } from 'react';
import { buildCandidate, explainDeployment, getAIStatus } from '../api.js';
import VerificationPanel from './VerificationPanel.jsx';
import DiffViewer from './DiffViewer.jsx';
import ReviewDownloadPanel from './ReviewDownloadPanel.jsx';
import { REQUIREMENT_LABELS } from '../review.js';

export default function AIExplanationPanel({ file, scan, requirements, onBusyChange, onProgressChange }) {
  const [checkId, setCheckId] = useState(scan.findings[0]?.check_id || '');
  const [status, setStatus] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState(null);
  const [approved, setApproved] = useState(false);
  const [candidateResult, setCandidateResult] = useState(null);
  const [action, setAction] = useState('explanation');
  const [verification, setVerification] = useState(null);
  useEffect(() => {
    let active = true;
    getAIStatus().then((value) => { if (active) setStatus(value); }).catch(() => {});
    return () => { active = false; };
  }, []);

  async function refreshStatus() {
    setError('');
    try { setStatus(await getAIStatus()); }
    catch (failure) { setError(failure.message); }
  }

  async function generate(provider) {
    if (busy || !checkId) return;
    setError(''); setResult(null); setApproved(false); setCandidateResult(null); setAction('explanation'); setBusy(true); onBusyChange(true);
    setVerification(null); onProgressChange?.({ explained: false, candidate: false, verification: false, reviewed: false, downloaded: false, verificationStatus: null });
    try {
      const response = await explainDeployment(file, checkId, provider, requirements);
      setResult(response);
      onProgressChange?.({ explained: true, mode: response.status });
      setStatus((current) => current ? { ...current, ...response.usage } : current);
    }
    catch (failure) { setError(failure.name === 'TimeoutError' ? 'Explanation timed out. No automatic retry was made.' : failure.message); }
    finally { setBusy(false); onBusyChange(false); }
  }

  async function approveCandidate() {
    if (!approved || busy || !result) return;
    setError(''); setAction('candidate'); setBusy(true); onBusyChange(true);
    try {
      const response = await buildCandidate(file, result, requirements, true, true);
      setCandidateResult(response); setVerification(null);
      onProgressChange?.({ candidate: response.status === 'candidate_created', verification: false, reviewed: false, downloaded: false, verificationStatus: null });
    }
    catch (failure) { setError(failure.name === 'TimeoutError' ? 'Candidate review timed out. No automatic retry was made.' : failure.message); }
    finally { setBusy(false); onBusyChange(false); }
  }

  const selected = scan.findings.find((finding) => finding.check_id === checkId);
  const report = candidateResult?.constraint_report || result?.constraint_report;
  return (
    <section id="ai" aria-labelledby="ai-title" className="panel">
      <p className="eyebrow">04 / Explain &amp; propose</p>
      <h2 id="ai-title" className="mt-2 text-xl font-semibold">Understand one finding at a time</h2>
      <p className="mt-3 text-sm leading-relaxed text-slate-300">Start with a mock example, or check whether the backend is configured for Gemini. Each live action makes at most one external generation request. It re-scans the file first.</p>
      <p className="mt-3 text-sm text-slate-400">Gemini receives selected security settings, reviewed guidance, and the requirements declared above. Names, images, commands, annotations, environment values, and raw YAML are omitted.</p>
      <label htmlFor="ai-finding" className="mt-5 block text-sm font-medium">Finding to explain</label>
      <select id="ai-finding" value={checkId} disabled={busy} onChange={(event) => { setCheckId(event.target.value); setResult(null); setError(''); setApproved(false); setCandidateResult(null); setVerification(null); onProgressChange?.({ explained: false, candidate: false, verification: false, reviewed: false, downloaded: false, verificationStatus: null }); }} className="mt-2 w-full rounded-lg border border-slate-600 bg-slate-950 p-3 text-sm">
        {scan.findings.map((finding) => <option key={finding.check_id} value={finding.check_id}>{finding.check_id}: {finding.description}</option>)}
      </select>
      <div className="mt-5 flex flex-wrap gap-3">
        <button type="button" disabled={busy} onClick={() => generate('mock')} className="rounded-lg bg-emerald-300 px-4 py-3 text-sm font-semibold text-slate-950 disabled:opacity-50">Generate mock example</button>
        <button type="button" disabled={busy} onClick={refreshStatus} className="rounded-lg border border-slate-500 px-4 py-3 text-sm disabled:opacity-50">Check AI configuration</button>
        <button type="button" disabled={busy || !status?.gemini_ready} onClick={() => generate('gemini')} className="rounded-lg border border-emerald-300 px-4 py-3 text-sm font-semibold text-emerald-300 disabled:opacity-50">Ask Gemini — one request</button>
      </div>
      {status && <p className="mt-4 text-sm text-slate-300">{status.message} Model: {status.model}. Process requests attempted: {status.process_requests_attempted}/{status.request_limit_per_process}.</p>}
      {busy && action !== 'verification' && <p role="status" className="mt-4 text-sm text-slate-300">{action === 'candidate' ? 'Re-checking the original finding and candidate requirements. No AI request is made...' : 'Re-checking the finding and preparing its explanation...'}</p>}
      {error && <p role="alert" className="mt-4 text-rose-300">{error}</p>}
      {!result && !busy && <p role="status" className="notice mt-4">Selected finding: {checkId}. Click Generate mock example or Ask Gemini — one request to prepare a suggestion for this finding. Selecting a finding clears the previous suggestion and approval. Step 5 appears after a suggestion is ready.</p>}
      {result && <div className="mt-6 rounded-lg border border-slate-600 p-5">
        <h4 className="font-semibold text-emerald-200">{result.status === 'mock' ? 'Mock demonstration — no AI call' : 'AI-generated suggestion — unverified'}</h4>
        <p className="mt-3 whitespace-pre-wrap text-sm leading-relaxed">{result.proposal.explanation}</p>
        <h5 className="mt-5 text-sm font-semibold">Unapproved candidate changes</h5>
        {result.proposal.candidates.length === 0 && <p className="mt-2 text-sm text-slate-300">No candidate change proposed. Review the explanation and limitations.</p>}
        <ul className="mt-3 space-y-3">{result.proposal.candidates.map((candidate) => <li key={candidate.path} className="rounded bg-slate-950 p-3 text-sm">
          <code className="break-all">{candidate.path}</code><p className="mt-2">Proposed value: <code>{JSON.stringify(candidate.value)}</code></p><p className="mt-2 text-slate-300">{candidate.rationale}</p>
        </li>)}</ul>
        <ul className="mt-4 list-disc space-y-2 pl-5 text-sm text-amber-200">{result.proposal.limitations.map((limitation, index) => <li key={index}>{limitation}</li>)}</ul>
        {report && <section aria-labelledby="constraint-title" className="mt-6 border-t border-slate-600 pt-5">
          <h5 id="constraint-title" className="font-semibold">Independent requirement checks</h5>
          <p role="status" className={`mt-3 text-sm ${report.status === 'conflict' ? 'text-rose-300' : 'text-amber-200'}`}>{report.status === 'conflict' ? 'Potential requirement conflict — candidate blocked' : 'Manual review required; runtime compatibility is unverified'}</p>
          <ul className="mt-4 space-y-3 text-sm">{report.results.map((item, index) => <li key={`${item.requirement}-${index}`}><span className="font-semibold">{REQUIREMENT_LABELS[item.requirement] || 'Additional review'}: {item.status === 'unverifiable' ? 'needs review' : item.status === 'conflict' ? 'potential conflict' : 'no detected conflict'}</span><p className="mt-1 text-slate-300">{item.message}</p></li>)}</ul>
        </section>}
        <section id="proposal" aria-labelledby="proposal-title" className="mt-6 border-t border-slate-600 pt-5">
          <p className="eyebrow">05 / Build candidate</p>
          <h3 id="proposal-title" className="mt-2 text-xl font-semibold">Next step: review and approve</h3>
          {report?.status === 'conflict' ? <div role="status" className="notice mt-4">
            <p className="font-semibold">Step 5 is blocked by a requirement conflict.</p>
            <p className="mt-2 text-sm">The proposed change conflicts with an application need declared in step 2. Keep that requirement if it is accurate. If it was entered incorrectly, correct it and generate a new suggestion. Changing requirements clears this suggestion.</p>
            <a href="#requirements" className="mt-4 inline-block text-emerald-200 underline">Return to step 2: review requirements</a>
            <p className="mt-2 text-sm">You can also select another finding in step 4. Verification becomes available after a separate candidate is built.</p>
          </div> : result.proposal.candidates.length === 0 ? <p className="notice mt-4">No changes were proposed, so there is no candidate to build or verify. Review the explanation, or select another finding in step 4.</p> : !candidateResult?.candidate_yaml ? <p className="mt-3 text-sm text-slate-300">Review the proposed fields and checks above, tick the approval checkbox below, then build the candidate. This uses no AI request. Step 6 appears after construction.</p> : <a href="#verification" className="mt-3 inline-block text-emerald-200 underline">Continue to step 6: verify candidate</a>}
        {result.proposal.candidates.length > 0 && report?.status !== 'conflict' && !candidateResult?.candidate_yaml && <div className="mt-6">
          <label className="flex items-start gap-3 text-sm"><input type="checkbox" checked={approved} disabled={busy} onChange={(event) => setApproved(event.target.checked)} className="mt-1" /><span>I reviewed these field changes and remaining uncertainties. I approve constructing a separate candidate for verification.</span></label>
          <button type="button" disabled={!approved || busy} onClick={approveCandidate} className="mt-4 rounded-lg bg-emerald-300 px-4 py-3 text-sm font-semibold text-slate-950 disabled:opacity-50">Approve and build candidate YAML</button>
        </div>}
        </section>
        {candidateResult && <div className="mt-6">
          <p role="status" className="font-semibold">{candidateResult.status === 'candidate_created' ? 'Candidate created — use the verification checks below' : candidateResult.status === 'blocked' ? 'Candidate blocked by requirement checks' : 'No candidate constructed; review the checks above'}</p>
          {candidateResult.candidate_yaml && <DiffViewer candidate={candidateResult} />}
          <details className="mt-4 text-xs text-slate-400"><summary>Candidate construction notes</summary><ul className="mt-3 list-disc space-y-2 pl-5">{candidateResult.warnings.map((warning) => <li key={warning}>{warning}</li>)}</ul></details>
          {candidateResult.candidate_yaml && <>
            <VerificationPanel file={file} explanation={result} requirements={requirements} candidate={candidateResult} disabled={busy} onBusyChange={(value) => { setAction('verification'); setBusy(value); onBusyChange(value); }} onResultChange={(value) => { setVerification(value); onProgressChange?.({ verification: !!value, verificationStatus: value?.status || null, reviewed: false, downloaded: false }); }} />
            <ReviewDownloadPanel file={file} candidate={candidateResult} verification={verification} provenance={result.status} disabled={busy} onDownloaded={() => onProgressChange?.({ downloaded: true })} onReviewed={(value) => onProgressChange?.({ reviewed: value })} />
          </>}
        </div>}
        <p className="mt-5 text-sm font-semibold">Referenced local documents</p>
        <ul className="mt-2 space-y-2 text-sm">{result.proposal.source_document_ids.map((id) => {
          const document = selected?.guidance?.documents.find((item) => item.document_id === id);
          return <li key={id}>{document ? <a href={document.source_url} target="_blank" rel="noopener noreferrer" className="text-emerald-200 underline">{document.title}</a> : id}</li>;
        })}</ul>
        <p className="mt-5 text-xs text-slate-400">Provider: {result.provider} · Model: {result.model} · External requests: {result.usage.external_requests_this_action} · Estimated input tokens: ~{result.usage.estimated_input_tokens} · Reported tokens: {result.usage.total_tokens ?? 'unavailable'}</p>
        <ul className="mt-4 list-disc space-y-2 pl-5 text-xs text-slate-400">{result.warnings.map((warning) => <li key={warning}>{warning}</li>)}</ul>
      </div>}
    </section>
  );
}

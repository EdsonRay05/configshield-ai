export default function FindingsList({ scan }) {
  return (
    <section aria-labelledby="findings-title" className="mt-6 border-t border-slate-700 pt-6">
      <h3 id="findings-title" className="text-xl font-semibold">Checkov findings</h3>
      <p role="status" className="mt-3 text-slate-300">
        {scan.status === 'incomplete' ? 'Scan incomplete' : 'Scan completed'} · Checkov {scan.scanner_version}
      </p>
      <p className="mt-2 text-sm text-slate-400">{scan.findings.length} failed · {scan.passed_checks.length} passed · {scan.skipped_checks.length} skipped · {scan.supported_checks.length} selected checks</p>
      {scan.findings.length === 0 && <p className="mt-4 text-slate-300">No failed findings were reported among the evaluated checks. Review completion status and warnings below.</p>}
      <ul className="mt-5 space-y-4">
        {scan.findings.map((finding) => <li key={finding.check_id} className="rounded-lg border border-amber-800/70 bg-amber-950/20 p-4">
          <p className="text-sm font-semibold text-amber-200">{finding.check_id}</p>
          <p className="mt-2 font-medium">{finding.description}</p>
          <p className="mt-2 break-all text-sm text-slate-300">Resource: {finding.resource}</p>
          {finding.line_range?.length > 0 && <p className="mt-1 text-sm text-slate-400">{finding.file}, lines {finding.line_range.join('–')}</p>}
          <details className="mt-5 border-t border-slate-700 pt-4">
            <summary className="text-sm font-semibold text-emerald-300">{finding.guidance?.status === 'available' ? `Retrieved documentation · ${finding.guidance.documents.length} sources` : finding.guidance?.status === 'unavailable' ? 'Local guidance unavailable' : 'No reviewed guidance mapped'}</summary>
            <p className="mt-2 text-sm text-slate-300">{finding.guidance?.message || 'No reviewed guidance was returned for this finding.'}</p>
            {finding.guidance?.status === 'available' ? <ul className="mt-4 space-y-4">
              {finding.guidance.documents.map((document) => <li key={document.document_id}>
                <a href={document.source_url} target="_blank" rel="noopener noreferrer" className="text-sm font-semibold text-emerald-200 underline underline-offset-4 hover:text-emerald-100">{document.title}</a>
                <p className="mt-2 text-sm leading-relaxed text-slate-200">{document.guidance}</p>
                <p className="mt-2 text-sm text-slate-400">Applies when: {document.applicable_condition}</p>
                <p className="mt-2 text-sm text-amber-200">Review note: {document.limitation}</p>
                <p className="mt-2 text-xs text-slate-400">Reviewed {document.reviewed_on} · {document.document_id} · Curated paraphrase</p>
              </li>)}
            </ul> : <p className="mt-2 text-sm text-amber-200">{finding.guidance?.status === 'unavailable' ? 'Local guidance unavailable.' : 'No reviewed guidance is mapped to this finding.'} Scanner results remain separate.</p>}
          </details>
        </li>)}
      </ul>
      {scan.skipped_checks.length > 0 && <p className="mt-4 text-amber-200">Skipped: {scan.skipped_checks.join(', ')}</p>}
      <ul className="mt-5 list-disc space-y-2 pl-5 text-sm text-amber-200">{scan.warnings.map((warning) => <li key={warning}>{warning}</li>)}</ul>
    </section>
  );
}

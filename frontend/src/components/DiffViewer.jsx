export default function DiffViewer({ candidate }) {
  return (
    <section id="candidate" aria-labelledby="comparison-title" className="mt-6">
      <div className="section-heading"><div><p className="eyebrow">Review the change</p><h3 id="comparison-title">Original &amp; candidate</h3></div><span className="pill">Original preserved</span></div>
      <p className="mt-3 text-sm text-slate-400">Compare both configurations before verification. Comments and formatting may change; the fields below describe semantic changes.</p>
      <h4 className="mt-5 font-semibold">What changed and why</h4>
      <ul aria-label="Changed configuration fields" className="mt-3 list-disc space-y-4 pl-5">{candidate.semantic_changed_paths.map((path) => {
        const detail = candidate.change_details?.find((item) => item.path === path);
        const field = path.split('/').at(-1);
        const location = path.includes('/containers/0/') ? 'Application container (containers[0])' : 'Pod settings (spec.template.spec)';
        return <li key={path} className="rounded-lg border border-emerald-900 bg-emerald-950/30 px-3 py-3 text-sm">
          <p className="font-semibold text-emerald-200">{field} · {location}</p>
          <p className="mt-2 break-all font-mono text-xs">Exact field: {path}</p>
          {detail ? <>
            <p className="mt-2">Original: <code>{detail.original_present ? detail.original_value : 'Not set (field absent)'}</code> → Candidate: <code>{detail.candidate_value}</code></p>
            <p className="mt-2 text-slate-300">Proposal rationale: {detail.rationale}</p>
          </> : <p className="mt-2 text-amber-200">Before/after details are unavailable. Restart the backend and rebuild this candidate to load them.</p>}
        </li>;
      })}</ul>
      <p className="mt-3 text-xs text-slate-400">These bullets describe constructed edits. The rationale is a proposal, not proof that the change is safe. Run independent verification next.</p>
      <div className="mt-5 grid gap-4 xl:grid-cols-2">
        <label className="code-label">Original YAML <span>Read only</span><textarea aria-label="Original YAML" readOnly value={candidate.original_yaml} spellCheck={false} className="code-editor" /></label>
        <label className="code-label">Candidate YAML <span>Awaiting your review</span><textarea aria-label="Candidate YAML" readOnly value={candidate.candidate_yaml} spellCheck={false} className="code-editor" /></label>
      </div>
    </section>
  );
}

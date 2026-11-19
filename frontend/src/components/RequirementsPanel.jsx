import { useEffect, useState } from 'react';

export const DEFAULT_REQUIREMENTS = {
  api_access: 'unknown',
  privileged_access: 'unknown',
  non_root_compatibility: 'unknown',
};

export default function RequirementsPanel({ value, onChange, disabled, hints }) {
  const [reviewed, setReviewed] = useState({});
  useEffect(() => { setReviewed({}); }, [hints]);
  function confirm(name, selected) {
    setReviewed((current) => ({ ...current, [name]: true }));
    onChange({ ...value, [name]: selected });
  }
  const controls = [
    { name: 'api_access', title: 'Kubernetes API access', options: [['unknown', 'Unknown'], ['required', 'Required'], ['not_required', 'Not required']] },
    { name: 'privileged_access', title: 'Privileged host/device access', options: [['unknown', 'Unknown'], ['required', 'Required'], ['not_required', 'Not required']] },
    { name: 'non_root_compatibility', title: 'Can this application run as non-root?', options: [['unknown', 'Unknown'], ['compatible', 'Yes, compatible'], ['incompatible', 'No, incompatible']] },
  ];
  return (
    <section id="requirements" aria-labelledby="requirements-title" className="panel">
      <p className="eyebrow">02 / Requirements</p>
      <h2 id="requirements-title" className="mt-2 text-xl font-semibold">What does your application need?</h2>
      <p className="mt-2 text-sm text-slate-300">Declare what this application needs. Leave uncertain answers as Unknown. Changing requirements clears any previous AI proposal and candidate.</p>
      <p className="mt-3 text-sm text-emerald-200">{hints?.length ? 'YAML evidence identified automatically. Suggested selections are drafts; accept or change them below. Until confirmed, they remain Unknown for AI and verification.' : 'Parse a Deployment to identify requirement clues automatically. No AI request is needed.'}</p>
      <div className="mt-4 grid grid-cols-1 gap-4 sm:grid-cols-3">
        {controls.map((control) => {
          const hint = hints?.find((item) => item.requirement === control.name);
          const suggestedLabel = control.options.find(([option]) => option === hint?.suggested_value)?.[1];
          const draft = !reviewed[control.name] && value[control.name] === 'unknown' && hint?.suggested_value !== 'unknown' && !!suggestedLabel;
          return <div key={control.name} className="min-w-0 rounded-lg border border-slate-700 p-3 text-sm">
          <label htmlFor={`requirement-${control.name}`}>{control.title}</label>
          <select id={`requirement-${control.name}`} value={draft ? 'unconfirmed' : value[control.name]} disabled={disabled} onChange={(event) => confirm(control.name, event.target.value)} className="mt-2 block w-full rounded-lg border border-slate-600 bg-slate-950 p-3 disabled:opacity-50">
            {draft && <option value="unconfirmed" disabled>Suggested: {suggestedLabel} (unconfirmed)</option>}
            {control.options.map(([option, label]) => <option key={option} value={option}>{label}</option>)}
          </select>
          {draft && <button type="button" disabled={disabled} onClick={() => confirm(control.name, hint.suggested_value)} className="btn-secondary mt-3 text-xs">Accept suggestion: {control.title}</button>}
          {hint && <div className="mt-3 text-xs leading-relaxed text-slate-300 [overflow-wrap:anywhere]">
            <p className="font-semibold">{reviewed[control.name] ? 'User reviewed — editable' : draft ? 'Automatic suggestion — needs your confirmation' : 'Automatic assessment: Unknown unless you declare otherwise'}</p>
            <ul className="mt-2 list-disc space-y-2 pl-4">{hint.evidence.map((evidence, index) => <li key={index}>{evidence}</li>)}</ul>
            <p className="mt-3 text-amber-200">{hint.limitation}</p>
          </div>}
        </div>;
        })}
      </div>
      <p className="mt-3 text-xs text-slate-400">Specific capability and syscall requirements need manual review. These declarations are not proof of runtime behavior.</p>
    </section>
  );
}

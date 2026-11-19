import { useEffect, useRef, useState } from 'react';
import { getDatasetCatalog, getDatasetCase, parseDeployment, scanDeployment } from '../api.js';
import FindingsList from './FindingsList.jsx';
import AIExplanationPanel from './AIExplanationPanel.jsx';
import RequirementsPanel, { DEFAULT_REQUIREMENTS } from './RequirementsPanel.jsx';
import { VERIFICATION_LABELS } from '../review.js';

const EMPTY_PROGRESS = { explained: false, candidate: false, verification: false, reviewed: false, downloaded: false, verificationStatus: null, mode: null };

export default function UploadPanel() {
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [scan, setScan] = useState(null);
  const [scanError, setScanError] = useState('');
  const [aiBusy, setAIBusy] = useState(false);
  const [requirements, setRequirements] = useState({ ...DEFAULT_REQUIREMENTS });
  const [requirementsRevision, setRequirementsRevision] = useState(0);
  const [requirementsTouched, setRequirementsTouched] = useState(false);
  const [progress, setProgress] = useState({ ...EMPTY_PROGRESS });
  const [datasets, setDatasets] = useState([]);
  const [datasetId, setDatasetId] = useState('');
  const [datasetSource, setDatasetSource] = useState(null);
  const [datasetError, setDatasetError] = useState('');
  const fileInput = useRef(null);
  const inputVersion = useRef(0);
  const [inspectionPhase, setInspectionPhase] = useState('idle');
  useEffect(() => {
    let active = true;
    getDatasetCatalog().then((entries) => { if (active) setDatasets(entries); })
      .catch((failure) => { if (active) setDatasetError(failure.message); });
    return () => { active = false; };
  }, []);

  async function selectFile(event) {
    setDatasetSource(null);
    setProgress({ ...EMPTY_PROGRESS }); setRequirementsTouched(false);
    setRequirements({ ...DEFAULT_REQUIREMENTS });
    setRequirementsRevision((revision) => revision + 1);
    setScan(null);
    setScanError('');
    const selectedFile = event.target.files?.[0] || null;
    setFile(selectedFile);
    setResult(null);
    setError('');
    await inspectFile(selectedFile);
  }

  async function loadDataset() {
    if (!datasetId || loading || scanning || aiBusy) return;
    // Discard the old review before fetching a replacement, not after it arrives.
    await selectFile({ target: { files: [] } });
    setLoading(true); setDatasetError('');
    try {
      const sample = await getDatasetCase(datasetId);
      const selectedFile = new File([sample.yaml], sample.filename, { type: 'application/yaml' });
      await selectFile({ target: { files: [selectedFile] } });
      setDatasetSource(datasets.find((entry) => entry.id === datasetId));
      if (fileInput.current) fileInput.current.value = '';
    } catch (failure) { setDatasetError(failure.message); }
    finally { setLoading(false); }
  }

  async function submit(event) {
    event.preventDefault();
    if (loading || scanning || aiBusy) return;
    await inspectFile(file);
  }

  async function inspectFile(selectedFile) {
    const version = ++inputVersion.current;
    setProgress({ ...EMPTY_PROGRESS });
    setScan(null);
    setScanError('');
    setResult(null);
    setError('');
    setInspectionPhase('idle');
    setLoading(false); setScanning(false);
    if (!selectedFile) { setLoading(false); setScanning(false); return; }
    if (!/\.ya?ml$/i.test(selectedFile.name)) return setError('Choose a .yaml or .yml file.');
    if (selectedFile.size > 256 * 1024) return setError('File exceeds the 256 KiB limit.');
    setLoading(true);
    setInspectionPhase('parsing');
    try {
      const parsed = await parseDeployment(selectedFile);
      if (version !== inputVersion.current) return;
      setResult(parsed);
      setLoading(false); setScanning(true); setInspectionPhase('scanning');
      try {
        const scanned = await scanDeployment(selectedFile);
        if (version !== inputVersion.current) return;
        setScan(scanned); setInspectionPhase(scanned.status === 'completed' ? 'ready' : 'incomplete');
      } catch (failure) {
        if (version !== inputVersion.current) return;
        setScanError(failure.name === 'TimeoutError' ? 'The scan request timed out. No successful scan is claimed.' : failure.message);
        setInspectionPhase('scan_error');
      }
    } catch (failure) {
      if (version !== inputVersion.current) return;
      setError(failure.name === 'TimeoutError' ? 'Upload timed out. Check that the backend is available.' : failure.message);
      setInspectionPhase('parse_error');
    } finally {
      if (version === inputVersion.current) { setLoading(false); setScanning(false); }
    }
  }

  async function handleScan() {
    if (!file || scanning) return;
    setScan(null);
    setProgress({ ...EMPTY_PROGRESS });
    setScanError('');
    setScanning(true);
    setInspectionPhase('scanning');
    try {
      const scanned = await scanDeployment(file);
      setScan(scanned); setInspectionPhase(scanned.status === 'completed' ? 'ready' : 'incomplete');
    } catch (failure) {
      setInspectionPhase('scan_error');
      setScanError(failure.name === 'TimeoutError'
        ? 'The scan request timed out. No successful scan is claimed.' : failure.message);
    } finally {
      setScanning(false);
    }
  }

  const stages = [
    ['Upload', !!result, true, 'upload'],
    ['Requirements', requirementsTouched || progress.explained, true, 'requirements'],
    ['Scan', !!scan, !!result, 'scan'],
    ['Explain', progress.explained, !!scan?.findings.length, 'ai'],
    ['Propose', progress.candidate, progress.explained, 'proposal'],
    ['Verify', progress.verification, progress.candidate, 'verification'],
    ['Review', progress.reviewed, progress.candidate, 'download'],
    ['Download', progress.downloaded, progress.candidate, 'download'],
  ];

  return (
    <div className="space-y-5">
      <nav aria-label="Review workflow" className="rounded-xl border border-slate-800 bg-slate-950/40 px-4 py-4">
        <ol className="grid grid-cols-4 gap-3 lg:grid-cols-8">{stages.map(([label, done, available, target], index) => <li key={label} className="text-[11px]">
          {available ? <a href={`#${target}`} className={`flex items-center gap-2 ${done ? 'text-emerald-200' : 'text-slate-300'}`}><span className={`flex h-6 w-6 shrink-0 items-center justify-center rounded-full border ${done ? 'border-emerald-700 bg-emerald-950' : 'border-slate-600'}`}>{done ? '✓' : index + 1}</span>{label}</a> : <span aria-disabled="true" className="flex items-center gap-2 text-slate-600"><span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full border border-slate-800">{index + 1}</span>{label}</span>}
        </li>)}</ol>
      </nav>
      <dl className="grid grid-cols-2 gap-3 lg:grid-cols-4" aria-label="Review summary">
        <div className="metric"><dt>Deployment</dt><dd>{result?.deployment.name || 'No file parsed'}</dd></div>
        <div className="metric"><dt>Scan results</dt><dd>{scan ? `${scan.findings.length} findings${scan.status === 'incomplete' ? ' · incomplete' : ''}` : 'Not scanned'}</dd></div>
        <div className="metric"><dt>Explanation</dt><dd>{progress.explained ? progress.mode === 'mock' ? 'Mock demonstration' : 'AI suggestion' : 'Not requested'}</dd></div>
        <div className="metric"><dt>Verification</dt><dd>{progress.verificationStatus ? VERIFICATION_LABELS[progress.verificationStatus] : 'Not run'}</dd></div>
      </dl>
    <section id="upload" aria-labelledby="upload-title" className="panel">
      <p className="eyebrow">01 / Upload</p>
      <h2 id="upload-title" className="mt-3 text-2xl font-semibold">Inspect a Deployment</h2>
      <p className="mt-3 text-sm text-slate-400">One apps/v1 Deployment · One Linux application container · Up to 256 KiB</p>
      <div className="mt-6 rounded-lg border border-slate-700 p-4">
        <label htmlFor="dataset-case" className="block text-sm font-medium">Try a dataset example</label>
        <p className="mt-2 text-xs text-slate-400">Testing examples, not AI training data. Loading a case clears the previous review, then automatically parses, scans, and retrieves guidance. Requirements remain Unknown until confirmed. No AI request runs automatically.</p>
        <select id="dataset-case" value={datasetId} disabled={loading || scanning || aiBusy} onChange={(event) => setDatasetId(event.target.value)} className="mt-3 w-full rounded-lg border border-slate-600 bg-slate-950 p-3 text-sm">
          <option value="">Select a case ({datasets.length} available)</option>
          {['External examples', 'Controlled synthetic cases'].map((group) => <optgroup key={group} label={group}>{datasets.filter((entry) => entry.group === group).map((entry) => <option key={entry.id} value={entry.id}>{entry.title}</option>)}</optgroup>)}
        </select>
        <button type="button" disabled={!datasetId || loading || scanning || aiBusy} onClick={loadDataset} className="btn-secondary mt-3">Load dataset case</button>
        {datasetError && <p role="alert" className="mt-3 text-sm text-amber-200">{datasetError}</p>}
      </div>
      {file && <div role="status" className="mt-4 text-sm text-emerald-200"><p>Selected input: {file.name}.</p><p className="mt-2">{({parsing:'1/3 · Parsing YAML and identifying requirement clues…',scanning:'2/3 · Scanning selected policies and retrieving local guidance…',ready:'3/3 · Inspection complete. Review requirements and findings below.',incomplete:'Inspection incomplete: review skipped checks below.',parse_error:'Parsing failed. Correct the file or select another YAML.',scan_error:'Scanning failed. Review the error and retry the scan.'})[inspectionPhase] || 'Select a supported YAML to start automatic inspection.'}</p>{datasetSource && <><p className="mt-2 text-slate-300">{datasetSource.description}</p>{datasetSource.source_url && <a href={datasetSource.source_url} target="_blank" rel="noopener noreferrer" className="underline">Dataset source: KustomizeGoat</a>}</>}</div>}
      <form onSubmit={submit} className="mt-6">
        <label htmlFor="yaml-file" className="mb-2 block text-sm font-medium">Kubernetes YAML file</label>
        <input ref={fileInput} id="yaml-file" type="file" accept=".yaml,.yml" disabled={loading || scanning || aiBusy} onChange={selectFile} aria-describedby="upload-help" className="block w-full rounded-lg border border-slate-600 p-3 text-sm file:mr-4 file:rounded file:border-0 file:bg-slate-700 file:px-3 file:py-2 file:text-slate-100" />
        <p id="upload-help" className="mt-2 text-sm text-slate-400">Multiple documents, extra containers, and YAML aliases are not supported.</p>
        <div className="mt-5 flex flex-wrap items-center gap-4"><button type="submit" disabled={loading || scanning || aiBusy || !file} className="btn-primary">{loading ? 'Parsing...' : 'Parse deployment'}</button><span className="text-xs text-slate-500">Parsing uses no AI. Scans use temporary copies removed afterward.</span></div>
      </form>
      {loading && <p role="status" className="mt-4 text-slate-300">Preparing the selected input...</p>}
      {error && <p role="alert" className="mt-4 text-rose-300">{error}</p>}
      {result && <div role="status" className="mt-6 border-t border-slate-700 pt-6">
        <h3 className="font-semibold text-emerald-300">Deployment parsed</h3>
        <dl className="mt-4 grid gap-4 sm:grid-cols-2">
          {Object.entries({ Name: result.deployment.name, Namespace: result.deployment.namespace, Replicas: result.deployment.replicas, Container: result.deployment.container_name, Image: result.deployment.image, OS: result.deployment.os_assumed ? 'Linux (assumed)' : 'Linux (declared)' }).map(([label, value]) => <div key={label}><dt className="text-sm text-slate-400">{label}</dt><dd className="mt-1 break-all">{value}</dd></div>)}
        </dl>
        <ul className="mt-5 list-disc space-y-2 pl-5 text-xs text-amber-200">{result.warnings.map((warning, index) => <li key={warning}>{index === 0 ? 'Parsing checks supported structure only. Security scans and candidate verification are reported in their own steps.' : warning}</li>)}</ul>
      </div>}
    </section>
      <RequirementsPanel value={requirements} hints={result?.requirement_hints} disabled={loading || scanning || aiBusy} onChange={(value) => { setRequirements(value); setRequirementsTouched(true); setProgress({ ...EMPTY_PROGRESS }); setRequirementsRevision((revision) => revision + 1); }} />
      {result && <section id="scan" aria-label="Security scan" className="panel">
        <div className="section-heading"><div><p className="eyebrow">03 / Scan</p><h2>Inspect the selected security policies</h2></div><button type="button" onClick={handleScan} disabled={scanning || loading || aiBusy} className="btn-primary">{scanning ? 'Scanning...' : scan ? 'Scan again' : 'Scan with Checkov'}</button></div>
        {!scan && !scanning && <p className="mt-4 text-sm text-slate-400">Run Checkov to collect findings from seven selected policies. Scanning works without AI.</p>}
        {scanning && <p role="status" className="mt-4 text-sm text-slate-300">Running seven selected Kubernetes checks. This can take up to 60 seconds.</p>}
        {scanError && <p role="alert" className="mt-4 text-rose-300">{scanError}</p>}
        {scan && <FindingsList scan={scan} />}
      </section>}
      {scan && scan.findings.length > 0 && <AIExplanationPanel key={requirementsRevision} file={file} scan={scan} requirements={requirements} onBusyChange={setAIBusy} onProgressChange={(patch) => setProgress((current) => ({ ...current, ...patch }))} />}
      {scan && scan.findings.length === 0 && <p className="notice">{scan.status === 'completed' ? 'No failed findings were reported by the selected scan. No remediation candidate is needed for these checks.' : 'The scan is incomplete. No failed findings are listed, but skipped checks have not passed.'} This does not prove complete security or runtime compatibility.</p>}
    </div>
  );
}

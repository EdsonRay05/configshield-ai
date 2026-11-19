import { webcrypto } from 'node:crypto';
import { TextEncoder } from 'node:util';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import * as review from './review.js';
import ReviewDownloadPanel from './components/ReviewDownloadPanel.jsx';
import { downloadDecision, downloadName, sha256, startDownload, verificationMatches } from './review.js';

const original = '\uFEFFapiVersion: apps/v1\r\n# original preserved\r\n';
const candidate = {status:'candidate_created', original_yaml:original, candidate_yaml:'apiVersion: apps/v1\n# candidate\n', semantic_changed_paths:[]};
const checkNames = ['original_binding','original_structure','candidate_structure','authorized_changes','schema_validation','original_security_scan','candidate_security_scan','finding_comparison','targeted_repair','requirement_checks'];
const policies = ['CKV_K8S_16','CKV_K8S_20','CKV_K8S_23','CKV_K8S_28','CKV_K8S_31','CKV_K8S_37','CKV_K8S_38'];

async function proof(status = 'verified_supported_checks') {
  const scan = {status:'completed', scanner_version:'3.4.5', skipped_checks:[], findings:[], supported_checks:policies};
  return {status, original_sha256:await sha256(original), candidate_sha256:await sha256(candidate.candidate_yaml),
    checks:checkNames.map((name)=>({name,status:'passed'})), schema_validation:{status:'passed'},
    original_scan:{...scan}, candidate_scan:{...scan}, targeted_finding_resolved:true,
    new_findings:[], remaining_findings:[], unexpected_changed_paths:[],
    constraint_report:{status:'manual_review', results:[{requirement:'runtime_compatibility',status:'unverifiable'}]}};
}

beforeEach(() => {
  vi.stubGlobal('crypto', webcrypto);
  vi.stubGlobal('TextEncoder', TextEncoder);
  Object.defineProperty(URL, 'createObjectURL', {configurable:true, value:vi.fn(()=>'blob:configshield-test')});
  Object.defineProperty(URL, 'revokeObjectURL', {configurable:true, value:vi.fn()});
  vi.spyOn(HTMLAnchorElement.prototype,'click').mockImplementation(()=>{});
});
afterEach(() => { cleanup(); vi.useRealTimers(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

describe('verification-bound download policy', () => {
  it('permits a reviewed candidate only with matching complete checks', async () => {
    const verification = await proof();
    expect(await verificationMatches(candidate, verification)).toBe(true);
    expect(downloadDecision(candidate, verification, true).allowed).toBe(true);
    expect(downloadDecision(candidate, verification, false).allowed).toBe(false);
    expect(downloadDecision(candidate, null, true).allowed).toBe(false);
  });

  it.each(['failed_validation','new_security_findings','requirement_conflict','incomplete'])('blocks %s even with matching bytes', async (status) => {
    expect(downloadDecision(candidate, await proof(status), true).allowed).toBe(false);
  });

  it.each(['missing_check','skipped_check','failed_check','duplicate_check','schema_failure','target_unresolved','new_finding','unexpected_path','requirement_conflict','missing_scan'])('blocks inconsistent evidence: %s', async (fault) => {
    const verification = await proof();
    if (fault==='missing_check') verification.checks.shift();
    if (fault==='skipped_check') verification.checks[0].status='unavailable';
    if (fault==='failed_check') verification.checks[0].status='failed';
    if (fault==='duplicate_check') verification.checks.push({...verification.checks[0]});
    if (fault==='schema_failure') verification.schema_validation.status='failed';
    if (fault==='target_unresolved') verification.targeted_finding_resolved=false;
    if (fault==='new_finding') verification.new_findings=[{check_id:'CKV_K8S_20'}];
    if (fault==='unexpected_path') verification.unexpected_changed_paths=['/spec/replicas'];
    if (fault==='requirement_conflict') verification.constraint_report.results=[{status:'conflict'}];
    if (fault==='missing_scan') verification.candidate_scan=null;
    expect(downloadDecision(candidate, verification, true).allowed).toBe(false);
  });

  it('allows a manual-review draft without pretending remaining findings passed', async () => {
    const verification = await proof('manual_review');
    verification.remaining_findings=[{check_id:'CKV_K8S_20'}];
    verification.candidate_scan.findings=verification.remaining_findings;
    expect(downloadDecision(candidate,verification,true).allowed).toBe(true);
  });

  it('detects modified original and candidate bytes', async () => {
    const verification = await proof();
    expect(await verificationMatches({...candidate,original_yaml:original.replaceAll('\r\n','\n')},verification)).toBe(false);
    expect(await verificationMatches({...candidate,candidate_yaml:candidate.candidate_yaml+'\n'},verification)).toBe(false);
  });

  it.each(['../../CON.yaml','C:\\private\\deployment.yaml','../../a weird name.yml'])('generates a local safe download filename for %s', (name) => {
    const result = downloadName(name);
    expect(result).toMatch(/^[a-zA-Z0-9._-]+\.candidate-review\.yaml$/);
    expect(result).not.toMatch(/[\\/]/);
    expect(result).not.toMatch(/^CON\./i);
  });

  it('removes its temporary link and releases the object URL', () => {
    vi.useFakeTimers();
    const blob = new Blob(['exact bytes']);
    startDownload(blob,'deployment.candidate-review.yaml');
    expect(URL.createObjectURL).toHaveBeenCalledWith(blob);
    expect(document.querySelector('a[download]')).toBeNull();
    vi.advanceTimersByTime(1000);
    expect(URL.revokeObjectURL).toHaveBeenCalledWith('blob:configshield-test');
  });
});

describe('review and download controls', () => {
  it('requires explicit review and exports exactly the candidate text', async () => {
    const verification = await proof();
    const onDownloaded = vi.fn();
    const file = new File([original],'example.yaml');
    render(<ReviewDownloadPanel file={file} candidate={candidate} verification={verification} onDownloaded={onDownloaded}/>);
    const checkbox = screen.getByRole('checkbox');
    await waitFor(()=>expect(checkbox.disabled).toBe(false));
    const button = screen.getByRole('button',{name:'Download candidate YAML'});
    expect(button.disabled).toBe(true);
    fireEvent.click(checkbox);
    fireEvent.click(button);
    await waitFor(()=>expect(onDownloaded).toHaveBeenCalledOnce());
    const blob = URL.createObjectURL.mock.calls[0][0];
    const text = await new Promise((resolve,reject)=>{ const reader=new FileReader(); reader.onload=()=>resolve(reader.result); reader.onerror=reject; reader.readAsText(blob); });
    expect(text).toBe(candidate.candidate_yaml);
    expect(screen.getByText(/Candidate download started/)).toBeTruthy();
  });

  it('keeps the original downloadable while candidate verification is unavailable', async () => {
    const file = new File([original],'example.yaml');
    render(<ReviewDownloadPanel file={file} candidate={candidate} verification={null}/>);
    expect(screen.getByRole('button',{name:'Download candidate YAML'}).disabled).toBe(true);
    fireEvent.click(screen.getByRole('button',{name:'Download original YAML'}));
    expect(URL.createObjectURL).toHaveBeenCalledWith(file);
  });

  it('shows remaining findings before allowing a manual-review download', async () => {
    const verification = await proof('manual_review');
    verification.remaining_findings=[{check_id:'CKV_K8S_20'}];
    verification.candidate_scan.findings=verification.remaining_findings;
    render(<ReviewDownloadPanel file={new File([original],'example.yaml')} candidate={candidate} verification={verification}/>);
    expect(screen.getByText(/still has 1 selected security finding/)).toBeTruthy();
    await waitFor(()=>expect(screen.getByRole('checkbox').disabled).toBe(false));
    expect(screen.getByRole('button',{name:'Download candidate YAML'}).disabled).toBe(true);
  });

  it('clears approval when verification is replaced or rerun', async () => {
    const verification = await proof();
    const props = {file:new File([original],'example.yaml'),candidate,verification};
    const {rerender} = render(<ReviewDownloadPanel {...props}/>);
    await waitFor(()=>expect(screen.getByRole('checkbox').disabled).toBe(false));
    fireEvent.click(screen.getByRole('checkbox'));
    expect(screen.getByRole('checkbox').checked).toBe(true);
    rerender(<ReviewDownloadPanel {...props} verification={null}/>);
    expect(screen.getByRole('checkbox').checked).toBe(false);
    expect(screen.getByRole('button',{name:'Download candidate YAML'}).disabled).toBe(true);
  });

  it('rejects stale verification instead of enabling a download', async () => {
    const verification = await proof();
    verification.candidate_sha256='0'.repeat(64);
    render(<ReviewDownloadPanel file={new File([original],'example.yaml')} candidate={candidate} verification={verification}/>);
    await waitFor(()=>expect(screen.queryByText(/Matching the current YAML/)).toBeNull());
    expect(screen.getByRole('checkbox').disabled).toBe(true);
    expect(screen.getByRole('button',{name:'Download candidate YAML'}).disabled).toBe(true);
  });

  it('cancels an in-flight export when the review is discarded', async () => {
    const verification = await proof();
    const {unmount} = render(<ReviewDownloadPanel file={new File([original],'example.yaml')} candidate={candidate} verification={verification}/>);
    await waitFor(()=>expect(screen.getByRole('checkbox').disabled).toBe(false));
    let complete;
    const pending = new Promise((resolve)=>{complete=resolve;});
    vi.spyOn(review,'verificationMatches').mockImplementationOnce(()=>pending);
    fireEvent.click(screen.getByRole('checkbox'));
    fireEvent.click(screen.getByRole('button',{name:'Download candidate YAML'}));
    unmount();
    await act(async()=>{complete(true);await pending;});
    expect(URL.createObjectURL).not.toHaveBeenCalled();
  });
});

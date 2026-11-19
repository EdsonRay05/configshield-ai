import { webcrypto } from 'node:crypto';
import { TextEncoder } from 'node:util';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import App from './App.jsx';
import * as api from './api.js';
import { sha256 } from './review.js';

vi.mock('./api.js', () => ({checkHealth:vi.fn(),parseDeployment:vi.fn(),scanDeployment:vi.fn(),
  explainDeployment:vi.fn(),getAIStatus:vi.fn(),buildCandidate:vi.fn(),verifyCandidate:vi.fn(),getDatasetCatalog:vi.fn(),getDatasetCase:vi.fn()}));

const originalYaml = 'apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: demo\nspec:\n  template:\n    spec:\n      containers:\n        - name: web\n          securityContext:\n            privileged: true\n';
const candidateYaml = originalYaml.replace('privileged: true','privileged: false');
const policies = ['CKV_K8S_16','CKV_K8S_20','CKV_K8S_23','CKV_K8S_28','CKV_K8S_31','CKV_K8S_37','CKV_K8S_38'];
const path = '/spec/template/spec/containers/0/securityContext/privileged';
const requirements = {api_access:'not_required',privileged_access:'not_required',non_root_compatibility:'compatible'};
let explanation;
let candidate;
let scan;

beforeEach(async () => {
  vi.clearAllMocks();
  vi.stubGlobal('crypto',webcrypto); vi.stubGlobal('TextEncoder',TextEncoder);
  Object.defineProperty(URL,'createObjectURL',{configurable:true,value:vi.fn(()=>'blob:workflow-test')});
  Object.defineProperty(URL,'revokeObjectURL',{configurable:true,value:vi.fn()});
  vi.spyOn(HTMLAnchorElement.prototype,'click').mockImplementation(()=>{});
  const deployment = {name:'demo',namespace:'default',replicas:1,container_name:'web',image:'example:demo',os:'linux',os_assumed:false};
  const finding = {check_id:'CKV_K8S_16',description:'Privileged container',resource:'Deployment.default.demo',line_range:[1,12],file:'deployment.yaml',
    guidance:{status:'available',message:'Reviewed local guidance',documents:[{document_id:'pss-privileged',title:'Pod Security Standards',source_url:'https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline',guidance:'Controlled test guidance',applicable_condition:'A privileged setting is reported',limitation:'Runtime is unverified',reviewed_on:'2026-11-17'}]}};
  scan = {status:'completed',scanner_version:'3.4.5',deployment,supported_checks:policies,passed_checks:policies.slice(1),skipped_checks:[],findings:[finding],warnings:['Selected policies only']};
  const report = {status:'manual_review',results:[{requirement:'privileged_access',status:'preserved',message:'No detected conflict'},{requirement:'runtime_compatibility',status:'unverifiable',message:'Runtime remains unverified'}]};
  explanation = {status:'mock',provider:'mock',model:'deterministic-mock',requirements,original_sha256:await sha256(originalYaml),constraint_report:report,
    proposal:{check_id:'CKV_K8S_16',explanation:'Mock finding explanation',candidates:[{path,value:false,rationale:'Controlled candidate'}],source_document_ids:['pss-privileged'],limitations:['Mock demonstration only']},
    usage:{external_requests_this_action:0,estimated_input_tokens:100,total_tokens:null},warnings:['No external AI call was made']};
  candidate = {status:'candidate_created',original_yaml:originalYaml,candidate_yaml:candidateYaml,original_sha256:explanation.original_sha256,
    change_details:[{path,original_present:true,original_value:'true',candidate_value:'false',rationale:'Controlled candidate'}],
    constraint_report:report,semantic_changed_paths:[path],warnings:['Review before use']};
  const checkNames = ['original_binding','original_structure','candidate_structure','authorized_changes','schema_validation','original_security_scan','candidate_security_scan','finding_comparison','targeted_repair','requirement_checks'];
  const verification = {status:'verified_supported_checks',original_sha256:explanation.original_sha256,candidate_sha256:await sha256(candidateYaml),
    checks:[...checkNames.map((name)=>({name,status:'passed',message:'Controlled check result'})),{name:'runtime_compatibility',status:'manual_review',message:'Runtime untested'}],
    schema_validation:{status:'passed',kubernetes_version:'1.35.0',validator_version:'v0.8.0'},original_scan:scan,
    candidate_scan:{...scan,findings:[],passed_checks:policies},resolved_findings:[finding],new_findings:[],remaining_findings:[],
    unexpected_changed_paths:[],targeted_finding_resolved:true,constraint_report:report,warnings:['Runtime is unverified']};
  api.parseDeployment.mockResolvedValue({status:'parsed',deployment,warnings:['Structure only']});
  api.scanDeployment.mockResolvedValue(scan);
  api.explainDeployment.mockResolvedValue(explanation);
  api.buildCandidate.mockResolvedValue(candidate);
  api.verifyCandidate.mockResolvedValue(verification);
  api.getAIStatus.mockResolvedValue({gemini_ready:false,message:'Mock mode',model:'gemini-3.1-flash-lite',process_requests_attempted:0,request_limit_per_process:5});
  api.checkHealth.mockResolvedValue({status:'ok',service:'configshield-ai'});
  api.getDatasetCatalog.mockResolvedValue([{id:'kustomizegoat-base',title:'KustomizeGoat / insecure base Deployment',group:'External examples',source_url:'https://github.com/bridgecrewio/kustomizegoat',description:'Original external example'}]);
  api.getDatasetCase.mockResolvedValue({id:'kustomizegoat-base',filename:'kustomizegoat-base.yaml',yaml:originalYaml});
});
afterEach(()=>{cleanup();vi.unstubAllGlobals();vi.restoreAllMocks();});

it('loads a dataset through the normal parse flow and clears previous review state', async () => {
  await buildAndVerify();
  fireEvent.change(screen.getByLabelText('Try a dataset example'),{target:{value:'kustomizegoat-base'}});
  fireEvent.click(screen.getByRole('button',{name:'Load dataset case'}));
  await screen.findByText(/Selected input: kustomizegoat-base.yaml/);
  expect(screen.queryByRole('textbox',{name:'Candidate YAML'})).toBeNull();
  expect(screen.getByLabelText('Privileged host/device access').value).toBe('unknown');
  await screen.findByRole('link',{name:'Dataset source: KustomizeGoat'});
  expect(api.parseDeployment).toHaveBeenCalledTimes(2);
  expect(api.explainDeployment).toHaveBeenCalledOnce();
  expect(screen.getByRole('link',{name:'Dataset source: KustomizeGoat'}).getAttribute('href')).toBe('https://github.com/bridgecrewio/kustomizegoat');
  const file=api.parseDeployment.mock.calls[1][0];
  expect(file.name).toBe('kustomizegoat-base.yaml');
  const text=await new Promise((resolve)=>{const reader=new FileReader();reader.onload=()=>resolve(reader.result);reader.readAsText(file);});
  expect(text).toBe(originalYaml);
});

it('keeps upload available if the dataset catalog is unavailable', async () => {
  api.getDatasetCatalog.mockRejectedValue(new Error('Dataset catalog unavailable'));
  render(<App/>);
  await screen.findByText('Dataset catalog unavailable');
  expect(screen.getByLabelText('Kubernetes YAML file').disabled).toBe(false);
  expect(api.explainDeployment).not.toHaveBeenCalled();
});

it('discards an old candidate before a replacement dataset fetch finishes', async () => {
  await buildAndVerify();
  let rejectReplacement;
  api.getDatasetCase.mockImplementationOnce(()=>new Promise((resolve,reject)=>{rejectReplacement=reject;}));
  fireEvent.change(screen.getByLabelText('Try a dataset example'),{target:{value:'kustomizegoat-base'}});
  fireEvent.click(screen.getByRole('button',{name:'Load dataset case'}));
  await waitFor(()=>expect(screen.queryByRole('textbox',{name:'Candidate YAML'})).toBeNull());
  expect(screen.queryByRole('button',{name:'Generate mock example'})).toBeNull();
  await waitFor(()=>expect(api.getDatasetCase).toHaveBeenCalledOnce());
  rejectReplacement(new Error('Replacement unavailable'));
  await screen.findByText('Replacement unavailable');
  expect(screen.getByRole('button',{name:'Parse deployment'}).disabled).toBe(true);
});

it('automatically displays a non-root draft but sends Unknown until the user accepts it', async () => {
  const parsed = await api.parseDeployment();
  api.parseDeployment.mockClear();
  api.parseDeployment.mockResolvedValue({...parsed,requirement_hints:[{
    requirement:'non_root_compatibility',suggested_value:'compatible',needs_confirmation:true,
    evidence:['Container runAsNonRoot is true.'],limitation:'Runtime compatibility is untested.',
  }]});
  const file = await uploadAndScan();
  expect(screen.getByLabelText('Can this application run as non-root?').value).toBe('unconfirmed');
  expect(screen.getByText('Container runAsNonRoot is true.')).toBeTruthy();
  expect(api.explainDeployment).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button',{name:'Generate mock example'}));
  await screen.findByText('Mock finding explanation');
  expect(api.explainDeployment).toHaveBeenLastCalledWith(file,'CKV_K8S_16','mock',{
    api_access:'unknown',privileged_access:'unknown',non_root_compatibility:'unknown',
  });
  fireEvent.click(screen.getByRole('button',{name:'Accept suggestion: Can this application run as non-root?'}));
  expect(screen.getByLabelText('Can this application run as non-root?').value).toBe('compatible');
  expect(screen.queryByText('Mock finding explanation')).toBeNull();
  fireEvent.click(screen.getByRole('button',{name:'Generate mock example'}));
  await screen.findByText('Mock finding explanation');
  expect(api.explainDeployment).toHaveBeenLastCalledWith(file,'CKV_K8S_16','mock',{
    api_access:'unknown',privileged_access:'unknown',non_root_compatibility:'compatible',
  });
  fireEvent.change(screen.getByLabelText('Can this application run as non-root?'),{target:{value:'unknown'}});
  expect(screen.getByLabelText('Can this application run as non-root?').value).toBe('unknown');
  expect(screen.queryByRole('button',{name:'Accept suggestion: Can this application run as non-root?'})).toBeNull();
});

async function uploadAndScan() {
  render(<App/>);
  const file = new File([originalYaml],'deployment.yaml',{type:'application/yaml'});
  fireEvent.change(screen.getByLabelText('Kubernetes YAML file'),{target:{files:[file]}});
  await screen.findByRole('heading',{name:'Checkov findings'});
  return file;
}

function declareRequirements() {
  fireEvent.change(screen.getByLabelText('Kubernetes API access'),{target:{value:'not_required'}});
  fireEvent.change(screen.getByLabelText('Privileged host/device access'),{target:{value:'not_required'}});
  fireEvent.change(screen.getByLabelText('Can this application run as non-root?'),{target:{value:'compatible'}});
}

async function buildAndVerify() {
  const file = await uploadAndScan(); declareRequirements();
  fireEvent.click(screen.getByRole('button',{name:'Generate mock example'}));
  await screen.findByText('Mock finding explanation');
  fireEvent.click(screen.getByLabelText(/I reviewed these field changes/));
  fireEvent.click(screen.getByRole('button',{name:'Approve and build candidate YAML'}));
  await screen.findByRole('textbox',{name:'Candidate YAML'});
  fireEvent.click(screen.getByRole('button',{name:'Verify candidate'}));
  await waitFor(()=>expect(screen.getByLabelText(/I reviewed the changes and verification results/).disabled).toBe(false));
  return file;
}

it('shows why step 5 is blocked and links back to requirements without building a candidate', async () => {
  explanation.constraint_report = {status:'conflict',results:[{requirement:'privileged_access',status:'conflict',message:'Privileged access is required'}]};
  await uploadAndScan();
  fireEvent.click(screen.getByRole('button',{name:'Generate mock example'}));
  await screen.findByText('Step 5 is blocked by a requirement conflict.');
  expect(screen.getByRole('heading',{name:'Next step: review and approve'})).toBeTruthy();
  expect(screen.getByRole('link',{name:'Return to step 2: review requirements'}).getAttribute('href')).toBe('#requirements');
  expect(screen.getByRole('link',{name:/Propose/}).getAttribute('href')).toBe('#proposal');
  expect(screen.queryByRole('button',{name:'Approve and build candidate YAML'})).toBeNull();
  expect(api.buildCandidate).not.toHaveBeenCalled();
  fireEvent.change(screen.getByLabelText('Privileged host/device access'),{target:{value:'not_required'}});
  expect(screen.queryByText('Step 5 is blocked by a requirement conflict.')).toBeNull();
});

it('explains that switching findings needs a new explicit generation action', async () => {
  scan.findings.push({...scan.findings[0],check_id:'CKV_K8S_20',description:'Privilege escalation'});
  await uploadAndScan();
  fireEvent.click(screen.getByRole('button',{name:'Generate mock example'}));
  await screen.findByText('Mock finding explanation');
  fireEvent.change(screen.getByLabelText('Finding to explain'),{target:{value:'CKV_K8S_20'}});
  expect(screen.getByText(/Selected finding: CKV_K8S_20/)).toBeTruthy();
  expect(screen.queryByRole('button',{name:'Approve and build candidate YAML'})).toBeNull();
  expect(api.explainDeployment).toHaveBeenCalledOnce();
  expect(api.buildCandidate).not.toHaveBeenCalled();
});

it('starts empty and does not request AI during upload or scanning', async () => {
  await uploadAndScan();
  expect(api.parseDeployment).toHaveBeenCalledOnce();
  expect(api.scanDeployment).toHaveBeenCalledOnce();
  expect(api.explainDeployment).not.toHaveBeenCalled();
  expect(api.getAIStatus).toHaveBeenCalled();
  expect(screen.getByRole('button',{name:'Ask Gemini — one request'}).disabled).toBe(true);
});

it('automatically shows Gemini readiness without generating a suggestion', async () => {
  api.getAIStatus.mockResolvedValue({gemini_ready:true,message:'Live configured'});
  render(<App/>);
  await screen.findByText('Gemini ready — backend connected');
  expect(api.explainDeployment).not.toHaveBeenCalled();
});

it('shows unavailable AI status when the backend cannot be reached', async () => {
  api.getAIStatus.mockRejectedValue(new Error('offline'));
  render(<App/>);
  await screen.findByText('AI status unavailable — backend unreachable');
  expect(api.explainDeployment).not.toHaveBeenCalled();
});

it('completes the explicit review workflow with separate build and download approvals', async () => {
  const file = await buildAndVerify();
  expect(api.explainDeployment).toHaveBeenCalledWith(file,'CKV_K8S_16','mock',requirements);
  expect(api.buildCandidate).toHaveBeenCalledWith(file,explanation,requirements,true,true);
  expect(api.verifyCandidate).toHaveBeenCalledOnce();
  expect(screen.getByRole('textbox',{name:'Original YAML'}).value).toBe(originalYaml);
  expect(screen.getByRole('textbox',{name:'Candidate YAML'}).value).toBe(candidateYaml);
  expect(screen.getByRole('heading',{name:'What changed and why'})).toBeTruthy();
  expect(screen.getByText(/privileged · Application container/)).toBeTruthy();
  expect(screen.getByText('Proposal rationale: Controlled candidate')).toBeTruthy();
  expect(screen.getByText('Original:',{exact:false}).textContent).toContain('true → Candidate: false');
  expect(screen.getByText(/Mock-generated candidate/)).toBeTruthy();
  const download = screen.getByRole('button',{name:'Download candidate YAML'});
  expect(download.disabled).toBe(true);
  fireEvent.click(screen.getByLabelText(/I reviewed the changes and verification results/));
  fireEvent.click(download);
  await screen.findByText(/Candidate download started/);
  expect(URL.createObjectURL).toHaveBeenCalledOnce();
});

it('invalidates proposals, candidates, verification, and download approval when requirements change', async () => {
  await buildAndVerify();
  fireEvent.click(screen.getByLabelText(/I reviewed the changes and verification results/));
  fireEvent.change(screen.getByLabelText('Privileged host/device access'),{target:{value:'required'}});
  expect(screen.queryByRole('textbox',{name:'Candidate YAML'})).toBeNull();
  expect(screen.queryByRole('button',{name:'Download candidate YAML'})).toBeNull();
  expect(screen.queryByText('Mock finding explanation')).toBeNull();
  expect(api.explainDeployment).toHaveBeenCalledOnce();
});

it('resets requirements and all downstream results when a new file is selected', async () => {
  await buildAndVerify();
  fireEvent.change(screen.getByLabelText('Kubernetes YAML file'),{target:{files:[new File(['new file'],'new.yaml')]}});
  expect(screen.queryByRole('textbox',{name:'Candidate YAML'})).toBeNull();
  expect(screen.queryByRole('heading',{name:'Checkov findings'})).toBeNull();
  expect(screen.getByLabelText('Kubernetes API access').value).toBe('unknown');
  expect(api.parseDeployment).toHaveBeenCalledTimes(2);
  expect(api.verifyCandidate).toHaveBeenCalledOnce();
});

it('shows a quota error without retrying or using a fallback provider', async () => {
  api.getAIStatus.mockResolvedValue({gemini_ready:true,message:'Live configured',model:'gemini-3.1-flash-lite',process_requests_attempted:0,request_limit_per_process:5});
  api.explainDeployment.mockRejectedValue(new Error('Gemini free quota reached. No retry was made.'));
  await uploadAndScan();
  fireEvent.click(screen.getByRole('button',{name:'Check AI configuration'}));
  await waitFor(()=>expect(screen.getByRole('button',{name:'Ask Gemini — one request'}).disabled).toBe(false));
  fireEvent.click(screen.getByRole('button',{name:'Ask Gemini — one request'}));
  expect(await screen.findByRole('alert')).toHaveProperty('textContent','Gemini free quota reached. No retry was made.');
  expect(api.explainDeployment).toHaveBeenCalledOnce();
  expect(api.explainDeployment.mock.calls[0][2]).toBe('gemini');
  expect(screen.getByRole('button',{name:'Generate mock example'}).disabled).toBe(false);
});

it('keeps upload controls disabled while an explicit scan is running', async () => {
  let finish;
  api.scanDeployment.mockImplementation(()=>new Promise((resolve)=>{finish=resolve;}));
  render(<App/>);
  fireEvent.change(screen.getByLabelText('Kubernetes YAML file'),{target:{files:[new File([originalYaml],'deployment.yaml')]}});
  await waitFor(()=>expect(api.scanDeployment).toHaveBeenCalledOnce());
  expect(screen.getByLabelText('Kubernetes YAML file').disabled).toBe(true);
  expect(screen.getByLabelText('Kubernetes API access').disabled).toBe(true);
  finish(scan);
  await screen.findByRole('heading',{name:'Checkov findings'});
  expect(screen.getByLabelText('Kubernetes YAML file').disabled).toBe(false);
});

it('shows scan errors separately and does not expose explanation or download controls', async () => {
  api.scanDeployment.mockRejectedValue(new Error('Checkov is unavailable.'));
  render(<App/>);
  fireEvent.change(screen.getByLabelText('Kubernetes YAML file'),{target:{files:[new File([originalYaml],'deployment.yaml')]}});
  expect(await screen.findByRole('alert')).toHaveProperty('textContent','Checkov is unavailable.');
  expect(screen.queryByRole('button',{name:'Generate mock example'})).toBeNull();
  expect(screen.queryByRole('button',{name:'Download candidate YAML'})).toBeNull();
});

it('does not invent a remediation when no selected findings failed', async () => {
  api.scanDeployment.mockResolvedValue({...scan,findings:[],passed_checks:policies});
  await uploadAndScan();
  expect(screen.getByText(/No remediation candidate is needed/)).toBeTruthy();
  expect(screen.queryByRole('button',{name:'Generate mock example'})).toBeNull();
});

it('rejects an oversized upload before calling the backend', async () => {
  render(<App/>);
  fireEvent.change(screen.getByLabelText('Kubernetes YAML file'),{target:{files:[new File([new Uint8Array(256*1024+1)],'large.yaml')]}});
  expect(await screen.findByRole('alert')).toHaveProperty('textContent','File exceeds the 256 KiB limit.');
  expect(api.parseDeployment).not.toHaveBeenCalled();
});

it('does not scan after automatic parsing fails', async () => {
  api.parseDeployment.mockRejectedValue(new Error('Malformed YAML'));
  render(<App/>);
  fireEvent.change(screen.getByLabelText('Kubernetes YAML file'),{target:{files:[new File(['invalid'],'invalid.yaml')]}});
  await screen.findByText('Malformed YAML');
  expect(api.scanDeployment).not.toHaveBeenCalled();
  expect(api.explainDeployment).not.toHaveBeenCalled();
});

it('ignores an older parse response after the selected input changes', async () => {
  const parsed = await api.parseDeployment();
  api.parseDeployment.mockClear();
  let finishOld;
  api.parseDeployment.mockImplementationOnce(()=>new Promise((resolve)=>{finishOld=resolve;}));
  render(<App/>);
  fireEvent.change(screen.getByLabelText('Kubernetes YAML file'),{target:{files:[new File(['first'],'first.yaml')]}});
  // Programmatic change exercises stale-response protection even though the UI disables input.
  fireEvent.change(screen.getByLabelText('Kubernetes YAML file'),{target:{files:[new File([originalYaml],'second.yaml')]}});
  await screen.findByRole('heading',{name:'Checkov findings'});
  finishOld(parsed);
  await waitFor(()=>expect(api.scanDeployment).toHaveBeenCalledOnce());
  expect(api.scanDeployment.mock.calls[0][0].name).toBe('second.yaml');
});

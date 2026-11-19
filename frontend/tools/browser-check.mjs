// Real local API + headless Edge. Provider errors are explicitly simulated.
import { chromium } from 'playwright';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdir, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const frontend = fileURLToPath(new URL('..', import.meta.url));
const root = path.resolve(frontend, '..');
const results = path.join(frontend, 'browser-results');
const children = [];
let browser;
const report = { mode: 'real-browser-local-tools-mock-provider', external_ai_requests: 0, scenarios: [] };

function start(command, args, cwd, env) {
  const child = spawn(command, args, { cwd, env: { ...process.env, ...env }, windowsHide: true, stdio: 'pipe' });
  let logs = '';
  child.stdout.on('data', (data) => { logs = (logs + data).slice(-3000); });
  child.stderr.on('data', (data) => { logs = (logs + data).slice(-3000); });
  child.on('error', (error) => { logs += error.message; });
  children.push(child);
  return { child, logs: () => logs };
}

async function ready(server, url) {
  for (let attempt = 0; attempt < 50; attempt++) {
    if (server.child.exitCode !== null) throw new Error(`Check server startup/unused ports. ${server.logs()}`);
    try { const response = await fetch(url); if (response.ok) return; } catch {}
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  throw new Error(`Server readiness timed out: ${url}`);
}

try {
  await mkdir(results, { recursive: true });
  // Refuse occupied ports rather than attaching to somebody else's dev server.
  for (const url of ['http://127.0.0.1:8001/health', 'http://127.0.0.1:5174']) {
    let occupied = false;
    try { await fetch(url, { signal: AbortSignal.timeout(500) }); occupied = true; } catch {}
    if (occupied) throw new Error('Browser check requires unused local ports 8001 and 5174.');
  }
  const backend = start(path.join(root, 'backend/.venv/Scripts/python.exe'), ['-m','uvicorn','app.main:app','--host','127.0.0.1','--port','8001'], path.join(root, 'backend'), {
    AI_PROVIDER:'mock', GEMINI_API_KEY:'', GEMINI_FREE_TIER_CONFIRMED:'false',
  });
  const vite = start(process.execPath, ['node_modules/vite/bin/vite.js','--port','5174'], frontend, { CONFIGSHIELD_BACKEND_URL:'http://127.0.0.1:8001' });
  await Promise.all([ready(backend, 'http://127.0.0.1:8001/health'), ready(vite, 'http://127.0.0.1:5174')]);
  browser = await chromium.launch({ channel:'msedge', headless:true });
  const page = await browser.newPage({ viewport:{ width:1440, height:1000 }, acceptDownloads:true });
  page.setDefaultTimeout(90000);
  const errors = [];
  page.on('pageerror', (error) => errors.push(error.message));
  await page.route('**/*', (route) => {
    const url = new URL(route.request().url());
    if (url.hostname !== '127.0.0.1' || url.searchParams.get('provider') === 'gemini') return route.abort();
    return route.continue();
  });
  await page.goto('http://127.0.0.1:5174');

  async function loadCase() {
    await page.getByLabel('Try a dataset example').selectOption('ckv_k8s_16-explicit');
    const scanned = page.waitForResponse((response) => response.url().includes('/api/scan?'));
    await page.getByRole('button',{name:'Load dataset case',exact:true}).click();
    assert.equal((await scanned).status(),200);
    await page.getByRole('heading',{name:'Checkov findings',exact:true}).waitFor();
  }
  async function generate() {
    const response = page.waitForResponse((response) => response.url().includes('/api/explain?'));
    await page.getByRole('button',{name:'Generate mock example',exact:true}).click();
    const body = await (await response).json();
    assert.equal(body.status,'mock', JSON.stringify(body.error || 'Unexpected mock response'));
    await page.getByRole('heading',{name:'Next step: review and approve',exact:true}).waitFor();
    return body;
  }
  async function build() {
    await page.getByLabel('I reviewed these field changes', {exact:false}).check();
    await page.getByRole('button',{name:'Approve and build candidate YAML',exact:true}).click();
    await page.getByRole('textbox',{name:'Candidate YAML',exact:true}).waitFor();
  }
  async function verify() {
    const response = page.waitForResponse((response) => response.url().endsWith('/api/verify'));
    await page.getByRole('button',{name:'Verify candidate',exact:true}).click();
    return (await response).json();
  }

  await loadCase();
  await page.getByLabel('Kubernetes API access',{exact:true}).selectOption('not_required');
  await page.getByLabel('Privileged host/device access',{exact:true}).selectOption('not_required');
  await page.getByLabel('Can this application run as non-root?',{exact:true}).selectOption('compatible');
  const explanation = await generate();
  await build();
  const candidate = await page.getByRole('textbox',{name:'Candidate YAML',exact:true}).inputValue();
  assert.equal((await verify()).status, 'verified_supported_checks');
  await page.getByLabel('I reviewed the changes and verification results',{exact:false}).check();
  const downloaded = page.waitForEvent('download');
  await page.getByRole('button',{name:'Download candidate YAML',exact:true}).click();
  const download = await downloaded;
  const stream = await download.createReadStream();
  const chunks = [];
  for await (const chunk of stream) chunks.push(chunk);
  assert.equal(Buffer.concat(chunks).toString('utf8'), candidate);
  report.scenarios.push('automatic dataset parse/scan/guidance; real mock proposal/build/verify; downloaded bytes equal reviewed candidate');
  await page.screenshot({path:path.join(results,'desktop.png'),fullPage:true});
  await page.setViewportSize({width:390,height:844});
  await page.screenshot({path:path.join(results,'mobile.png'),fullPage:true});
  report.mobile_overflow = await page.evaluate(()=>[...document.querySelectorAll('body *')].filter((element)=>element.getBoundingClientRect().right > window.innerWidth + 1).slice(0,12).map((element)=>({tag:element.tagName,class:element.className})));
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth <= window.innerWidth), true);
  report.scenarios.push('390px viewport has no horizontal page overflow; screenshots captured');
  await page.setViewportSize({width:1440,height:1000});

  await loadCase();
  await generate(); await build();
  const unknown = await verify();
  assert.equal(unknown.status,'manual_review');
  assert(unknown.constraint_report.results.some((result)=>result.requirement==='api_access' && result.status==='unverifiable'));
  report.scenarios.push('unconfirmed/unknown requirements retain manual review after real verification');

  const input = await (await page.request.get('http://127.0.0.1:5174/api/datasets/ckv_k8s_16-explicit')).json();
  const conflict = await page.request.post('http://127.0.0.1:5174/api/candidate', { data:{filename:input.filename,original_yaml:input.yaml,
    original_sha256:input.sha256,proposal:explanation.proposal,
    requirements:{api_access:'not_required',privileged_access:'required',non_root_compatibility:'compatible'},
    approved:true,acknowledge_manual_review:true} });
  const blocked = await conflict.json();
  assert.equal(blocked.status,'blocked');
  assert.equal(blocked.candidate_yaml,null);
  report.scenarios.push('real API rejects an approved proposal that conflicts with required privileged access');

  await page.getByLabel('Kubernetes YAML file',{exact:true}).setInputFiles({name:'invalid.yaml',mimeType:'application/yaml',buffer:Buffer.from('apiVersion: [broken')});
  await page.getByRole('alert').filter({hasText:'Malformed or unsupported YAML'}).waitFor();
  assert.equal(await page.getByRole('textbox',{name:'Candidate YAML',exact:true}).count(),0);
  report.scenarios.push('invalid YAML automatically reports parse error and clears candidate');

  await page.route('**/api/ai/status', (route)=>route.fulfill({json:{gemini_ready:true,mock_available:true,message:'Simulated readiness for quota UI check',model:'gemini-3.1-flash-lite',process_requests_attempted:0,request_limit_per_process:5}}));
  await page.route('**/api/explain?**', (route)=>route.fulfill({status:429,json:{error:{code:'ai_quota_exhausted',message:'Simulated Gemini quota exhausted. No retry was made.'}}}));
  await loadCase();
  await page.getByRole('button',{name:'Check AI configuration',exact:true}).click();
  await page.getByRole('button',{name:'Ask Gemini — one request',exact:true}).click();
  await page.getByRole('alert').filter({hasText:'Simulated Gemini quota exhausted'}).waitFor();
  report.scenarios.push('simulated quota response displays an error; no external provider request');
  assert.deepEqual(errors,[]);
  report.browser_version = browser.version();
  report.status = 'passed';
  console.log(JSON.stringify(report,null,2));
} catch(error) {
  report.status = 'failed'; report.error = error.message;
  const failedPage = browser?.contexts()[0]?.pages()[0];
  if (failedPage) {
    report.failure_ui = (await failedPage.locator('main').innerText()).slice(-7000);
    await failedPage.screenshot({path:path.join(results,'failure.png'),fullPage:true});
  }
  console.error(error.message); process.exitCode = 1;
} finally {
  if(browser) await browser.close();
  for(const child of children) { if(child.exitCode === null) child.kill(); }
  await writeFile(path.join(results,'report.json'),JSON.stringify(report,null,2)+'\n');
}

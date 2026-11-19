import { useEffect, useState } from 'react';
import { checkHealth, getAIStatus } from './api.js';
import UploadPanel from './components/UploadPanel.jsx';

export default function App() {
  const [state, setState] = useState('idle');
  const [ai, setAI] = useState(null);
  const [aiUnavailable, setAIUnavailable] = useState(false);
  useEffect(() => {
    let active = true;
    async function refresh() {
      try { const status = await getAIStatus(); if (active) { setAI(status); setAIUnavailable(false); } }
      catch { if (active) { setAI(null); setAIUnavailable(true); } }
    }
    refresh();
    const timer = setInterval(refresh, 30000);
    return () => { active = false; clearInterval(timer); };
  }, []);
  const [message, setMessage] = useState('Ready to check your local backend.');

  async function handleCheck() {
    setState('loading');
    setMessage('Connecting to the backend…');
    try {
      const health = await checkHealth();
      setState('connected');
      setMessage(`${health.service} is connected and responding.`);
    } catch (error) {
      setState('error');
      setMessage(error.name === 'TimeoutError'
        ? 'The backend took too long to respond. Check that FastAPI is running.'
        : error instanceof TypeError
          ? 'Could not reach the backend. Check that FastAPI is running on port 8000.'
          : error.message);
    }
  }

  return (
    <main className="mx-auto max-w-7xl px-4 pb-10 sm:px-8">
      <header className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 py-5">
        <a href="#upload" className="flex items-center gap-3 text-lg font-semibold tracking-tight" aria-label="ConfigShield AI review workspace">
          <span className="brand-mark"><svg aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7"><path d="M12 3 4.5 6v5.5c0 4.3 3.2 7.5 7.5 9.5 4.3-2 7.5-5.2 7.5-9.5V6L12 3Z"/><path d="m8.5 12 2.4 2.4 4.6-4.8"/></svg></span>
          <span>ConfigShield <span className="text-emerald-300">AI</span><span className="mt-0.5 block text-[10px] font-normal uppercase tracking-[.18em] text-slate-400">Kubernetes security review</span></span>
        </a>
        <div className="flex items-center gap-3"><span className="pill hidden sm:inline-flex">Local workspace</span><button type="button" onClick={handleCheck} disabled={state === 'loading'} className="btn-secondary text-xs">{state === 'loading' ? 'Connecting...' : state === 'connected' ? 'Backend connected' : 'Check connection'}</button></div>
      </header>
      <div role="status" aria-label="AI availability" className={`mt-3 rounded-lg border p-3 text-xs ${ai?.gemini_ready ? 'border-emerald-800 text-emerald-200' : 'border-slate-700 text-slate-300'}`}>
        <span aria-hidden="true">{ai?.gemini_ready ? '● ' : '○ '}</span>
        <strong>{aiUnavailable ? 'AI status unavailable — backend unreachable' : !ai ? 'Checking AI availability…' : ai.gemini_ready ? 'Gemini ready — backend connected' : 'Gemini setup needed — mock available'}</strong>
        <p className="mt-1">{aiUnavailable ? 'Start the backend; this indicator refreshes every 30 seconds.' : ai ? `${ai.message} Status checks use no AI requests; Google authentication and quota are tested only when you ask Gemini.` : 'Checking backend settings without sending an AI request.'}</p>
      </div>
      <p role="status" aria-live="polite" className={`mt-3 text-xs ${state === 'error' ? 'text-rose-300' : 'text-slate-400'}`}>{message}</p>
      <section className="flex flex-wrap items-end justify-between gap-6 py-8 sm:py-10">
        <div><p className="eyebrow">Intent-aware configuration review</p><h1 className="mt-3 max-w-3xl text-3xl font-semibold leading-tight tracking-tight sm:text-4xl">Review the risk.<br className="sm:hidden" /> Preserve the intent.</h1><p className="mt-4 max-w-2xl text-sm leading-relaxed text-slate-400 sm:text-base">Inspect a Deployment, explain findings with trusted guidance, and verify a minimal candidate before you decide what to download.</p></div>
        <div className="flex gap-2"><span className="pill">7 selected policies</span><span className="pill">No auto-deployment</span></div>
      </section>
      <UploadPanel />
      <footer className="mt-8 flex flex-wrap justify-between gap-3 border-t border-slate-800 pt-5 text-xs leading-relaxed text-slate-500"><span>ConfigShield AI · Your configuration, your decision.</span><span>Schema validity and selected security checks do not prove runtime compatibility.</span></footer>
    </main>
  );
}

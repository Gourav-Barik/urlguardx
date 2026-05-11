import React, { useState, useEffect, useRef, useCallback } from 'react';
import { 
  ShieldAlert, ShieldCheck, Search, Lock, Globe, 
  FileText, Database, Bot, AlertTriangle, CheckCircle2, 
  XCircle, Activity, Terminal, Cpu, Network,
  Server, Zap, Code, MinusCircle, Crosshair, Radar, Fingerprint,
  Clock, X, Trash2, RefreshCw, Eye, ExternalLink
} from 'lucide-react';
const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || 'https://urlguardx-backend.onrender.com').replace(/\/$/, '');
export default function App() {
  const [url, setUrl] = useState('');
  const [appState, setAppState] = useState('IDLE'); // IDLE, SCANNING, COMPLETE, ERROR
  const [result, setResult] = useState(null);
  const [scanLogs, setScanLogs] = useState([]);
  const [errorMsg, setErrorMsg] = useState('');
  const [urlError, setUrlError] = useState('');
  const logsEndRef = useRef(null);

  // --- URL VALIDATION ---
  // Accepts: google.com, http://google.com, https://sub.google.co.in/path
  //          192.168.1.1, http://8.8.8.8, https://10.0.0.1/path
  // Rejects: google, localhost, 123, bare hostnames with no structure
  const isValidUrl = (input) => {
    const trimmed = input.trim();
    const withoutScheme = trimmed.replace(/^https?:\/\//i, '').replace(/^www\./i, '').split('/')[0].split(':')[0];
    // Accept domain names (must have a letter-TLD)
    const isDomain = /^[^\s/]+\.[a-zA-Z]{2,}/.test(withoutScheme);
    // Accept IPv4 addresses (four numeric octets)
    const isIPv4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(withoutScheme);
    return isDomain || isIPv4;
  };

  // History State
  const [history, setHistory] = useState(() => {
    try {
      const saved = localStorage.getItem('urlguardx_history');
      return saved ? JSON.parse(saved) : [];
    } catch {
      return [];
    }
  });
  const [showHistory, setShowHistory] = useState(false);

  // --- TIME FORMATTING (IST) ---
  const getTerminalISTTime = () => {
    return new Date().toLocaleTimeString('en-IN', {
      timeZone: 'Asia/Kolkata', hour12: false,
      hour: '2-digit', minute: '2-digit', second: '2-digit', fractionalSecondDigits: 3
    });
  };

  const getDisplayISTTime = () => {
    return new Date().toLocaleString('en-IN', {
      timeZone: 'Asia/Kolkata', day: '2-digit', month: 'short', year: 'numeric',
      hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: true
    }) + ' IST';
  };

  useEffect(() => {
    if (logsEndRef.current) {
      logsEndRef.current.scrollIntoView({ behavior: 'smooth', block: 'end' });
    }
  }, [scanLogs]);

  // --- STATUS BADGE HELPERS ---
  const getStatusBadge = (status) => {
    if (status === 'High Risk') return { bg: 'bg-rose-950', text: 'text-rose-400', border: 'border-rose-500/40', dot: 'bg-rose-500' };
    if (status === 'Suspicious') return { bg: 'bg-amber-950', text: 'text-amber-400', border: 'border-amber-500/40', dot: 'bg-amber-500' };
    return { bg: 'bg-cyan-950', text: 'text-cyan-400', border: 'border-cyan-500/40', dot: 'bg-cyan-500' };
  };

  const getRiskColor = (score) => {
    if (score >= 70) return 'text-rose-400';
    if (score >= 40) return 'text-amber-400';
    return 'text-cyan-400';
  };

  // --- TERMINAL TYPING LOGIC ---
  const typeLog = async (text, delayMs = 20, pauseMs = 150) => {
    const delay = (ms) => new Promise(res => setTimeout(res, ms));
    const logTime = getTerminalISTTime();
    const words = text.split(' ');
    let currentText = '';

    setScanLogs(prev => [...prev, { time: logTime, text: '' }]);

    for (let w = 0; w < words.length; w++) {
      currentText += (w === 0 ? '' : ' ') + words[w];
      setScanLogs(prev => {
        const newLogs = [...prev];
        newLogs[newLogs.length - 1].text = currentText;
        return newLogs;
      });
      await delay(delayMs);
    }
    await delay(pauseMs); 
  };
const fetchWithRetry = async (url, options, retries = 2, timeout = 30000) => {
  const fetchWithTimeout = () =>
    Promise.race([
      fetch(url, options),
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error("timeout")), timeout)
      )
    ]);

  try {
    const res = await fetchWithTimeout();
    if (!res.ok) throw new Error("HTTP error");
    return res;
  } catch (err) {
    if (retries > 0) {
      await new Promise(r => setTimeout(r, 700));
      return fetchWithRetry(url, options, retries - 1, timeout);
    }
    throw err;
  }
};
  // --- MAIN SCAN HANDLER (STRICT BACKEND ENFORCEMENT) ---
  // Core scan logic — accepts URL as parameter so it can be called from
  // both the form submit handler AND the Re-scan button in history.
  const runScan = async (targetUrl) => {
    if (!targetUrl || !targetUrl.trim()) return;

    setAppState('SCANNING');
    setResult(null);
    setErrorMsg('');
    setScanLogs([]);

    await typeLog("[SYSTEM] Initializing security analysis...");
    await typeLog(`[TARGET] Processing URL: ${targetUrl}`);
    await typeLog("[AGENT] Allocating analysis pipeline...");
    try {
      const response = await fetchWithRetry(`${API_BASE_URL}/api/v1/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
        body: JSON.stringify({ url: targetUrl })
      });
      if (!response.ok) throw new Error(`Backend HTTP Error: ${response.status}`);
      const backendData = await response.json();

      await typeLog("[LEXICAL] Running ML structural analysis...");
      await typeLog(`[LEXICAL] Result: [${backendData.modules.lexical.status.toUpperCase()}]`);
      await typeLog("[THREAT_INTEL] Checking threat intelligence feeds...");
      await typeLog(`[THREAT_INTEL] Result: [${backendData.modules.blacklist.status.toUpperCase()}]`);

      if (backendData.modules.blacklist.status === 'Danger') {
        await typeLog("[AGENT] Confirmed malicious via threat intelligence.");
        await typeLog("[AGENT] Short-circuiting further analysis.");
        await typeLog("[DOMAIN] Skipped (blacklist authority).");
        await typeLog("[SSL] Skipped (blacklist authority).");
      } else {
        if (backendData.modules.domain.details?.toLowerCase().includes("golden domain")) {
          await typeLog("[AGENT] Trusted domain detected.");
          await typeLog("[DOMAIN] Skipped (golden domain).");
          await typeLog(`[SSL] Result: [${backendData.modules.ssl.status.toUpperCase()}]`);
        } else if (targetUrl.startsWith("http://")) {
          await typeLog("[AGENT] Insecure HTTP detected.");
          await typeLog(`[SSL] Result: [${backendData.modules.ssl.status.toUpperCase()}]`);
          await typeLog("[DOMAIN] Running WHOIS analysis...");
          await typeLog(`[DOMAIN] Result: [${backendData.modules.domain.status.toUpperCase()}]`);
        } else {
          await typeLog("[AGENT] Running full domain + SSL validation...");
          await typeLog("[DOMAIN] Running WHOIS analysis...");
          await typeLog(`[DOMAIN] Result: [${backendData.modules.domain.status.toUpperCase()}]`);
          await typeLog(`[SSL] Result: [${backendData.modules.ssl.status.toUpperCase()}]`);
        }
      }

      await typeLog("[RISK_ENGINE] Calculating final risk score...");
      await typeLog(`[SYSTEM] Risk Score: ${backendData.riskScore}/100`);
      await typeLog("[AI] Generating explanation (Gemini)...");
      await typeLog("[SYSTEM] Scan complete. Rendering dashboard...");

      formatAndSetResult(backendData);
      setAppState('COMPLETE');
    } catch (err) {
      await typeLog("[SYSTEM] Network instability detected...");
      await typeLog("[SYSTEM] Retrying silently...");
      await new Promise(r => setTimeout(r, 1200));
      await typeLog("[SYSTEM] Unable to complete scan.");
      setErrorMsg("Scan could not be completed. Please try again.");
      setAppState('ERROR');
    }
  };

  const handleScan = async (e) => {
    e.preventDefault();
    const trimmedUrl = url.trim();
    if (!trimmedUrl) return;
    if (!isValidUrl(trimmedUrl)) {
      setUrlError('Please enter a valid URL with a domain name (e.g. google.com or https://google.com)');
      return;
    }
    setUrlError('');
    await runScan(trimmedUrl);
  };

  const handleRetry = async () => {
    if (!url.trim()) return;
    await runScan(url.trim());
  };

  const formatAndSetResult = (data) => {
    const isDangerous = data.status === "High Risk";
    const isWarning = data.status === "Suspicious";

    const theme = isDangerous ? { base: 'rose', hex: '#f43f5e' } : (isWarning ? { base: 'amber', hex: '#f59e0b' } : { base: 'cyan', hex: '#22d3ee' });
    
    const mainIcon = isDangerous ? <ShieldAlert className={`w-20 h-20 text-${theme.base}-500 drop-shadow-[0_0_20px_rgba(244,63,94,0.6)]`} /> 
                                 : <ShieldCheck className={`w-20 h-20 text-${theme.base}-400 drop-shadow-[0_0_20px_rgba(34,211,238,0.6)]`} />;

    const getModuleIcon = (status) => {
      if (status === 'Danger') return <XCircle className="w-5 h-5 text-rose-500"/>;
      if (status === 'Warning') return <AlertTriangle className="w-5 h-5 text-amber-500"/>;
      if (status === 'Skipped') return <MinusCircle className="w-5 h-5 text-neutral-500"/>;
      return <CheckCircle2 className="w-5 h-5 text-cyan-400"/>;
    };

    setResult({
      ...data, theme, icon: mainIcon, scanTimeIST: getDisplayISTTime(),
      canonicalUrl: data.canonicalUrl || url,
      resolvedUrl:  data.resolvedUrl  || null,
      modules: {
        lexical:   { ...data.modules.lexical,   icon: getModuleIcon(data.modules.lexical.status)   },
        domain:    { ...data.modules.domain,     icon: getModuleIcon(data.modules.domain.status)    },
        ssl:       { ...data.modules.ssl,        icon: getModuleIcon(data.modules.ssl.status)       },
        blacklist: { ...data.modules.blacklist,  icon: getModuleIcon(data.modules.blacklist.status) },
      }
    });

    const resolvedDisplayUrl = data.resolvedUrl || data.canonicalUrl || url;

    setHistory(prev => {
      // Deduplicate by resolved URL so http://site.com/ and http://site.com are the same entry
      const filtered = prev.filter(item => item.url !== resolvedDisplayUrl);
      const updated = [
        {
          url: resolvedDisplayUrl,
          status: data.status,
          riskScore: data.riskScore,
          time: getDisplayISTTime(),
          savedData: { ...data, scanTimeIST: getDisplayISTTime() }  // inject scanTimeIST for View restore
        },
        ...filtered
      ].slice(0, 20);
      localStorage.setItem('urlguardx_history', JSON.stringify(updated));
      return updated;
    });
  };

  const deleteHistoryItem = (urlToDelete) => {
    setHistory(prev => {
      const updated = prev.filter(item => item.url !== urlToDelete);
      localStorage.setItem('urlguardx_history', JSON.stringify(updated));
      return updated;
    });
  };

  // Restore a previous scan result WITHOUT re-scanning and WITHOUT moving history.
  // Also updates the search bar to show the restored URL.
  const restoreResult = (savedData, itemUrl) => {
    const isDangerous = savedData.status === "High Risk";
    const isWarning   = savedData.status === "Suspicious";
    const theme = isDangerous
      ? { base: 'rose', hex: '#f43f5e' }
      : (isWarning ? { base: 'amber', hex: '#f59e0b' } : { base: 'cyan', hex: '#22d3ee' });
    const mainIcon = isDangerous
      ? <ShieldAlert className={`w-20 h-20 text-${theme.base}-500 drop-shadow-[0_0_20px_rgba(244,63,94,0.6)]`} />
      : <ShieldCheck  className={`w-20 h-20 text-${theme.base}-400 drop-shadow-[0_0_20px_rgba(34,211,238,0.6)]`} />;
    const getModuleIcon = (status) => {
      if (status === 'Danger')  return <XCircle       className="w-5 h-5 text-rose-500"/>;
      if (status === 'Warning') return <AlertTriangle  className="w-5 h-5 text-amber-500"/>;
      if (status === 'Skipped') return <MinusCircle   className="w-5 h-5 text-neutral-500"/>;
      return <CheckCircle2 className="w-5 h-5 text-cyan-400"/>;
    };
    // Update search bar to reflect the restored URL
    if (itemUrl) setUrl(itemUrl);
    // Set result — preserve the ORIGINAL scanTimeIST so timestamp doesn't change
    setResult({
      ...savedData, theme, icon: mainIcon,
      scanTimeIST: savedData.scanTimeIST || getDisplayISTTime(),
      canonicalUrl: savedData.canonicalUrl,
      resolvedUrl:  savedData.resolvedUrl || null,
      modules: {
        lexical:   { ...savedData.modules.lexical,   icon: getModuleIcon(savedData.modules.lexical.status)   },
        domain:    { ...savedData.modules.domain,     icon: getModuleIcon(savedData.modules.domain.status)    },
        ssl:       { ...savedData.modules.ssl,        icon: getModuleIcon(savedData.modules.ssl.status)       },
        blacklist: { ...savedData.modules.blacklist,  icon: getModuleIcon(savedData.modules.blacklist.status) },
      }
    });
    setAppState('COMPLETE');
    setScanLogs([]);
    setShowHistory(false);
    // History is NOT touched — item stays in its original position with original timestamp
  };

  return (
    <>
      <style>{`
        ::-webkit-scrollbar { width: 6px; height: 6px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: #334155; border-radius: 10px; }
        ::-webkit-scrollbar-thumb:hover { background: #22d3ee; }
        .glass-panel {
          background: rgba(10, 15, 25, 0.6);
          backdrop-filter: blur(16px);
          -webkit-backdrop-filter: blur(16px);
          border: 1px solid rgba(255, 255, 255, 0.05);
          box-shadow: 0 4px 30px rgba(0, 0, 0, 0.5);
        }
      `}</style>

      <div className="min-h-screen bg-neutral-950 text-slate-300 font-sans selection:bg-cyan-500/30 overflow-x-hidden relative flex flex-col">
        
        {/* Advanced Matrix Background */}
        <div className="fixed inset-0 z-0 pointer-events-none">
          <div className="absolute inset-0 bg-[radial-gradient(#ffffff10_1px,transparent_1px)] [background-size:20px_20px] opacity-40"></div>
          <div className="absolute top-[-20%] left-[-10%] w-[50%] h-[50%] rounded-full bg-indigo-900/20 blur-[150px]"></div>
          <div className="absolute bottom-[-20%] right-[-10%] w-[50%] h-[50%] rounded-full bg-cyan-900/10 blur-[150px]"></div>
        </div>

        {/* HUD Navigation */}
        <nav className="relative z-10 border-b border-white/5 glass-panel">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="flex justify-between h-20 items-center">
              <div className="flex items-center gap-4">
                <div className="relative flex items-center justify-center w-12 h-12 rounded-lg bg-neutral-900/80 border border-white/10 shadow-[0_0_15px_rgba(34,211,238,0.15)] p-2">
                  <img src="/urlguardx-logo.svg" alt="URLGuardX Logo" className="w-full h-full object-contain relative z-10" />
                </div>
                <div>
                  <h1 className="font-extrabold text-2xl tracking-tighter text-white leading-none">
                    URLGuard<span className="text-cyan-400">X</span>
                  </h1>
                  <span className="text-[10px] font-mono text-cyan-500/70 tracking-[0.2em] uppercase">ADVANCED THREAT MONITOR</span>
                </div>
              </div>
              
              <div className="flex items-center gap-3">
                {/* SYSTEM / NODE status block */}
                <div className="hidden md:flex items-center gap-3 font-mono text-xs border border-white/10 bg-black/40 px-4 h-9 rounded-md shadow-inner">
                  <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse shadow-[0_0_8px_rgba(16,185,129,0.8)]"></div>
                  <span className="text-slate-400">SYSTEM:</span>
                  <span className="text-emerald-400">ONLINE</span>
                  <span className="text-slate-600 px-2">|</span>
                  <span className="text-slate-400">NODE:</span>
                  <span className="text-cyan-400">AP-SOUTH-1</span>
                </div>

                {/* HISTORY button — same height as status block, cyan default */}
                <div className="relative group">
                  <button
                    onClick={() => setShowHistory(true)}
                    className="flex items-center gap-2 font-mono text-xs border border-white/10 bg-black/40 px-4 h-9 rounded-md shadow-inner text-cyan-400 border-cyan-500/20 transition-colors duration-200 hover:bg-black/60"
                  >
                    <Clock className="w-3.5 h-3.5" />
                    <span className="tracking-widest uppercase">History</span>
                  </button>
                  {/* Tooltip */}
                  <div className="absolute top-full right-0 mt-2 w-max opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all duration-200 z-50 pointer-events-none">
                    <div className="bg-black/90 border border-white/10 text-slate-300 text-[10px] font-mono px-2 py-1 rounded shadow-lg">
                      View Scan History
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </nav>

        {/* Main Interface Content */}
        <main className="relative z-10 flex-grow flex flex-col items-center justify-start pt-12 pb-20 px-4 sm:px-6 lg:px-8 w-full max-w-7xl mx-auto">
          
          {/* SEARCH CONSOLE */}
          <div className={`w-full max-w-4xl transition-all duration-700 ease-in-out ${appState !== 'IDLE' ? 'mb-8 scale-95 opacity-90' : 'mt-20 mb-0 scale-100 opacity-100'}`}>
            {appState === 'IDLE' && (
              <div className="text-center mb-10 animate-in slide-in-from-bottom-4 fade-in duration-700">
                <div className="inline-flex items-center justify-center p-3 mb-6 rounded-full bg-cyan-950/30 border border-cyan-500/20">
                  <Radar className="w-6 h-6 text-cyan-400 animate-[spin_4s_linear_infinite]" />
                </div>
                <h2 className="text-5xl font-black text-white mb-6 tracking-tight drop-shadow-lg">
                  Explainable Phishing URL Detection
                </h2>
                <p className="text-slate-400 text-lg max-w-3xl mx-auto font-light leading-relaxed">
                  A multi-layered AI security engine that analyzes URL structures, validates SSL certificates, and cross-checks domain history to instantly detect and explain phishing threats.
                </p>
              </div>
            )}

            <form onSubmit={handleScan} className="relative group w-full">
              <div className="absolute -inset-1 bg-gradient-to-r from-cyan-500/40 via-indigo-500/40 to-cyan-500/40 rounded-xl blur-md opacity-50 group-hover:opacity-100 transition duration-500 group-hover:duration-200 animate-pulse"></div>
              <div className="relative flex items-center w-full bg-[#050914] border border-cyan-900/50 rounded-2xl shadow-2xl p-2">
                <div className="pl-4 pr-3 text-cyan-500">
                  <Crosshair className="w-6 h-6 opacity-70" />
                </div>
                <input 
                  type="text" 
                  value={url}
                  onChange={(e) => { setUrl(e.target.value); if (urlError) setUrlError(''); }}
                  placeholder="Enter target URI vector (e.g., https://secure-login.com)"
                  className={`w-full py-4 pr-4 bg-transparent border-none focus:outline-none text-white text-lg font-mono placeholder-slate-600 ${urlError ? 'text-rose-300' : ''}`}
                  disabled={appState === 'SCANNING'}
                  required
                />
                <button 
                  type="submit" 
                  disabled={appState === 'SCANNING'}
                  className={`px-8 py-4 font-bold uppercase tracking-widest text-sm transition-all flex items-center gap-3 rounded-xl border border-transparent
                    ${appState === 'SCANNING' ? 'bg-neutral-900 text-slate-500 cursor-wait' : 'bg-cyan-950/60 text-cyan-400 border-cyan-500/30 hover:bg-cyan-900/80 hover:text-cyan-300 hover:shadow-[0_0_15px_rgba(34,211,238,0.2)]'}`}
                >
                  {appState === 'SCANNING' ? 'Analyzing' : 'Execute'}
                  {appState === 'SCANNING' ? <Activity className="w-5 h-5 animate-spin" /> : <Terminal className="w-5 h-5" />}
                </button>
              </div>
            </form>

            {/* Inline URL validation error */}
            {urlError && (
              <div className="flex items-center gap-3 mt-3 px-4 py-3 rounded-xl bg-rose-500/10 border border-rose-500/25 animate-in fade-in slide-in-from-top-2 duration-300">
                <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
                <span className="text-rose-300 text-sm font-mono">{urlError}</span>
              </div>
            )}
            
            {appState === 'IDLE' && (
              <div className="flex justify-center gap-10 mt-8 text-xs font-mono text-cyan-300 opacity-70">
                <div className="flex items-center gap-2"><Fingerprint className="w-4 h-4"/> FEATURE-BASED ML ENGINE</div>
                <div className="flex items-center gap-2"><Network className="w-4 h-4"/> AGENTIC SCAN CONTROLLER</div>
                <div className="flex items-center gap-2"><Zap className="w-4 h-4"/> REAL-TIME THREAT FEEDS</div>
              </div>
            )}
          </div>

          {/* TERMINAL INTERFACE */}
          {(appState === 'SCANNING' || appState === 'ERROR') && (
            <div className="w-full max-w-4xl glass-panel rounded-xl overflow-hidden shadow-2xl border-cyan-500/20 animate-in fade-in zoom-in-95 duration-500">
              <div className="bg-black/60 px-4 py-3 flex items-center justify-between border-b border-white/5">
                <div className="flex gap-2">
                  <div className="w-3 h-3 rounded-full bg-rose-500/80 shadow-[0_0_5px_rgba(244,63,94,0.5)]"></div>
                  <div className="w-3 h-3 rounded-full bg-amber-500/80 shadow-[0_0_5px_rgba(245,158,11,0.5)]"></div>
                  <div className="w-3 h-3 rounded-full bg-emerald-500/80 shadow-[0_0_5px_rgba(16,185,129,0.5)]"></div>
                </div>
                <span className="text-[10px] font-mono text-slate-500 tracking-widest uppercase">Agentic_Orchestrator_CLI</span>
                <Activity className={`w-4 h-4 ${appState === 'ERROR' ? 'text-rose-500' : 'text-cyan-500 animate-pulse'}`} />
              </div>
              <div className="p-6 h-80 overflow-y-auto font-mono text-[13px] leading-relaxed space-y-2 bg-[#02040a]">
                {scanLogs.map((log, index) => {
                  let textColor = 'text-cyan-400/80';
                  if (log.text.includes('AGENT')) textColor = 'text-indigo-400 font-semibold';
                  if (log.text.includes('Match:') || log.text.includes('Danger') || log.text.includes('ERROR') || log.text.includes('FATAL')) textColor = 'text-rose-400';
                  if (log.text.includes('Safe') || log.text.includes('Clean')) textColor = 'text-emerald-400';
                  if (log.text.includes('bypassed') || log.text.includes('Short-circuiting')) textColor = 'text-slate-500 italic';
                  
                  return (
                    <div key={index} className="flex gap-4 min-w-max hover:bg-white/5 px-2 py-0.5 rounded transition-colors">
                      <span className="text-slate-600 shrink-0 select-none">[{log.time}]</span>
                      <span className={textColor}>{log.text}</span>
                    </div>
                  );
                })}
                <div ref={logsEndRef} className="pt-2 pl-2">
                  {appState === 'SCANNING' && (
                  <span className="inline-block w-2 h-4 bg-cyan-500 animate-pulse"></span>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* BACKEND ERROR OVERLAY */}
          {appState === 'ERROR' && (
            <div className="w-full max-w-4xl mt-6 p-6 rounded-xl bg-rose-500/10 border border-rose-500/30 flex items-start gap-4 animate-in fade-in slide-in-from-bottom-4">
              <AlertTriangle className="w-8 h-8 text-rose-500 shrink-0" />
              <div>
                <h3 className='text-rose-400 font-bold'>SCAN UNAVAILABLE</h3>
                
                <p className='text-rose-200'>We couldn’t analyze this URL right now. Please retry in a moment.</p>
                
                <div className="flex gap-2 mt-4">
                <button 
                  onClick={() => handleRetry()}
                  className="mt-4 px-4 py-2 bg-rose-950/50 hover:bg-rose-900/50 text-rose-200 text-xs font-mono rounded border border-rose-500/20 transition-colors">
                  
                  RETRY SCAN
                </button>
                
                <button 
                  onClick={() => setAppState('IDLE')}
                  className="mt-4 px-4 py-2 bg-rose-950/50 hover:bg-rose-900/50 text-rose-200 text-xs font-mono rounded border border-rose-500/20 transition-colors">
                  EDIT URL
                </button>
                </div>
              </div>
            </div>
          )}

          {/* BENTO DASHBOARD RESULTS */}
          {appState === 'COMPLETE' && result && (
            <div className="w-full animate-in fade-in slide-in-from-bottom-8 duration-700 ease-out space-y-6">
              
              {/* TOP ROW: Score & Synthesis */}
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                
                {/* Threat Confidence Card */}
                <div className={`glass-panel rounded-2xl p-6 border-t-4 border-t-${result.theme.base}-500 flex flex-col items-center justify-between relative overflow-hidden group`}>
                  <div className={`absolute inset-0 bg-gradient-to-b from-${result.theme.base}-500/10 to-transparent opacity-50`}></div>
                  
                  <div className="w-full flex justify-between items-center relative z-10 mb-4">
                    <h2 className="text-xs font-mono text-slate-400 uppercase tracking-widest">Confidence Index</h2>
                    <span className="text-[10px] font-mono text-slate-600">MEM:0x8F2</span>
                  </div>
                  
                  <div className="relative flex-grow flex items-center justify-center py-6 z-10">
                    <svg className="w-48 h-48 transform -rotate-90 overflow-visible">
                      <circle cx="96" cy="96" r="80" fill="transparent" stroke="rgba(255,255,255,0.05)" strokeWidth="8" />
                      <circle 
                        cx="96" cy="96" r="80" 
                        fill="transparent" 
                        stroke={result.theme.hex} 
                        strokeWidth="12" 
                        strokeDasharray="502" 
                        strokeDashoffset={502 - (502 * (result.riskScore || 0)) / 100} 
                        className="transition-all duration-1500 ease-out drop-shadow-[0_0_12px_currentColor]" 
                        strokeLinecap="round"
                      />
                    </svg>
                    <div className="absolute inset-0 flex flex-col items-center justify-center">
                      <span className={`text-6xl font-black text-white tracking-tighter drop-shadow-[0_0_15px_${result.theme.hex}]`}>
                        {result.riskScore}
                      </span>
                    </div>
                  </div>
                  
                  <div className={`w-full bg-black/40 rounded-lg p-4 flex items-center gap-4 border border-${result.theme.base}-500/20 relative z-10`}>
                    <div className="bg-black/50 p-2 rounded-lg border border-white/5">
                      {result.icon}
                    </div>
                    <div>
                      <span className="block text-[10px] text-slate-500 font-mono uppercase mb-1">Status Designation</span>
                      <span className={`text-2xl font-black uppercase tracking-widest text-${result.theme.base}-400 drop-shadow-[0_0_8px_currentColor]`}>
                        {result.status}
                      </span>
                    </div>
                  </div>
                </div>

                {/* AI Synthesis Card */}
                <div className="lg:col-span-2 glass-panel rounded-2xl p-8 relative flex flex-col">
                  <div className="absolute top-0 right-0 p-4 opacity-20 pointer-events-none">
                    <svg width="60" height="60" viewBox="0 0 100 100" className="text-indigo-400 fill-current">
                      <path d="M10,10 L30,10 L30,15 L15,15 L15,30 L10,30 Z M90,10 L90,30 L85,30 L85,15 L70,15 L70,10 Z M90,90 L70,90 L70,85 L85,85 L85,70 L90,70 Z M10,90 L10,70 L15,70 L15,85 L30,85 L30,90 Z" />
                    </svg>
                  </div>
                  
                  <div className="flex items-center justify-between mb-6 pb-4 border-b border-white/10">
                    <div className="flex items-center gap-4">
                      <div className="p-3 bg-indigo-500/10 rounded-xl border border-indigo-500/30 shadow-[0_0_15px_rgba(99,102,241,0.2)]">
                        <Bot className="w-6 h-6 text-indigo-400" />
                      </div>
                      <div>
                        <h2 className="text-lg font-bold text-white tracking-wide">Agentic AI Synthesis</h2>
                        <p className="text-xs font-mono text-indigo-400/80 uppercase tracking-widest">Gemini Reasoning Engine</p>
                      </div>
                    </div>
                  </div>

                  <div className="flex-grow flex items-center mb-6">
                    <p className="text-slate-300 text-lg leading-relaxed font-light border-l-2 border-indigo-500/50 pl-6">
                      {result.explanation}
                    </p>
                  </div>
                  
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-auto">
                    <div className="bg-[#050914] border border-white/5 rounded-lg p-4 flex items-start gap-3">
                      <Code className="w-4 h-4 text-cyan-500 mt-0.5" />
                      <div className="overflow-hidden w-full">
                        <span className="text-[10px] font-mono text-slate-500 uppercase block mb-1">Analyzed Vector</span>
                        <div className="flex items-center gap-2 w-full overflow-hidden">
                          <span className="text-sm text-white font-mono truncate flex-1" title={result.resolvedUrl || result.canonicalUrl}>
                            {result.resolvedUrl || result.canonicalUrl}
                          </span>
                          <div className="relative group shrink-0">
                            <a
                              href={result.resolvedUrl || result.canonicalUrl}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="p-1 rounded text-slate-500 hover:text-cyan-400 hover:bg-cyan-500/10 transition-colors flex"
                            >
                              <ExternalLink className="w-3.5 h-3.5" />
                            </a>
                            <span className="pointer-events-none absolute bottom-full left-1/2 -translate-x-1/2 mb-2 px-2 py-1 text-[10px] font-mono text-slate-300 bg-slate-900 border border-white/10 rounded whitespace-nowrap opacity-0 group-hover:opacity-100 transition-opacity z-50">
                              Open in new tab
                            </span>
                          </div>
                        </div>
                      </div>
                    </div>
                    <div className="bg-[#050914] border border-white/5 rounded-lg p-4 flex items-start gap-3">
                      <Server className="w-4 h-4 text-cyan-500 mt-0.5" />
                      <div>
                        <span className="text-[10px] font-mono text-slate-500 uppercase block mb-1">Node & Timestamp</span>
                        <span className="text-sm text-white font-mono block">
                          AP-SOUTH-1 <span className="text-slate-600 mx-1">/</span> <span className="text-cyan-400">{result.scanTimeIST}</span>
                        </span>
                      </div>
                    </div>
                  </div>
                </div>

              </div>

              {/* BOTTOM ROW: Subsystem Grid */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                {[
                  { key: 'lexical', title: 'Lexical Char-CNN', icon: FileText, color: 'indigo' },
                  { key: 'domain', title: 'WHOIS Registry', icon: Globe, color: 'teal' },
                  { key: 'ssl', title: 'TLS Validation', icon: Lock, color: 'emerald' },
                  { key: 'blacklist', title: 'Threat Intel', icon: Database, color: 'orange' }
                ].map((mod) => {
                  const modData = result.modules[mod.key];
                  const isSkipped = modData.status === 'Skipped';
                  const isBad = modData.status === 'Danger' || modData.status === 'Warning';
                  
                  return (
                    <div key={mod.key} className={`glass-panel rounded-xl p-6 transition-all relative overflow-hidden group hover:-translate-y-1 hover:shadow-2xl hover:shadow-${mod.color}-500/10 ${isSkipped ? 'opacity-60 grayscale-[50%]' : ''}`}>
                      <div className="absolute top-4 right-4">
                         <span className={`text-[9px] font-bold font-mono px-2 py-1 rounded-sm uppercase tracking-widest
                          ${modData.status === 'Clean' ? 'bg-cyan-950 text-cyan-400 border border-cyan-500/30' : 
                            (modData.status === 'Warning' ? 'bg-amber-950 text-amber-400 border border-amber-500/30' : 
                            (modData.status === 'Danger' ? 'bg-rose-950 text-rose-400 border border-rose-500/30' : 'bg-black text-slate-500 border border-slate-800'))}`}>
                          {modData.status}
                        </span>
                      </div>

                      <div className="flex flex-col gap-4 relative z-10">
                        <div className={`p-3 w-max rounded-lg bg-${isSkipped ? 'neutral' : mod.color}-500/10 border border-${isSkipped ? 'neutral' : mod.color}-500/20`}>
                           <mod.icon className={`w-5 h-5 text-${isSkipped ? 'slate-500' : mod.color + '-400'}`} />
                        </div>
                        
                        <div>
                          <h3 className={`font-bold text-sm mb-2 ${isSkipped ? 'text-slate-500' : 'text-white'}`}>{mod.title}</h3>
                          <div className={`text-xs leading-relaxed font-light ${isSkipped ? 'text-slate-600 italic' : 'text-slate-400'}`}>
                            {modData.status === "Skipped"? "Skipped by agentic decision": modData.details}
                          </div>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>

            </div>
          )}
        </main>

        {/* HISTORY DRAWER */}
        <div 
          className={`fixed inset-y-0 right-0 z-50 w-full sm:w-[450px] bg-[#050914] border-l border-white/5 shadow-2xl transform transition-transform duration-300 ease-in-out flex flex-col ${showHistory ? 'translate-x-0' : 'translate-x-full'}`}
        >
          {/* Header */}
          <div className="flex items-center justify-between p-6 border-b border-white/5 bg-black/40">
            <div className="flex items-center gap-4">
              <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/20">
                <Clock className="w-5 h-5 text-cyan-400" />
              </div>
              <div>
                <h3 className="text-lg font-bold text-white tracking-wide leading-tight">Scan History</h3>
                <p className="text-[10px] font-mono text-cyan-500/70 uppercase tracking-widest mt-1">LOCAL STORAGE - LAST 20 RECORDS</p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <button onClick={() => setShowHistory(false)} className="p-2 text-slate-500 hover:text-rose-400 transition-colors" title="Close">
                <X className="w-5 h-5" />
              </button>
            </div>
          </div>
          
          {/* List */}
          <div className="flex-grow overflow-y-auto p-4 space-y-4">
            {history.length === 0 ? (
              <div className="h-full flex flex-col items-center justify-center text-slate-500 opacity-60">
                <Database className="w-12 h-12 mb-4 text-slate-600" />
                <p className="font-mono text-xs uppercase tracking-widest">No Records Found</p>
              </div>
            ) : (
              history.map((item, idx) => {
                const isDangerous = item.status === "High Risk";
                const isWarning = item.status === "Suspicious";
                const badgeColor = isDangerous ? 'bg-rose-950 text-rose-400 border-rose-500/30' : (isWarning ? 'bg-amber-950 text-amber-400 border-amber-500/30' : 'bg-cyan-950 text-cyan-400 border-cyan-500/30');
                const riskColor = isDangerous ? 'text-rose-400' : (isWarning ? 'text-amber-400' : 'text-cyan-400');
                
                return (
                  <div key={idx} className="bg-black/40 border border-white/5 rounded-xl p-5 hover:bg-black/60 hover:border-white/10 transition-colors relative group">
                    <div className="flex justify-between items-start mb-3">
                      <span className={`text-[10px] font-bold uppercase tracking-widest px-2 py-1 rounded-sm border ${badgeColor} flex items-center gap-1.5`}>
                        <div className={`w-1.5 h-1.5 rounded-full ${isDangerous ? 'bg-rose-500' : (isWarning ? 'bg-amber-500' : 'bg-cyan-500')}`}></div>
                        {item.status === 'Clean' ? 'SAFE' : item.status}
                      </span>
                      <div className="font-mono text-xs text-slate-500 uppercase flex items-center gap-1.5">
                        RISK <span className={`text-base font-bold ${riskColor}`}>{item.riskScore}</span> /100
                      </div>
                    </div>
                    
                    <div className="text-sm font-mono text-white mb-3 truncate w-full" title={item.url}>
                      {item.url}
                    </div>
                    
                    <div className="flex items-center gap-2 text-xs font-mono text-slate-500 mb-5">
                      <Clock className="w-3.5 h-3.5" />
                      {item.time}
                    </div>
                    
                    <div className="flex items-center gap-2">
                        {item.savedData && (
                          <div className="relative group flex-1">
                            <button 
                              onClick={() => restoreResult(item.savedData, item.url)}
                              className="w-full py-2 px-3 flex items-center justify-center gap-2 rounded-lg bg-indigo-950/30 hover:bg-indigo-900/50 text-indigo-400 hover:text-indigo-300 transition-all border border-indigo-500/20 hover:border-indigo-500/50 text-[10px] font-mono uppercase tracking-widest hover:shadow-[0_0_14px_rgba(99,102,241,0.25)] active:scale-95 hover:scale-[1.02]"
                            >
                              <Eye className="w-3.5 h-3.5" />
                              View
                            </button>
                            <span className="pointer-events-none absolute bottom-full left-1/2 -translate-x-1/2 mb-2 px-2 py-1 text-[10px] font-mono text-slate-300 bg-slate-900 border border-white/10 rounded whitespace-nowrap opacity-0 group-hover:opacity-100 transition-opacity z-50">
                              Restore without re-scanning
                            </span>
                          </div>
                        )}
                      <button 
                        onClick={() => {
                          setUrl(item.url);
                          setShowHistory(false);
                          runScan(item.url);
                        }}
                        className="flex-1 py-2 px-3 flex items-center justify-center gap-2 rounded-lg bg-cyan-950/30 hover:bg-cyan-900/50 text-cyan-400 hover:text-cyan-300 transition-all border border-cyan-500/20 hover:border-cyan-500/50 text-[10px] font-mono uppercase tracking-widest hover:shadow-[0_0_14px_rgba(34,211,238,0.2)] active:scale-95 hover:scale-[1.02]"
                      >
                        <RefreshCw className="w-3.5 h-3.5" />
                        RE-SCAN
                      </button>
                      <button 
                        onClick={() => deleteHistoryItem(item.url)}
                        className="py-2 px-4 flex items-center justify-center gap-2 rounded-lg bg-rose-950/30 hover:bg-rose-900/50 text-rose-400 hover:text-rose-300 transition-all border border-rose-500/20 hover:border-rose-500/50 text-[10px] font-mono uppercase tracking-widest hover:shadow-[0_0_14px_rgba(244,63,94,0.25)] active:scale-95 hover:scale-[1.02]"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                        DELETE
                      </button>
                    </div>
                  </div>
                );
              })
            )}
          </div>
          
          {/* Footer */}
          <div className="p-4 border-t border-white/5 bg-black/40 text-center">
            <p className="text-[10px] font-mono text-slate-500 uppercase tracking-widest">
              Showing {history.length} most recent record{history.length !== 1 ? 's' : ''} • Sorted by latest
            </p>
          </div>
        </div>
        
        {/* Backdrop overlay */}
        {showHistory && (
          <div 
            className="fixed inset-0 bg-black/60 backdrop-blur-sm z-40 animate-in fade-in duration-300" 
            onClick={() => setShowHistory(false)}
          ></div>
        )}

      </div>
    </>
  );
}
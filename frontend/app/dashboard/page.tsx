"use client";

import { useEffect, useState, Suspense, useMemo, useCallback } from "react";
import { useAuth } from "../context/AuthContext"; 
import { useRouter, useSearchParams } from "next/navigation";
import Link from "next/link";
import { 
  ShieldAlert, ShieldCheck, Activity, AlertTriangle, Server, Search, Filter, 
  ChevronLeft, ChevronRight, Network, Ban, LogOut, UploadCloud, Info, Clock, Sparkles, ArrowLeft, X 
} from "lucide-react";
import { 
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, 
  PieChart, Pie, Cell, Legend, AreaChart, Area 
} from 'recharts';

interface Log {
  id: number;
  log_time: string;
  user_login: string;
  source_ip: string;
  url: string;
  action: string;
  risk_score: number;
  is_anomaly: boolean;
  ai_explanation: string | null;
  bytes_sent: number;
  bytes_received: number;
  threat_name: string;
  confidence_score: number | null;
}

const InfoTooltip = ({ text }: { text: string }) => (
  <div className="relative group cursor-help ml-2">
    <Info className="w-3.5 h-3.5 text-slate-400 hover:text-blue-500 transition-colors" />
    <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 hidden group-hover:block w-48 bg-slate-800 text-white text-xs p-2.5 rounded shadow-lg z-50 text-center font-normal normal-case leading-relaxed">
      {text}
      <div className="absolute top-full left-1/2 -translate-x-1/2 border-4 border-transparent border-t-slate-800"></div>
    </div>
  </div>
);

function DashboardContent() {
  const { token, logout, isAuthLoading } = useAuth();
  const router = useRouter();
  const searchParams = useSearchParams(); 
  const uploadId = searchParams.get("upload_id");

  const [logs, setLogs] = useState<Log[]>([]);
  const [loading, setLoading] = useState(true);
  
  const [filename, setFilename] = useState<string | null>(null);

  const [searchTerm, setSearchTerm] = useState("");
  const [filterAction, setFilterAction] = useState("All");
  const [filterAnomaly, setFilterAnomaly] = useState("All");
  
  const [rangeMinPct, setRangeMinPct] = useState(0);
  const [rangeMaxPct, setRangeMaxPct] = useState(100);

  const [chartThreatFilter, setChartThreatFilter] = useState<string | null>(null);
  const [chartActionFilter, setChartActionFilter] = useState<string | null>(null);
  
  const [currentPage, setCurrentPage] = useState(1);
  const [rowsPerPage, setRowsPerPage] = useState(10);

  useEffect(() => {
    if (!isAuthLoading && token === null) router.push("/login");
  }, [token, router, isAuthLoading]);

  useEffect(() => {
    if (!token || !uploadId) return;
    
    fetch("http://127.0.0.1:8000/api/history", {
      headers: { "Authorization": `Bearer ${token}` },
      cache: "no-store"
    })
      .then((res) => res.json())
      .then((data) => {
        const record = data.find((r: { id: number; filename: string }) => r.id === Number(uploadId));
        if (record) {
          setFilename(record.filename);
        }
      })
      .catch((err) => console.error("Failed to fetch filename:", err));
  }, [token, uploadId]);

  useEffect(() => {
    if (!token) return;
    const fetchUrl = uploadId ? `http://127.0.0.1:8000/api/logs?upload_id=${uploadId}` : "http://127.0.0.1:8000/api/logs";

    fetch(fetchUrl, {
      headers: { "Authorization": `Bearer ${token}`, "Content-Type": "application/json" }
    })
      .then((res) => {
        if (!res.ok) throw new Error("Unauthorized");
        return res.json();
      })
      .then((data) => {
        setLogs(data);
        setLoading(false);
      })
      .catch((err) => {
        setLoading(false);
        if (err.message === "Unauthorized") logout();
      });
  }, [token, logout, uploadId]);

  useEffect(() => {
    const t = setTimeout(() => {
      setRangeMinPct(0);
      setRangeMaxPct(100);
    }, 0);
    return () => clearTimeout(t);
  }, [logs]);

  useEffect(() => {
    const t = setTimeout(() => {
      setCurrentPage(1);
    }, 0);
    return () => clearTimeout(t);
  }, [searchTerm, filterAction, filterAnomaly, rowsPerPage, rangeMinPct, rangeMaxPct, chartThreatFilter, chartActionFilter]);

  // ==========================================
  // 🧠 CORE DATA PROCESSING & TIME SLICING
  // ==========================================
  
  const globalMinMs = useMemo(() => logs.length > 0 ? Math.min(...logs.map(l => new Date(l.log_time).getTime())) : 0, [logs]);
  const globalMaxMs = useMemo(() => logs.length > 0 ? Math.max(...logs.map(l => new Date(l.log_time).getTime())) : 0, [logs]);

  const timeFilteredLogs = useMemo(() => {
    if (logs.length === 0) return logs;
    const startMs = globalMinMs + (rangeMinPct / 100) * (globalMaxMs - globalMinMs);
    const endMs = globalMinMs + (rangeMaxPct / 100) * (globalMaxMs - globalMinMs);
    return logs.filter(l => {
      const t = new Date(l.log_time).getTime();
      return t >= startMs && t <= endMs;
    });
  }, [logs, rangeMinPct, rangeMaxPct, globalMinMs, globalMaxMs]);

  const filteredLogs = useMemo(() => {
    return timeFilteredLogs.filter(log => {
      const matchesSearch = log.user_login.toLowerCase().includes(searchTerm.toLowerCase()) || 
                            log.url.toLowerCase().includes(searchTerm.toLowerCase()) ||
                            log.source_ip.includes(searchTerm);
      const matchesAction = filterAction === "All" || log.action === filterAction;
      const matchesAnomaly = filterAnomaly === "All" ? true : filterAnomaly === "Anomalies" ? log.is_anomaly : !log.is_anomaly;
      
      // FIXED LOGIC: Strictly trust the backend's exact threat_name and action
      const matchesChartAction = chartActionFilter ? log.action === chartActionFilter : true;
      const matchesChartThreat = chartThreatFilter ? log.threat_name === chartThreatFilter : true;

      return matchesSearch && matchesAction && matchesAnomaly && matchesChartAction && matchesChartThreat;
    });
  }, [timeFilteredLogs, searchTerm, filterAction, filterAnomaly, chartActionFilter, chartThreatFilter]);

  const { minTimeStr, maxTimeStr } = useMemo(() => {
    if (timeFilteredLogs.length === 0) return { minTimeStr: "N/A", maxTimeStr: "N/A" };
    const times = timeFilteredLogs.map(l => new Date(l.log_time).getTime());
    const minD = new Date(Math.min(...times));
    const maxD = new Date(Math.max(...times));
    const options: Intl.DateTimeFormatOptions = { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' };
    return {
      minTimeStr: minD.toLocaleString('en-US', options),
      maxTimeStr: maxD.toLocaleString('en-US', options)
    };
  }, [timeFilteredLogs]);

  const totalEvents = timeFilteredLogs.length;
  const anomalyCount = timeFilteredLogs.filter(log => log.is_anomaly).length;
  const uniqueIps = new Set(timeFilteredLogs.map(log => log.source_ip)).size;
  const blockedCount = timeFilteredLogs.filter(log => log.action === "Blocked").length;

  const actionData = [
    { name: 'Allowed', value: totalEvents - blockedCount, color: '#10b981' }, 
    { name: 'Blocked', value: blockedCount, color: '#f59e0b' } 
  ];

  const timelineData = useMemo(() => {
    const map = new Map<string, { time: string, events: number, anomalies: number }>();
    timeFilteredLogs.forEach(log => {
      const d = new Date(log.log_time);
      const bucket = `${d.getMonth()+1}/${d.getDate()} ${d.getHours().toString().padStart(2,'0')}:${d.getMinutes().toString().padStart(2,'0')}`;
      if (!map.has(bucket)) map.set(bucket, { time: bucket, events: 0, anomalies: 0 });
      const entry = map.get(bucket)!;
      entry.events += 1;
      if (log.is_anomaly) entry.anomalies += 1;
    });
    return Array.from(map.values()).sort((a, b) => a.time.localeCompare(b.time));
  }, [timeFilteredLogs]);

  const attackTypeData = useMemo(() => {
    const map = new Map<string, number>();
    timeFilteredLogs.forEach(log => {
      // FIXED LOGIC: Only count explicitly named threats provided by the Python backend
      if (log.is_anomaly && log.threat_name && log.threat_name !== "None") {
        map.set(log.threat_name, (map.get(log.threat_name) || 0) + 1);
      }
    });
    return Array.from(map.entries()).map(([name, value]) => ({ name, value, color: '#ef4444' })).sort((a,b) => b.value - a.value);
  }, [timeFilteredLogs]);

  const topThreat = attackTypeData.length > 0 ? attackTypeData[0].name : "None";
  const dynamicAiSummary = totalEvents === 0 
    ? "No data available in the current time range or filter selection." 
    : `AI Analysis engine processed ${totalEvents} network events. Detected ${anomalyCount} anomalies requiring attention. The dominant threat vector is identified as '${topThreat}'. ${blockedCount} suspicious connections were halted by firewall rules.`;

  const totalPages = Math.ceil(filteredLogs.length / rowsPerPage);
  const startIndex = (currentPage - 1) * rowsPerPage;
  const paginatedLogs = filteredLogs.slice(startIndex, startIndex + rowsPerPage);

  const formatSliderTime = useCallback((pct: number) => {
    if (globalMinMs === 0 && globalMaxMs === 0) return "";
    const ms = globalMinMs + (pct / 100) * (globalMaxMs - globalMinMs);
    return new Date(ms).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
  }, [globalMinMs, globalMaxMs]);

  if (isAuthLoading || !token) return null;

  return (
    <div className="min-h-screen bg-slate-50 p-8 text-slate-800 font-sans">
      
      <style dangerouslySetInnerHTML={{__html: `
        input[type="range"].dual-slider {
          -webkit-appearance: none; appearance: none; background: transparent; pointer-events: none;
        }
        input[type="range"].dual-slider::-webkit-slider-thumb {
          pointer-events: auto; -webkit-appearance: none; height: 18px; width: 18px; border-radius: 50%; background: white; border: 2px solid #2563eb; cursor: pointer; box-shadow: 0 1px 4px rgba(0,0,0,0.3); transition: background 0.1s;
        }
        input[type="range"].dual-slider::-moz-range-thumb {
          pointer-events: auto; height: 18px; width: 18px; border-radius: 50%; background: white; border: 2px solid #2563eb; cursor: pointer; box-shadow: 0 1px 4px rgba(0,0,0,0.3);
        }
        input[type="range"].dual-slider::-webkit-slider-thumb:hover { background: #eff6ff; }
      `}} />

      <div className="max-w-[1400px] mx-auto space-y-6">
        
        {/* 1. CLEAN HEADER AREA */}
        <div className="flex flex-col md:flex-row items-center justify-between bg-white p-6 rounded-xl border border-slate-200 shadow-sm gap-4">
          <div className="flex items-center gap-4">
            <Link href="/" className="p-2 bg-slate-50 hover:bg-slate-100 text-slate-600 rounded-lg transition-colors border border-slate-200 shadow-sm">
              <ArrowLeft className="w-6 h-6" />
            </Link>
            <div>
              <h1 className="text-3xl font-bold text-slate-900 flex items-center gap-3">
                <Activity className="text-blue-600 w-8 h-8" />
                SOC Analyst Dashboard
              </h1>
              <div className="text-slate-500 mt-1 text-sm font-medium">
                {uploadId ? `Viewing ${filename ? filename : `Upload #${uploadId}`}` : "Real-time threat detection"}
              </div>
            </div>
          </div>
          
          <div className="flex items-center gap-3">
            <Link href="/" className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors font-medium text-sm shadow-sm whitespace-nowrap">
              <UploadCloud className="w-4 h-4" /> Upload New
            </Link>
            <button onClick={logout} className="flex items-center gap-2 px-4 py-2 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-lg transition-colors font-medium text-sm border border-slate-200 whitespace-nowrap">
              <LogOut className="w-4 h-4" /> Sign Out
            </button>
          </div>
        </div>

        {/* 2. DEDICATED TIME RANGE CONTROL BLOCK */}
        {!loading && logs.length > 0 && (
          <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-sm flex flex-col xl:flex-row items-center justify-between gap-6">
            
            <div className="flex items-center gap-3 text-slate-700 font-medium whitespace-nowrap w-full xl:w-auto">
              <div className="p-2.5 bg-blue-50 text-blue-600 rounded-lg">
                <Clock className="w-5 h-5" />
              </div>
              <div>
                <div className="text-[11px] text-slate-400 uppercase tracking-wider font-bold mb-0.5">Selected Timeframe</div>
                <div className="text-[15px] font-semibold text-slate-800">{minTimeStr} <span className="text-slate-400 font-normal mx-1">—</span> {maxTimeStr}</div>
              </div>
            </div>

            <div className="flex flex-col items-center justify-center w-full max-w-3xl">
              <div className="flex justify-between w-full text-[10px] font-bold text-slate-500 mb-2 uppercase tracking-wider">
                <span className="bg-slate-100 px-2 py-0.5 rounded">{formatSliderTime(rangeMinPct)}</span>
                <span className="text-slate-400 font-medium normal-case">Drag handles to slice timeline</span>
                <span className="bg-slate-100 px-2 py-0.5 rounded">{formatSliderTime(rangeMaxPct)}</span>
              </div>
              <div className="relative w-full h-3 bg-slate-100 border border-slate-200 rounded-full shadow-inner">
                <div className="absolute top-0 bottom-0 bg-blue-500 rounded-full" style={{ left: `${rangeMinPct}%`, right: `${100 - rangeMaxPct}%` }} />
                <input type="range" min="0" max="100" step="1" value={rangeMinPct} onChange={(e) => setRangeMinPct(Math.min(Number(e.target.value), rangeMaxPct - 1))} className="dual-slider absolute w-full top-1/2 -translate-y-1/2 z-10" />
                <input type="range" min="0" max="100" step="1" value={rangeMaxPct} onChange={(e) => setRangeMaxPct(Math.max(Number(e.target.value), rangeMinPct + 1))} className="dual-slider absolute w-full top-1/2 -translate-y-1/2 z-20" />
              </div>
            </div>

          </div>
        )}

        {loading ? (
          <div className="text-center py-20 text-slate-500 animate-pulse font-medium text-lg">Loading secure logs...</div>
        ) : (
          <>
            {/* 3. AI SUMMARY */}
            <div className="bg-gradient-to-r from-slate-900 to-slate-800 rounded-xl shadow-lg border border-slate-700 p-5 text-white flex items-start gap-4">
              <div className="p-3 bg-blue-500/20 rounded-lg text-blue-400 mt-1">
                <Sparkles className="w-6 h-6" />
              </div>
              <div>
                <h2 className="text-lg font-bold text-white flex items-center gap-2">AI Summary</h2>
                <p className="text-slate-300 mt-1 text-sm leading-relaxed max-w-4xl">{dynamicAiSummary}</p>
              </div>
            </div>

            {/* 4. KPI CARDS */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-sm flex items-center gap-4">
                <div className="p-3 bg-blue-100 rounded-lg text-blue-700"><Server className="w-6 h-6" /></div>
                <div>
                  <div className="text-slate-500 text-xs font-bold uppercase tracking-wider flex items-center">
                    Total Events <InfoTooltip text="The total number of raw network requests processed in this time frame." />
                  </div>
                  <p className="text-2xl font-bold text-slate-800">{totalEvents}</p>
                </div>
              </div>
              <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-sm flex items-center gap-4">
                <div className="p-3 bg-indigo-100 rounded-lg text-indigo-700"><Network className="w-6 h-6" /></div>
                <div>
                  <div className="text-slate-500 text-xs font-bold uppercase tracking-wider flex items-center">
                    Unique IPs <InfoTooltip text="The number of distinct source IP addresses communicating with the network." />
                  </div>
                  <p className="text-2xl font-bold text-slate-800">{uniqueIps}</p>
                </div>
              </div>
              <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-sm flex items-center gap-4">
                <div className="p-3 bg-red-100 rounded-lg text-red-700"><AlertTriangle className="w-6 h-6" /></div>
                <div>
                  <div className="text-slate-500 text-xs font-bold uppercase tracking-wider flex items-center">
                    Critical Anomalies <InfoTooltip text="Events flagged by the AI engine as highly suspicious or malicious behavior." />
                  </div>
                  <p className="text-2xl font-bold text-red-600">{anomalyCount}</p>
                </div>
              </div>
              <div className="bg-white p-5 rounded-xl border border-slate-200 shadow-sm flex items-center gap-4">
                <div className="p-3 bg-orange-100 rounded-lg text-orange-700"><Ban className="w-6 h-6" /></div>
                <div>
                  <div className="text-slate-500 text-xs font-bold uppercase tracking-wider flex items-center">
                    Blocked Traffic <InfoTooltip text="Requests that were automatically dropped or blocked by firewall rules." />
                  </div>
                  <p className="text-2xl font-bold text-orange-600">{blockedCount}</p>
                </div>
              </div>
            </div>

            <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm">
              <h2 className="text-lg font-bold text-slate-800 mb-4">Traffic & Anomaly Timeline</h2>
              <div className="h-72 w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={timelineData}>
                    <defs>
                      <linearGradient id="colorEvents" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3}/><stop offset="95%" stopColor="#3b82f6" stopOpacity={0}/></linearGradient>
                      <linearGradient id="colorAnomalies" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="#ef4444" stopOpacity={0.5}/><stop offset="95%" stopColor="#ef4444" stopOpacity={0}/></linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#e2e8f0" />
                    <XAxis dataKey="time" stroke="#64748b" fontSize={11} tickLine={false} axisLine={false} minTickGap={30} />
                    <YAxis stroke="#64748b" fontSize={11} tickLine={false} axisLine={false} />
                    <Tooltip contentStyle={{ borderRadius: '8px', border: 'none', boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)' }} />
                    <Legend verticalAlign="top" height={36} />
                    <Area type="monotone" dataKey="events" name="Normal Events" stroke="#3b82f6" strokeWidth={2} fillOpacity={1} fill="url(#colorEvents)" />
                    <Area type="monotone" dataKey="anomalies" name="Detected Anomalies" stroke="#ef4444" strokeWidth={2} fillOpacity={1} fill="url(#colorAnomalies)" />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              
              <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm lg:col-span-2">
                <h2 className="text-lg font-bold text-slate-800 mb-4 flex items-center gap-2">
                  Anomaly Attack Type Breakdown
                  <span className="text-xs font-normal text-slate-400 bg-slate-100 px-2 py-1 rounded">(Click a bar to filter table)</span>
                </h2>
                <div className="h-64 w-full">
                  {attackTypeData.length > 0 ? (
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={attackTypeData} margin={{ top: 10, right: 30, left: 0, bottom: 0 }}>
                        <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#e2e8f0" />
                        <XAxis dataKey="name" stroke="#64748b" fontSize={11} tickLine={false} axisLine={false} />
                        <YAxis stroke="#64748b" fontSize={11} tickLine={false} axisLine={false} />
                        <Tooltip cursor={{ fill: '#fee2e2' }} contentStyle={{ borderRadius: '8px', border: 'none', boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)' }} />
                        <Bar 
                          dataKey="value" 
                          name="Occurrences" 
                          fill="#ef4444" 
                          radius={[4, 4, 0, 0]} 
                          barSize={40} 
                          onClick={(data: { name?: string }) => setChartThreatFilter(data?.name || null)} 
                          className="cursor-pointer hover:opacity-80 transition-opacity focus:outline-none"
                          activeBar={{ stroke: 'none', fill: '#dc2626' }} 
                        />
                      </BarChart>
                    </ResponsiveContainer>
                  ) : (
                    <div className="h-full flex items-center justify-center text-slate-400">No anomalies detected.</div>
                  )}
                </div>
              </div>

              <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm lg:col-span-1 flex flex-col items-center">
                <h2 className="text-lg font-bold text-slate-800 self-start mb-2 flex items-center gap-2">
                  Traffic Disposition
                  <span className="text-xs font-normal text-slate-400 bg-slate-100 px-2 py-1 rounded">(Click slice)</span>
                </h2>
                <div className="h-64 w-full">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie data={actionData} innerRadius={60} outerRadius={80} paddingAngle={5} dataKey="value">
                        {actionData.map((entry, index) => (
                          <Cell 
                            key={`cell-${index}`} 
                            fill={entry.color} 
                            onClick={() => setChartActionFilter(entry.name)} 
                            className="cursor-pointer hover:opacity-80 transition-opacity focus:outline-none"
                            style={{ outline: 'none' }} 
                          />
                        ))}
                      </Pie>
                      <Tooltip />
                      <Legend verticalAlign="bottom" height={36} />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
              </div>

            </div>

            <div className="bg-white rounded-xl shadow-sm border border-slate-200 overflow-hidden">
              <div className="p-4 border-b border-slate-200 bg-slate-50 flex flex-col gap-4">
                {(chartThreatFilter || chartActionFilter) && (
                  <div className="flex items-center gap-3 p-3 bg-blue-50 border border-blue-200 rounded-lg">
                    <span className="text-sm font-semibold text-blue-800">Active Chart Filters:</span>
                    {chartThreatFilter && (
                      <span className="flex items-center gap-1 bg-white border border-blue-200 text-blue-700 text-xs font-medium px-2 py-1 rounded-full shadow-sm">
                        Threat: {chartThreatFilter}
                        <button onClick={() => setChartThreatFilter(null)} className="hover:text-red-500 ml-1"><X className="w-3 h-3" /></button>
                      </span>
                    )}
                    {chartActionFilter && (
                      <span className="flex items-center gap-1 bg-white border border-blue-200 text-blue-700 text-xs font-medium px-2 py-1 rounded-full shadow-sm">
                        Action: {chartActionFilter}
                        <button onClick={() => setChartActionFilter(null)} className="hover:text-red-500 ml-1"><X className="w-3 h-3" /></button>
                      </span>
                    )}
                    <button onClick={() => { setChartThreatFilter(null); setChartActionFilter(null); }} className="text-xs text-blue-600 hover:text-blue-800 underline ml-auto font-medium">
                      Clear All Filters
                    </button>
                  </div>
                )}

                <div className="flex flex-col md:flex-row gap-4 items-center justify-between">
                  <div className="relative w-full md:w-96">
                    <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-400" />
                    <input type="text" placeholder="Search by User, URL, or IP..." className="w-full pl-9 pr-4 py-2 border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm" value={searchTerm} onChange={(e) => setSearchTerm(e.target.value)} />
                  </div>
                  
                  <div className="flex gap-3 w-full md:w-auto">
                    <div className="flex items-center gap-2">
                      <Filter className="h-4 w-4 text-slate-400" />
                      <select className="border border-slate-200 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 bg-white" value={filterAction} onChange={(e) => setFilterAction(e.target.value)}>
                        <option value="All">All Actions</option>
                        <option value="Allowed">Allowed</option>
                        <option value="Blocked">Blocked</option>
                      </select>
                    </div>
                    <select className="border border-slate-200 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 bg-white" value={filterAnomaly} onChange={(e) => setFilterAnomaly(e.target.value)}>
                      <option value="All">All Traffic</option>
                      <option value="Anomalies">Anomalies Only</option>
                      <option value="Normal">Normal Only</option>
                    </select>
                  </div>
                </div>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead className="bg-slate-100 text-slate-600 border-b border-slate-200">
                    <tr>
                      <th className="p-4 font-semibold">Timestamp</th>
                      <th className="p-4 font-semibold">Source IP</th>
                      <th className="p-4 font-semibold">User</th>
                      <th className="p-4 font-semibold">Target URL</th>
                      <th className="p-4 font-semibold">Data Volume</th>
                      <th className="p-4 font-semibold">Threat Intel</th>
                      <th className="p-4 font-semibold text-center">Action</th>
                      <th className="p-4 font-semibold w-1/4">AI Analysis</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {paginatedLogs.length > 0 ? (
                      paginatedLogs.map((log) => (
                        <tr key={log.id} className={`hover:bg-slate-50 transition-colors ${log.is_anomaly ? 'bg-red-50/30' : ''}`}>
                          <td className="p-4 text-slate-500 whitespace-nowrap">{new Date(log.log_time).toLocaleString()}</td>
                          <td className="p-4 font-mono text-slate-600">{log.source_ip}</td>
                          <td className="p-4 font-medium text-slate-700">{log.user_login}</td>
                          <td className="p-4 text-slate-500 truncate max-w-[150px]" title={log.url}>{log.url}</td>
                          <td className="p-4 text-xs">
                            <span className="text-blue-600 font-medium">↑ {(log.bytes_sent / 1024).toFixed(1)} KB</span><br/>
                            <span className="text-emerald-600 font-medium">↓ {(log.bytes_received / 1024).toFixed(1)} KB</span>
                          </td>
                          <td className="p-4">
                            {log.threat_name !== "None" && log.threat_name !== null ? (
                              <span className="inline-block px-2.5 py-1 bg-red-50 text-red-700 text-[11px] leading-snug rounded-md font-semibold border border-red-200 text-center">
                                {log.threat_name}
                              </span>
                            ) : <span className="text-slate-400 text-xs">Clean</span>}
                          </td>
                          <td className="p-4 text-center">
                            <span className={`px-3 py-1 rounded-full text-xs font-semibold ${log.action === "Allowed" ? "bg-emerald-100 text-emerald-700" : "bg-orange-100 text-orange-700"}`}>
                              {log.action}
                            </span>
                          </td>
                          <td className="p-4">
                            {log.is_anomaly ? (
                              <div className="flex items-start gap-2 text-red-700">
                                <ShieldAlert className="w-5 h-5 flex-shrink-0 mt-0.5" />
                                <div>
                                  <p className="font-bold text-red-800">Critical Anomaly Detected</p>
                                  <p className="text-xs mt-1 text-red-600/90 leading-relaxed whitespace-pre-wrap">{log.ai_explanation}</p>
                                </div>
                              </div>
                            ) : (
                              <div className="flex items-center gap-2 text-slate-400">
                                <ShieldCheck className="w-4 h-4" />
                                <span className="text-xs font-medium">Normal Behavior</span>
                              </div>
                            )}
                          </td>
                        </tr>
                      ))
                    ) : (
                      <tr><td colSpan={8} className="p-12 text-center text-slate-500">No logs match your filters.</td></tr>
                    )}
                  </tbody>
                </table>
              </div>
              
              <div className="p-4 border-t border-slate-200 bg-slate-50 flex flex-col md:flex-row items-center justify-between text-sm text-slate-600">
                <div className="flex items-center gap-2 mb-4 md:mb-0">
                  <span>Show</span>
                  <select className="border border-slate-200 rounded px-2 py-1 bg-white focus:outline-none focus:ring-2 focus:ring-blue-500" value={rowsPerPage} onChange={(e) => setRowsPerPage(Number(e.target.value))}>
                    <option value={5}>5</option><option value={10}>10</option><option value={20}>20</option><option value={50}>50</option>
                  </select>
                  <span>entries</span>
                  <span className="ml-4 text-slate-400">
                    Showing {filteredLogs.length === 0 ? 0 : startIndex + 1} to {Math.min(startIndex + rowsPerPage, filteredLogs.length)} of {filteredLogs.length} logs
                  </span>
                </div>
                <div className="flex items-center gap-1">
                  <button onClick={() => setCurrentPage(prev => Math.max(prev - 1, 1))} disabled={currentPage === 1} className="p-1.5 rounded border border-slate-200 bg-white text-slate-600 hover:bg-slate-100 disabled:opacity-50 disabled:cursor-not-allowed"><ChevronLeft className="w-4 h-4" /></button>
                  <span className="px-4 py-1.5 font-medium">Page {currentPage} of {totalPages || 1}</span>
                  <button onClick={() => setCurrentPage(prev => Math.min(prev + 1, totalPages))} disabled={currentPage === totalPages || totalPages === 0} className="p-1.5 rounded border border-slate-200 bg-white text-slate-600 hover:bg-slate-100 disabled:opacity-50 disabled:cursor-not-allowed"><ChevronRight className="w-4 h-4" /></button>
                </div>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

export default function DashboardPage() {
  return (
    <Suspense fallback={<div className="min-h-screen bg-slate-50 flex items-center justify-center text-slate-500 font-medium text-lg animate-pulse">Loading Secure Dashboard...</div>}>
      <DashboardContent />
    </Suspense>
  );
}
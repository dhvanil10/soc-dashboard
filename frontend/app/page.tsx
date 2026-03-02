"use client";

import { useState, useEffect } from "react";
import { useAuth } from "./context/AuthContext";
import { useRouter } from "next/navigation";
import { UploadCloud, FileText, CheckCircle, AlertTriangle, Loader2, ArrowRight, LogOut, History, ShieldAlert } from "lucide-react";
import Link from "next/link";

interface UploadRecord {
  id: number;
  filename: string;
  upload_date: string;
  total_events: number;
  anomalies_found: number;
}

export default function HomeUploadPage() {
  const { token, logout, isAuthLoading } = useAuth();
  const router = useRouter();
  
  const [file, setFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState<{ text: string; type: "success" | "error", uploadId?: number } | null>(null);
  
  const [history, setHistory] = useState<UploadRecord[]>([]);
  const [loadingHistory, setLoadingHistory] = useState(true);

  useEffect(() => {
    if (!isAuthLoading && token === null) {
      router.push("/login");
    }
  }, [token, router, isAuthLoading]);

  const fetchHistory = async () => {
    if (!token) return;
    try {
      const res = await fetch("http://127.0.0.1:8000/api/history", {
        headers: { "Authorization": `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setHistory(data);
      }
    } catch (err) {
      console.error("Failed to load history", err);
    } finally {
      setLoadingHistory(false);
    }
  };

  useEffect(() => {
    fetchHistory();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token]);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      setFile(e.target.files[0]);
      setMessage(null);
    }
  };

  const handleUpload = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!file) return setMessage({ text: "Please select a log file first.", type: "error" });

    setLoading(true);
    setMessage(null);

    const formData = new FormData();
    formData.append("file", file);

    try {
      const response = await fetch("http://127.0.0.1:8000/api/upload", {
        method: "POST",
        headers: { "Authorization": `Bearer ${token}` },
        body: formData,
      });

      const data = await response.json();

      if (!response.ok) {
        if (response.status === 401) {
          logout();
          throw new Error("Session expired. Please log in again.");
        }
        throw new Error(data.detail || "Upload failed");
      }

      setMessage({ text: data.message || "Logs processed successfully!", type: "success", uploadId: data.upload_id });
      setFile(null); 
      
      const fileInput = document.getElementById('file-upload') as HTMLInputElement;
      if (fileInput) fileInput.value = '';

      // REFRESH THE HISTORY TABLE IMMEDIATELY!
      fetchHistory();

    } catch (err) {
      if (err instanceof Error) {
        setMessage({ text: err.message, type: "error" });
      } else {
        setMessage({ text: "An unexpected error occurred.", type: "error" });
      }
    } finally {
      setLoading(false);
    }
  };

  if (isAuthLoading || !token) return null; 

  return (
    <div className="min-h-screen bg-slate-50 p-8 text-slate-800 font-sans flex flex-col items-center">
      <div className="w-full max-w-4xl space-y-8">
        
        {/* Top Navigation */}
        <div className="flex justify-between items-center">
          <button onClick={logout} className="flex items-center gap-2 text-sm font-medium text-slate-500 hover:text-red-600 transition-colors">
            <LogOut className="w-4 h-4" /> Sign Out
          </button>
          <Link href="/dashboard" className="flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-900 text-white rounded-lg transition-colors font-medium text-sm shadow-sm">
            View All Logs <ArrowRight className="w-4 h-4" />
          </Link>
        </div>

        {/* Upload Box */}
        <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
          <div className="p-6 border-b border-slate-200 bg-slate-50">
            <h1 className="text-xl font-bold text-slate-800">Upload Network Logs</h1>
            <p className="text-sm text-slate-500 mt-1">Upload raw Zscaler or firewall logs to generate AI threat reports.</p>
          </div>

          <div className="p-6">
            <form onSubmit={handleUpload}>
              <div className="w-full flex justify-center items-center">
                <label htmlFor="file-upload" className={`flex flex-col items-center justify-center w-full h-48 border-2 border-dashed rounded-lg cursor-pointer transition-colors ${file ? 'border-blue-400 bg-blue-50' : 'border-slate-300 bg-slate-50 hover:bg-slate-100 hover:border-slate-400'}`}>
                  <div className="flex flex-col items-center justify-center pt-5 pb-6">
                    {file ? <FileText className="w-12 h-12 text-blue-500 mb-4" /> : <UploadCloud className="w-12 h-12 text-slate-400 mb-4" />}
                    <p className="mb-2 text-sm text-slate-600 font-medium">
                      {file ? file.name : <><span className="text-blue-600">Click to upload</span> or drag and drop</>}
                    </p>
                    <p className="text-xs text-slate-500">
                      {file ? `${(file.size / 1024).toFixed(2)} KB` : "TXT, CSV, or LOG files (Max 10MB)"}
                    </p>
                  </div>
                  <input id="file-upload" type="file" className="hidden" accept=".txt,.csv,.log" onChange={handleFileChange} disabled={loading} />
                </label>
              </div>

              {message && (
                <div className={`mt-6 p-4 rounded-lg flex flex-col gap-3 ${message.type === 'success' ? 'bg-emerald-50 border border-emerald-200 text-emerald-800' : 'bg-red-50 border border-red-200 text-red-800'}`}>
                  <div className="flex items-start gap-3">
                    {message.type === 'success' ? <CheckCircle className="w-5 h-5 flex-shrink-0 mt-0.5" /> : <AlertTriangle className="w-5 h-5 flex-shrink-0 mt-0.5" />}
                    <p className="text-sm font-medium">{message.text}</p>
                  </div>
                  {message.type === 'success' && message.uploadId && (
                    <Link href={`/dashboard?upload_id=${message.uploadId}`} className="inline-flex items-center justify-center px-4 py-2 mt-2 bg-emerald-600 hover:bg-emerald-700 text-white text-sm font-medium rounded-md transition-colors w-fit">
                      View Report <ArrowRight className="w-4 h-4 ml-2" />
                    </Link>
                  )}
                </div>
              )}

              <button type="submit" disabled={!file || loading} className={`mt-6 w-full flex items-center justify-center gap-2 py-3 px-4 rounded-lg font-semibold text-white transition-all ${!file || loading ? 'bg-slate-400 cursor-not-allowed' : 'bg-blue-600 hover:bg-blue-700 shadow-md hover:shadow-lg'}`}>
                {loading ? <><Loader2 className="w-5 h-5 animate-spin" /> Processing with AI...</> : <><UploadCloud className="w-5 h-5" /> Analyze File</>}
              </button>
            </form>
          </div>
        </div>

        {/* Upload History Table */}
        <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
          <div className="p-6 border-b border-slate-200 bg-slate-50 flex items-center gap-2">
            <History className="w-5 h-5 text-slate-500" />
            <h2 className="text-lg font-bold text-slate-800">Recent Uploads</h2>
          </div>
          
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="bg-slate-50 text-slate-500 border-b border-slate-200">
                <tr>
                  <th className="p-4 font-semibold">Filename</th>
                  <th className="p-4 font-semibold text-center">Total Events</th>
                  <th className="p-4 font-semibold text-center">Anomalies Found</th>
                  <th className="p-4 font-semibold text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {loadingHistory ? (
                  <tr><td colSpan={4} className="p-8 text-center text-slate-400 animate-pulse">Loading history...</td></tr>
                ) : history.length === 0 ? (
                  <tr><td colSpan={4} className="p-8 text-center text-slate-500">No logs uploaded yet.</td></tr>
                ) : (
                  history.map((record) => (
                    <tr key={record.id} className="hover:bg-slate-50 transition-colors">
                      <td className="p-4 font-medium text-slate-700">{record.filename}</td>
                      <td className="p-4 text-center text-slate-600">{record.total_events}</td>
                      <td className="p-4 text-center">
                        {record.anomalies_found > 0 ? (
                          <div className="flex justify-center">
                            <span className="flex items-center gap-1 text-red-600 font-semibold bg-red-50 px-2 py-1 rounded w-fit">
                              <ShieldAlert className="w-3 h-3" /> {record.anomalies_found}
                            </span>
                          </div>
                        ) : (
                          <span className="text-slate-400">0</span>
                        )}
                      </td>
                      <td className="p-4 text-right">
                        <Link href={`/dashboard?upload_id=${record.id}`} className="inline-flex items-center px-3 py-1.5 bg-blue-50 hover:bg-blue-100 text-blue-700 text-xs font-semibold rounded transition-colors border border-blue-200">
                          View Dashboard
                        </Link>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

      </div>
    </div>
  );
}
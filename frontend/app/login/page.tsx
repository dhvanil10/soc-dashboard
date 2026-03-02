"use client";
import { useState } from "react";
import { useAuth } from "../context/AuthContext"; // <--- FIXED: Correct relative path
import { ShieldAlert } from "lucide-react";

export default function LoginPage() {
  const [isLogin, setIsLogin] = useState(true);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const { login } = useAuth();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    const endpoint = isLogin ? "/api/login" : "/api/signup";
    
    try {
      const response = await fetch(`http://127.0.0.1:8000${endpoint}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || "Authentication failed");
      }

      if (isLogin) {
        login(data.access_token);
      } else {
        setIsLogin(true);
        setError("Account created! Please sign in.");
      }
    } catch (err) {
      // <--- FIXED: Removed the 'any' type to satisfy TypeScript
      if (err instanceof Error) {
        setError(err.message);
      } else {
        setError("An unexpected error occurred");
      }
    }
  };

  return (
    <div className="min-h-screen bg-slate-900 flex items-center justify-center p-4">
      <div className="bg-slate-800 p-8 rounded-xl shadow-2xl w-full max-w-md border border-slate-700">
        <div className="flex flex-col items-center mb-8">
          <ShieldAlert className="w-12 h-12 text-blue-500 mb-4" />
          <h1 className="text-2xl font-bold text-white">SOC Portal</h1>
          <p className="text-slate-400 text-sm mt-1">
            {isLogin ? "Authenticate to access dashboard" : "Register new analyst account"}
          </p>
        </div>

        {error && (
          <div className={`p-3 rounded mb-4 text-sm ${error.includes("created") ? 'bg-green-900/50 text-green-400 border border-green-800' : 'bg-red-900/50 text-red-400 border border-red-800'}`}>
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-slate-300 text-sm mb-1">Email Address</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full bg-slate-900 border border-slate-700 rounded px-3 py-2 text-white focus:outline-none focus:border-blue-500"
              required
            />
          </div>
          <div>
            <label className="block text-slate-300 text-sm mb-1">Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full bg-slate-900 border border-slate-700 rounded px-3 py-2 text-white focus:outline-none focus:border-blue-500"
              required
            />
          </div>
          <button
            type="submit"
            className="w-full bg-blue-600 hover:bg-blue-700 text-white font-semibold py-2 rounded transition-colors"
          >
            {isLogin ? "Sign In" : "Create Account"}
          </button>
        </form>

        <div className="mt-6 text-center">
          <button
            onClick={() => {
              setIsLogin(!isLogin);
              setError("");
            }}
            className="text-slate-400 hover:text-white text-sm transition-colors"
          >
            {isLogin ? "Need an account? Sign up" : "Already have an account? Sign in"}
          </button>
        </div>
      </div>
    </div>
  );
}
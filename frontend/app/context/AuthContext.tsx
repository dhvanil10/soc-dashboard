"use client";
import { createContext, useContext, useState, useEffect, ReactNode } from "react";
import { useRouter } from "next/navigation";

interface AuthContextType {
  token: string | null;
  isAuthLoading: boolean;
  login: (token: string) => void;
  logout: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [token, setToken] = useState<string | null>(null);
  const [isAuthLoading, setIsAuthLoading] = useState(true);
  const router = useRouter();

  useEffect(() => {
    // FIXED: setTimeout pushes this to the end of the queue, bypassing the Next.js warning!
    setTimeout(() => {
      const savedToken = localStorage.getItem("soc_token");
      if (savedToken) {
        setToken(savedToken);
      }
      setIsAuthLoading(false);
    }, 0);
  }, []);

  const login = (newToken: string) => {
    localStorage.setItem("soc_token", newToken);
    setToken(newToken);
    router.push("/"); 
  };

  const logout = () => {
    localStorage.removeItem("soc_token");
    setToken(null);
    router.push("/login"); 
  };

  return (
    <AuthContext.Provider value={{ token, isAuthLoading, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
};
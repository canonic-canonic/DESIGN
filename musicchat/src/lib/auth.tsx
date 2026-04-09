"use client";

import { createContext, useContext, useEffect, useState, useCallback, type ReactNode } from "react";
import { authGitHub, authMe } from "./api";
import { GITHUB_CLIENT_ID, TOKEN_KEY } from "./constants";
import type { User } from "./types";

interface AuthContextType {
  user: User | null;
  loading: boolean;
  login: () => void;
  logout: () => void;
  handleCallback: (code: string) => Promise<boolean>;
  refreshUser: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType>({
  user: null, loading: true, login: () => {}, logout: () => {},
  handleCallback: async () => false, refreshUser: async () => {},
});

function getToken(): string | null {
  try { return localStorage.getItem(TOKEN_KEY); } catch { return null; }
}

function setToken(t: string) {
  try { localStorage.setItem(TOKEN_KEY, t); } catch {}
}

function clearToken() {
  try { localStorage.removeItem(TOKEN_KEY); } catch {}
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  const refreshUser = useCallback(async () => {
    try {
      const data = await authMe();
      if (data.user) setUser(data.user);
    } catch {}
  }, []);

  useEffect(() => {
    const token = getToken();
    if (!token) { setLoading(false); return; }
    authMe()
      .then((data) => { if (data.user) setUser(data.user); })
      .catch(() => clearToken())
      .finally(() => setLoading(false));
  }, []);

  const handleCallback = useCallback(async (code: string): Promise<boolean> => {
    try {
      const data = await authGitHub(code);
      if (data.token) {
        setToken(data.token);
        setUser(data.user);
        return true;
      }
      return false;
    } catch { return false; }
  }, []);

  const login = useCallback(() => {
    const returnUrl = `${window.location.origin}/auth/callback/`;
    window.location.href =
      `https://github.com/login/oauth/authorize?client_id=${GITHUB_CLIENT_ID}` +
      `&redirect_uri=${encodeURIComponent(returnUrl)}&scope=read:user`;
  }, []);

  const logout = useCallback(() => {
    clearToken();
    setUser(null);
  }, []);

  return (
    <AuthContext.Provider value={{ user, loading, login, logout, handleCallback, refreshUser }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}

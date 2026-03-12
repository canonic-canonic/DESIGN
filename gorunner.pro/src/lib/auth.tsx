// Auth context — port of ~/.canonic/design/assets/js/auth.js
// GitHub OAuth → api.canonic.org/auth/github → session token → VAULT principal

"use client";

import {
  createContext,
  useContext,
  useEffect,
  useState,
  useCallback,
  type ReactNode,
} from "react";
import { authGitHub, authLogin, validateSession } from "./api";

const TOKEN_KEY = "canonic_session_token";

interface AuthUser {
  user: string; // GitHub username
  name?: string;
  avatar_url?: string;
}

interface RunnerIdentity {
  userId: string;
  role: string;
  principal?: string;
}

interface AuthContextType {
  user: AuthUser | null;
  identity: RunnerIdentity | null;
  loading: boolean;
  login: () => void;
  logout: () => void;
  handleCallback: (code: string) => Promise<boolean>;
}

const AuthContext = createContext<AuthContextType>({
  user: null,
  identity: null,
  loading: true,
  login: () => {},
  logout: () => {},
  handleCallback: async () => false,
});

// ── Token storage (mirrors auth.js) ──────────────────────────────
function getToken(): string | null {
  try {
    return localStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

function setToken(t: string) {
  try {
    localStorage.setItem(TOKEN_KEY, t);
  } catch {}
  try {
    document.cookie = `${TOKEN_KEY}=${encodeURIComponent(t)};path=/;max-age=604800;SameSite=Lax;Secure`;
  } catch {}
}

function clearToken() {
  try {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem("runner_user_id");
    localStorage.removeItem("runner_principal");
  } catch {}
  try {
    document.cookie = `${TOKEN_KEY}=;path=/;max-age=0`;
  } catch {}
}

// ── GitHub OAuth redirect ────────────────────────────────────────
// Matches auth.js pattern: GitHub → api.canonic.org/api/v1/auth/github/callback → 302 back with ?code=
// state= carries the return URL so the backend knows where to redirect
const GITHUB_CLIENT_ID =
  process.env.NEXT_PUBLIC_GITHUB_CLIENT_ID || "";

function redirectToGitHub() {
  const returnUrl = `${window.location.origin}/auth/callback`;
  const url =
    `https://github.com/login/oauth/authorize?client_id=${GITHUB_CLIENT_ID}` +
    `&scope=read:user,user:email` +
    `&state=${encodeURIComponent(returnUrl)}`;
  window.location.href = url;
}

// ── Provider ─────────────────────────────────────────────────────
export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [identity, setIdentity] = useState<RunnerIdentity | null>(null);
  const [loading, setLoading] = useState(true);

  // Resolve RUNNER identity after auth
  const resolveIdentity = useCallback(async (authUser: AuthUser) => {
    try {
      const data = await authLogin({
        name: authUser.name || authUser.user,
        github: authUser.user,
        role: "Requester",
      });
      if (data.user) {
        const id: RunnerIdentity = {
          userId: data.user.id,
          role: data.user.role,
          principal: data.principal,
        };
        setIdentity(id);
        localStorage.setItem("runner_user_id", data.user.id);
        if (data.principal)
          localStorage.setItem("runner_principal", data.principal);
      }
    } catch {
      // Silent — matches runner.js behavior
    }
  }, []);

  // Validate existing session on mount
  useEffect(() => {
    const token = getToken();
    if (!token) {
      setLoading(false);
      return;
    }

    validateSession()
      .then((data) => {
        if (data.user) {
          const u: AuthUser = {
            user: data.user,
            name: data.name,
            avatar_url: data.avatar_url,
          };
          setUser(u);
          resolveIdentity(u);
        }
      })
      .catch(() => {
        // Token might be a raw GitHub token — try direct validation
        const token = getToken();
        if (token?.startsWith("gho_")) {
          fetch("https://api.github.com/user", {
            headers: {
              Authorization: `Bearer ${token}`,
              Accept: "application/json",
            },
          })
            .then((r) => r.json())
            .then((gh: { login?: string; name?: string; avatar_url?: string }) => {
              if (gh.login) {
                const u: AuthUser = {
                  user: gh.login,
                  name: gh.name,
                  avatar_url: gh.avatar_url,
                };
                setUser(u);
                resolveIdentity(u);
              }
            })
            .catch(() => clearToken());
        }
      })
      .finally(() => setLoading(false));
  }, [resolveIdentity]);

  const handleCallback = useCallback(
    async (code: string): Promise<boolean> => {
      try {
        const data = await authGitHub(code);
        const token = data.session_token || data.access_token;
        if (token) {
          setToken(token);
          const u: AuthUser = {
            user: data.user || "",
            name: data.name,
            avatar_url: data.avatar_url,
          };
          setUser(u);
          await resolveIdentity(u);
          return true;
        }
        return false;
      } catch {
        return false;
      }
    },
    [resolveIdentity]
  );

  const logout = useCallback(() => {
    clearToken();
    setUser(null);
    setIdentity(null);
  }, []);

  return (
    <AuthContext.Provider
      value={{
        user,
        identity,
        loading,
        login: redirectToGitHub,
        logout,
        handleCallback,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}

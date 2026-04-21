import {
  createContext,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from "react";
import { whoami, ApiError, type WhoamiResponse } from "./api";

interface AuthCtx {
  user: WhoamiResponse;
}

const AuthContext = createContext<AuthCtx | null>(null);

export function useAuth(): AuthCtx {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth outside AuthProvider");
  return ctx;
}

const AUTH_URL = import.meta.env.VITE_AUTH_URL;

function redirectToLogin() {
  if (!AUTH_URL) {
    throw new Error(
      "VITE_AUTH_URL is not configured. Set it to the auth service origin (e.g. https://auth.drhayt.com).",
    );
  }
  const redirect = encodeURIComponent(window.location.href);
  window.location.href = `${AUTH_URL}/?redirect=${redirect}`;
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<WhoamiResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    whoami()
      .then(setUser)
      .catch((err) => {
        if (err instanceof ApiError && err.status === 401) {
          redirectToLogin();
          return;
        }
        setError(err instanceof Error ? err.message : String(err));
      })
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen text-zinc-500">
        Loading...
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center h-screen gap-3">
        <div className="text-red-600 font-medium">Failed to load session</div>
        <div className="text-sm text-zinc-500 max-w-md text-center">{error}</div>
        <button
          onClick={() => window.location.reload()}
          className="px-3 py-1.5 text-sm bg-zinc-900 text-white rounded hover:bg-zinc-700"
        >
          Retry
        </button>
      </div>
    );
  }

  if (!user) {
    return (
      <div className="flex items-center justify-center h-screen text-zinc-500">
        Redirecting to login...
      </div>
    );
  }

  return (
    <AuthContext.Provider value={{ user }}>{children}</AuthContext.Provider>
  );
}

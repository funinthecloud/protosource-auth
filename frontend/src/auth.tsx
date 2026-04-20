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

const AUTH_URL = import.meta.env.VITE_AUTH_URL ?? "";

function redirectToLogin() {
  const redirect = encodeURIComponent(window.location.href);
  window.location.href = `${AUTH_URL}/?redirect=${redirect}`;
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<WhoamiResponse | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    whoami()
      .then(setUser)
      .catch((err) => {
        if (err instanceof ApiError && err.status === 401) {
          redirectToLogin();
        }
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

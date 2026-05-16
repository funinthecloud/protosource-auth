const API_BASE = import.meta.env.VITE_API_BASE ?? "";

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

export async function api<T>(
  path: string,
  init?: RequestInit,
): Promise<T> {
  const res = await fetch(`${API_BASE}/${path}`, {
    credentials: "include",
    ...init,
    headers: { ...init?.headers },
  });
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText);
    throw new ApiError(res.status, text);
  }
  const ct = res.headers.get("content-type") ?? "";
  if (ct.includes("application/json")) return res.json();
  return {} as T;
}

export function post<T>(path: string, body: unknown): Promise<T> {
  return api(path, {
    method: "POST",
    body: JSON.stringify(body),
    headers: { "Content-Type": "application/json" },
  });
}

export interface WhoamiResponse {
  user_id: string;
  email: string;
  roles: Record<string, { role_id: string; assigned_at: number }>;
}

export const whoami = () => api<WhoamiResponse>("whoami");

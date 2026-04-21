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

// ---- Types ----

export interface WhoamiResponse {
  user_id: string;
  email: string;
  roles: Record<string, { role_id: string; assigned_at: number }>;
}

export interface User {
  id: string;
  email: string;
  state: number;
  create_at: number;
  modify_at: number;
  roles: Record<string, { role_id: string; assigned_at: number }>;
}

export interface Role {
  id: string;
  name: string;
  description: string;
  state: number;
  create_at: number;
  modify_at: number;
  functions: Record<string, { function: string; granted_at: number }>;
}

export interface Issuer {
  id: string;
  iss: string;
  display_name: string;
  kind: number;
  default_algorithm: string;
  jwks_url: string;
  state: number;
  create_at: number;
  modify_at: number;
}

export interface Key {
  id: string;
  issuer_id: string;
  algorithm: string;
  state: number;
  effective_at: number;
  signing_until: number;
  verify_until: number;
  create_at: number;
}

export interface Token {
  id: string;
  user_id: string;
  issuer_id: string;
  state: number;
  issued_at: number;
  expires_at: number;
  create_at: number;
}

// ---- Queries ----

export const whoami = () => api<WhoamiResponse>("whoami");

export const listUsers = () =>
  api<User[]>("auth/user/v1/query/by-state?state=1");
export const getUser = (id: string) =>
  api<User>(`auth/user/v1/get/${id}`);

export const listRoles = () =>
  api<Role[]>("auth/role/v1/query/by-state?state=1");
export const getRole = (id: string) =>
  api<Role>(`auth/role/v1/get/${id}`);

export const listIssuers = () =>
  api<Issuer[]>("auth/issuer/v1/query/by-state?state=1");
export const getIssuer = (id: string) =>
  api<Issuer>(`auth/issuer/v1/get/${id}`);

export const listKeys = () =>
  api<Key[]>("auth/key/v1/query/by-state?state=1");
export const getKey = (id: string) =>
  api<Key>(`auth/key/v1/get/${id}`);

export const listTokens = () =>
  api<Token[]>("auth/token/v1/query/by-state?state=1");
export const getToken = (id: string) =>
  api<Token>(`auth/token/v1/get/${id}`);

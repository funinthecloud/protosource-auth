import { useEffect, useState, useCallback } from "react";
import { ApiError } from "./api";

export function useAsync<T>(fn: () => Promise<T>, deps: unknown[] = []) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const reload = useCallback(() => {
    setLoading(true);
    setError(null);
    fn()
      .then(setData)
      .catch((e) => setError(e instanceof ApiError ? e.message : String(e)))
      .finally(() => setLoading(false));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  useEffect(reload, [reload]);

  return { data, error, loading, reload };
}

export function fmtTime(epoch: number): string {
  if (!epoch) return "-";
  return new Date(epoch * 1000).toLocaleString();
}

export function stateName(state: number, map: Record<number, string>): string {
  return map[state] ?? `Unknown (${state})`;
}

export const userStates: Record<number, string> = {
  0: "Unspecified",
  1: "Active",
  2: "Locked",
  3: "Deleted",
};

export const roleStates: Record<number, string> = {
  0: "Unspecified",
  1: "Active",
  2: "Deleted",
};

export const issuerStates: Record<number, string> = {
  0: "Unspecified",
  1: "Active",
  2: "Deactivated",
  3: "Deleted",
};

export const issuerKinds: Record<number, string> = {
  0: "Unspecified",
  1: "Self",
  2: "External",
};

export const keyStates: Record<number, string> = {
  0: "Unspecified",
  1: "Signing",
  2: "Verify Only",
  3: "Expired",
};

export const tokenStates: Record<number, string> = {
  0: "Unspecified",
  1: "Issued",
  2: "Revoked",
};

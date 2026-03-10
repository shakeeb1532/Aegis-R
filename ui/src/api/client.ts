import { apiKeyHeader, getApiKey as readApiKey } from "./auth";

const base = import.meta.env.VITE_API_BASE || "http://localhost:8081";

export function getApiBase() {
  return base;
}

export function getApiKey() {
  return readApiKey();
}

export function apiHeaders() {
  return apiKeyHeader(readApiKey());
}

export async function fetchJson<T>(path: string, fallback: T): Promise<T> {
  try {
    const res = await fetch(`${base}${path}`, { headers: apiHeaders() });
    if (!res.ok) {
      return fallback;
    }
    const raw = (await res.json()) as any;
    if (raw && typeof raw === "object" && "data" in raw) {
      return raw.data as T;
    }
    return raw as T;
  } catch {
    return fallback;
  }
}

const base = import.meta.env.VITE_API_BASE || "http://localhost:8081";

export async function fetchJson<T>(path: string, fallback: T): Promise<T> {
  try {
    const res = await fetch(`${base}${path}`);
    if (!res.ok) {
      return fallback;
    }
    const data = (await res.json()) as T;
    return data;
  } catch {
    return fallback;
  }
}

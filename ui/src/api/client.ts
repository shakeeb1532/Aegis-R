const base = import.meta.env.VITE_API_BASE || "http://localhost:8081";
function apiKey() {
  return (
    import.meta.env.VITE_API_KEY ||
    window.localStorage.getItem("amanApiKey") ||
    window.localStorage.getItem("ingestApiKey") ||
    ""
  );
}

export async function fetchJson<T>(path: string, fallback: T): Promise<T> {
  try {
    const key = apiKey();
    const res = await fetch(`${base}${path}`, {
      headers: key ? { "X-API-Key": key } : undefined
    });
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

import { FeedbackPayload } from "../types";

const base = import.meta.env.VITE_API_BASE || "http://localhost:8081";

function apiKey() {
  return (
    import.meta.env.VITE_API_KEY ||
    window.localStorage.getItem("amanApiKey") ||
    window.localStorage.getItem("ingestApiKey") ||
    ""
  );
}

export async function postFeedback(payload: FeedbackPayload) {
  const key = apiKey();
  const res = await fetch(`${base}/v1/feedback`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(key ? { "X-API-Key": key } : {})
    },
    body: JSON.stringify(payload)
  });
  if (!res.ok) {
    throw new Error("feedback_failed");
  }
  return res.json();
}

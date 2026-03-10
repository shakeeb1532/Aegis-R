import { FeedbackPayload } from "../types";
import { apiKeyHeader, getApiKey } from "./auth";

const base = import.meta.env.VITE_API_BASE || "http://localhost:8081";

export async function postFeedback(payload: FeedbackPayload) {
  const res = await fetch(`${base}/v1/feedback`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...apiKeyHeader(getApiKey())
    },
    body: JSON.stringify(payload)
  });
  if (!res.ok) {
    throw new Error("feedback_failed");
  }
  return res.json();
}

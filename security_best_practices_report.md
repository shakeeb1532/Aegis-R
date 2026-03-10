# Security Best Practices Report (Aman)

## Executive Summary
I reviewed the Go backend and React frontend with a security‑best‑practices lens. The core risk is **availability and key exposure**, not data integrity: the UI API server lacks HTTP timeouts/limits, and UI API keys are stored in browser localStorage. There are also **unbounded request bodies** on UI API POST endpoints and **weak path safety** checks that could become exploitable if any user‑controlled path is introduced later.

Below are prioritized findings with evidence, impact, and concrete fixes.

---

## Critical / High

### **[GO-HTTP-001] UI API server lacks HTTP timeouts and header limits**
- **Severity:** High
- **Location:** `cmd/aman/api.go:63-65`
- **Evidence:**
  ```go
  log.Printf("UI API listening on %s", *addr)
  if err := http.ListenAndServe(*addr, srv.Routes()); err != nil {
      log.Fatalf("serve-api: %v", err)
  }
  ```
- **Impact:** A slow‑loris or oversized‑header client can hold connections open indefinitely, exhausting server resources and causing denial of service.
- **Fix:** Use an `http.Server` with `ReadHeaderTimeout`, `ReadTimeout`, `WriteTimeout`, `IdleTimeout`, and `MaxHeaderBytes` (mirroring the ingest server configuration).
- **Mitigation:** If a reverse proxy enforces timeouts (e.g., ALB/NGINX), the risk is reduced but still present if the service is exposed directly.

---

## Medium

### **[GO-HTTP-002] UI API POST handlers read unbounded request bodies**
- **Severity:** Medium
- **Location:**  
  - `internal/uiapi/server.go:304-321` (feedback)  
  - `internal/uiapi/server.go:392-420` (tuning)
- **Evidence:**
  ```go
  body, err := io.ReadAll(r.Body)
  ...
  if err := json.Unmarshal(body, &payload); err != nil { ... }
  ```
- **Impact:** A large POST can cause memory exhaustion and crash the UI API. This is exploitable by any caller with the API key (or by mistake during testing).
- **Fix:** Wrap request bodies with `http.MaxBytesReader` (e.g., 1–2 MiB) before `io.ReadAll`.
- **Mitigation:** Add a reverse proxy body limit (`client_max_body_size` in NGINX) if you can’t patch immediately.

### **[WEB-SECRET-001] API keys stored in localStorage**
- **Severity:** Medium
- **Location:** `ui/src/api/auth.ts:1-16`
- **Evidence:**
  ```ts
  window.localStorage.getItem("amanApiKey")
  window.localStorage.getItem("ingestApiKey")
  ```
- **Impact:** Any XSS in the UI (or a malicious browser extension) can exfiltrate API keys. This breaks the security boundary.
- **Fix:** Use short‑lived tokens in memory or secure cookies (HttpOnly + SameSite + Secure when behind TLS).
- **Mitigation:** Reduce CORS exposure and treat the UI as an internal tool until auth is hardened.

---

## Low

### **[GO-PATH-001] Path validation is too weak**
- **Severity:** Low (latent risk)
- **Location:** `internal/ops/paths.go:8-10`
- **Evidence:**
  ```go
  func IsSafePath(p string) bool {
      clean := filepath.Clean(p)
      return !strings.Contains(clean, "..")
  }
  ```
- **Impact:** This does not prevent absolute paths, symlink escapes, or path traversal through junctions. If any user‑controlled path is ever introduced, this will be a bypass.
- **Fix:** Enforce a base directory allowlist and resolve symlinks (`filepath.EvalSymlinks`), then ensure the resolved path stays within the allowed base.
- **Mitigation:** Keep all file paths operator‑controlled only.

### **[WEB-CORS-001] Wildcard CORS on API endpoints**
- **Severity:** Low
- **Location:**  
  - `internal/uiapi/server.go:106-110`  
  - `internal/integration/http.go:266-270`
- **Evidence:**
  ```go
  w.Header().Set("Access-Control-Allow-Origin", "*")
  ```
- **Impact:** Any origin can call the APIs. If API keys leak, browser‑based exfiltration becomes easier. This isn’t a vulnerability alone but increases blast radius.
- **Fix:** Set explicit allowlisted origins for production deployments.
- **Mitigation:** Keep API keys secret and rotate regularly.

---

## Summary of Recommended Fixes (priority order)
1. Add timeouts + MaxHeaderBytes to `serve-api` server.
2. Add request size limits to UI API POST endpoints.
3. Stop storing API keys in localStorage (use secure cookies or short‑lived tokens).
4. Harden `IsSafePath` with base‑directory enforcement + symlink resolution.
5. Restrict CORS origins in production.

---

## Notes
This report only covers issues visible in the codebase. If a reverse proxy, WAF, or gateway already enforces strict limits, note that in deployment documentation, but still patch the app to be safe by default.


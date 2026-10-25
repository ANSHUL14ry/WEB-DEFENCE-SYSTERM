# AEGIS Ω — Architecture Specification

## 1. Executive Overview
**AEGIS Ω** is an adaptive, application-layer cyber defense and deception platform that sits in front of web applications and APIs.

Traditional perimeter defenses rely either on static rule sets (WAF) or post-breach monitoring (SIEM/EDR). AEGIS unites perimeter filtering, behavioral heuristics (AgentShield), active honeypot deception, and cryptographically provable mitigation verification into a cohesive system.

---

## 2. Request Lifecycle & Traffic Pipeline

```
[External Traffic / Attack Simulator]
               │
               ▼
   [AEGIS Ingress Gateway (:8080)]
         (Nginx Reverse Proxy)
         - Hardened ingress baseline
         - Request ID validation & propagation
         - Trace ID chain linkage
         - Structured JSON access logging
         - Security response headers
         - Controlled JSON error handling
               │
               ▼
   [Coraza WAF + OWASP CRS]  <── (Phase 3)
         - Inspection of headers, query, body
         - Rule violation scoring
               │
               ▼
         [AgentShield]        <── (Phase 6)
         - Velocity profiling
         - Endpoint discovery heuristics
         - Attack chain correlation
               │
               ▼
         [Risk Engine]        <── (Phase 5)
         - Explainable deterministic score (0-100)
               │
               ▼
        [Policy Engine]       <── (Phase 7)
         │
         ├─── LOW RISK ───────────────► [Origin Application (:8088)]
         │
         ├─── HIGH RISK ──────────────► [Drop / 403 Forbidden]
         │
         └─── HIGH-CONFIDENCE AGENTIC ─► [Isolated Decoy Honeypot (:8090)]
                                                 │
                                                 ▼
                                        [Evidence Collector]
                                                 │
                                                 ▼
                                    [Mitigation Verification]
                                                 │
                                                 ▼
                                          [SOC Dashboard]
```

---

## 3. Subsystem Breakdown

### 3.1 Hardened Gateway (`gateway/nginx`) — Phase 2 Active
- Custom Nginx ingress proxy mapping incoming HTTP requests.
- **Request Tracing**:
  - `request_id`: Unique identifier for each discrete HTTP transaction.
  - `trace_id`: Request-chain correlation identifier across multi-request workflows.
  - `session_id`: Session-level fingerprint (placeholder until Phase 6 behavioral clustering).
- **Validation Policy**: Client-provided `X-Request-ID` is accepted only if matching `^[a-zA-Z0-9_\-]{8,64}$`. Malformed IDs (containing special symbols, spaces, or injection attempts) are safely stripped and replaced by a fresh 32-character hexadecimal UUID (`$request_id`).
- **Structured JSON Logging**: Every access log event is structured JSON containing ISO timestamp, IDs, methods, normalized URI (no raw query string to prevent secret leakage), upstream address, latency metrics, and byte counts.
- **Security Headers Injected**:
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: SAMEORIGIN`
  - `Referrer-Policy: strict-origin-when-cross-origin`
  - `Permissions-Policy: geolocation=(), camera=(), microphone=()`
  - `Content-Security-Policy: default-src 'self' ...`
  - `X-Protected-By: AEGIS-Omega-Gateway`
- **Request Limits & Timeouts**:
  - `client_max_body_size 10M;` (Oversized requests receive clean 413 JSON error).
  - Explicit upstream timeouts: `proxy_connect_timeout 5s;`, `proxy_read_timeout 10s;`, `proxy_send_timeout 10s;`.
- **Controlled Error Handling**:
  - 502/503/504 upstream errors return clean JSON envelopes without exposing internal Docker networking details.
  - Unsupported HTTP verbs receive 405 Method Not Allowed JSON responses.

### 3.2 Control Plane API (`services/api`)
- FastAPI service coordinating system state and metrics.
- Exposes `/health`, `/api/v1/health`, and `/api/v1/system/status`.
- Connects to PostgreSQL telemetry database via SQLAlchemy connection pool.

### 3.3 Database (`database/`)
- PostgreSQL 16 Alpine container.
- Holds relational audit events, session tracking, WAF triggers, policy decisions, honeypot telemetry, and mitigation verifications.

### 3.4 Protected Origin (`services/origin`)
- Demonstrates upstream protection.
- Runs exclusively on the internal `aegis-net` Docker network; unreachable directly from host.

### 3.5 SOC Dashboard (`apps/dashboard`)
- React 18, TypeScript, Tailwind CSS, Vite.
- Dark SOC theme inspired by enterprise cyber command centers.

---

## 4. Network Isolation Architecture

| Port | Accessibility | Service | Justification |
|---|---|---|---|
| **8080** | **PUBLIC / HOST** | AEGIS Gateway Ingress | Primary entrance for client and external traffic |
| **3000** | **PUBLIC / HOST** | SOC Dashboard | Operator interface for security monitoring |
| **8001** | **PUBLIC / HOST** (Dev) | Control Plane API | Development and debugging API access |
| **5433** | **PUBLIC / HOST** (Dev) | PostgreSQL Store | Direct database inspection for developers |
| **8088** | **INTERNAL ONLY** | Protected Origin | Internal network `aegis-net`; totally inaccessible from outside |
| **8000** | **INTERNAL ONLY** | API internal port | Ingress gateway proxies `/api/` to `api:8000` |
| **5432** | **INTERNAL ONLY** | DB internal port | `db:5432` accessible only by API |

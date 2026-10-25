# AEGIS Ω — Architecture Specification

## 1. Executive Overview
**AEGIS Ω** is an adaptive, application-layer cyber defense and deception platform that sits in front of web applications and APIs.

Traditional perimeter defenses rely either on static rule sets (WAF) or post-breach monitoring (SIEM/EDR). AEGIS unites perimeter filtering, behavioral heuristics (AgentShield), active honeypot deception, and cryptographically provable mitigation verification into a cohesive system.

---

## 2. Request Lifecycle & Traffic Pipeline

```
[Client / Authorized Attack Simulator]
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
   [Coraza WAF (Internal :8080)]
         - OWASP Coraza Engine v3.2.2
         - OWASP Core Rule Set v4.30.0
         - Anomaly scoring & method validation
         - Clean JSON blocking interception
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

### 2.1 Normal Traffic Pipeline
```
Client
  ↓
AEGIS Gateway (:8080)
  ↓
Coraza WAF (Caddy)
  ↓
OWASP CRS (Rule Evaluation: Clean)
  ↓
Origin Application (:8088)
  ↓
Response to Client (200 OK)
```

### 2.2 Attack Blocking & Telemetry Flow
```
Suspicious Request
  ↓
AEGIS Gateway
  ↓
Coraza WAF
  ↓
CRS Rule Match (Anomaly Score Exceeded)
  ↓
BLOCK (HTTP 403 Forbidden)
  ↓
Coraza JSON Audit Log (/var/log/coraza/audit.log)
  ↓
Async Log Watcher Worker (FastAPI)
  ↓
Internal Ingestion API (/api/v1/internal/events)
  ↓
PostgreSQL Database (`security_events` & `waf_events`)
  ↓
Real-Time WebSocket Broadcast (`/api/v1/ws/events`)
  ↓
SOC Dashboard Live Telemetry
```

### 2.3 End-to-End Pipeline Dataflow
```
Client
  ↓
AEGIS Gateway
  ↓
Coraza WAF
  ↓
Security Event Pipeline
  ↓
PostgreSQL Database
  ↓
Real-Time SOC Dashboard
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

### 3.2 Real Web Application Firewall (`services/waf`) — Phase 3 Active
- **Engine**: OWASP Coraza WAF v3.2.2 running on Caddy v2.11.4 (`ghcr.io/coreruleset/coraza-crs:caddy-alpine`).
- **Rule Set**: OWASP Core Rule Set (CRS) v4.30.0 pinned for reproducible, deterministic threat detection.
- **Operational Modes**:
  - `BLOCK` (Default for Hackathon): Blocks requests exceeding CRS anomaly score threshold with HTTP 403 Forbidden.
  - `DETECTION`: Logs rule matches to the audit log while forwarding requests to the origin.
- **Method Policy Enforcement**: CRS rule 911100 configured via `/opt/coraza/config.d/01-methods.conf` to allow standard RESTful verbs (`GET HEAD POST OPTIONS PUT PATCH DELETE`).
- **Error Interception**: Nginx intercepts Coraza 403 blocks via `proxy_intercept_errors on;` and `@waf_blocked` named location, outputting a sanitized, non-leaking JSON error:
  `{"error":"request_blocked","status":403,"message":"Request blocked by AEGIS Web Application Firewall","request_id":"...","trace_id":"..."}`
- **Origin Isolation**: Blocked requests are terminated at the WAF level; protected origin receives **0** malicious requests during attacks.
- **Audit Logging & Event Pipeline**:
  - Coraza writes structured JSON audit logs to `/var/log/coraza/audit.log` (shared Docker volume `waf_logs`).
  - FastAPI asynchronous background watcher (`waf_log_watcher.py`) tails the log in real time.
  - Ingests events into `waf_events` table in PostgreSQL with rule IDs, messages, severity, tags, and anomaly scores.


### 3.3 Control Plane API (`services/api`)
- FastAPI service coordinating system state and metrics.
- Exposes `/health`, `/api/v1/health`, `/api/v1/system/status`, and `/api/v1/waf/status`.
- Connects to PostgreSQL telemetry database via SQLAlchemy connection pool.

### 3.4 Database (`database/`)
- PostgreSQL 16 Alpine container.
- Holds relational audit events, session tracking, WAF triggers (`waf_events`), policy decisions, honeypot telemetry, and mitigation verifications.

### 3.5 Protected Origin (`services/origin`)
- Demonstrates upstream protection.
- Runs exclusively on the internal `aegis-net` Docker network; unreachable directly from host.

### 3.6 SOC Dashboard (`apps/dashboard`)
- React 18, TypeScript, Tailwind CSS, Vite.
- Dark SOC theme inspired by enterprise cyber command centers with live WAF operational status indicators.
- **Live Security Telemetry Feed**: Real-time WebSocket connection streaming security events directly to the browser with zero manual polling.
- **Investigation Drawer**: Allows operators to drill down into structured event payloads, OWASP CRS rule IDs, anomaly scores, and verify origin protection.

### 3.7 Security Event Pipeline & Real-Time Telemetry (`services/api`) — Phase 4 Active
- **Unified Event Taxonomy**: Standardized envelope for `GATEWAY_REQUEST`, `WAF_DETECTION`, `WAF_BLOCK`, `ORIGIN_REQUEST`, and `SYSTEM_EVENT`.
- **Deduplication Engine**: Uses deterministic hashing signatures (`sha256(request_id:component:rule:action)`) combined with PostgreSQL `ON CONFLICT (event_id) DO NOTHING` to guarantee zero duplicate alerts upon log watcher restarts.
- **Multi-Level Correlation**:
  - `request_id`: Correlates gateway entrance, WAF inspection, and origin receipt for an individual HTTP transaction.
  - `trace_id`: Correlates multi-step request chains, foundational for future AgentShield velocity and path progression analysis.
  - `session_id`: Structured placeholder for future behavioral session clustering.
- **Automated Credential Sanitization**: Recursively redacts passwords, tokens, API keys, and authorization secrets from both metadata payloads and URI query parameters.
- **Real-Time WebSocket Broadcaster (`broadcaster.py`)**: Asynchronously multicasts newly ingested security events to all connected SOC dashboard clients.
- **Database Model (`security_events`)**: Persistent relational table indexed by timestamp, identifiers, severity, and event type.

---

## 4. Network Isolation Architecture

| Port | Accessibility | Service | Justification |
|---|---|---|---|
| **8080** | **PUBLIC / HOST** | AEGIS Gateway Ingress | Primary entrance for client and external traffic |
| **3000** | **PUBLIC / HOST** | SOC Dashboard | Operator interface for security monitoring |
| **8001** | **PUBLIC / HOST** (Dev) | Control Plane API | Development and debugging API access |
| **5433** | **PUBLIC / HOST** (Dev) | PostgreSQL Store | Direct database inspection for developers |
| **8080** | **INTERNAL ONLY** | Coraza WAF (`waf`) | `waf:8080` on `aegis-net`; inspected ingress traffic proxy |
| **8088** | **INTERNAL ONLY** | Protected Origin | Internal network `aegis-net`; totally inaccessible from outside |
| **8000** | **INTERNAL ONLY** | API internal port | Ingress gateway proxies `/api/` to `api:8000` |
| **5432** | **INTERNAL ONLY** | DB internal port | `db:5432` accessible only by API |

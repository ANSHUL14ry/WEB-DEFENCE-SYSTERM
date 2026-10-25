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
         - Tags X-Request-ID
         - SSL Termination
         - Upstream routing
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

### 3.1 Gateway (`gateway/nginx`)
- Custom Nginx ingress proxy mapping incoming HTTP requests.
- Assigns unique `X-Request-ID` to all traffic.
- Exposes native health probe at `/healthz`.
- Structured JSON logging containing response times and upstream metrics.

### 3.2 Control Plane API (`services/api`)
- FastAPI service coordinating system state and metrics.
- Exposes `/health`, `/api/v1/health`, and `/api/v1/system/status`.
- Connects to PostgreSQL telemetry database.

### 3.3 Database (`database/`)
- PostgreSQL 16 Alpine container.
- Holds relational audit events, session tracking, WAF triggers, policy decisions, honeypot telemetry, and mitigation verifications.

### 3.4 Protected Origin (`services/origin`)
- Demonstrates upstream protection.
- Runs exclusively on the internal `aegis-net` Docker network; unreachable directly from host.

### 3.5 SOC Dashboard (`apps/dashboard`)
- React 18, TypeScript, Tailwind CSS, Vite.
- Dark SOC theme inspired by enterprise cyber command centers.

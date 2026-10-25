# AEGIS Ω — Coraza WAF Service

## Overview
The AEGIS Web Application Firewall service embeds the official **OWASP Coraza WAF v3** engine alongside the **OWASP Core Rule Set (CRS) v4.30.0** within a high-performance Caddy reverse proxy layer.

## Architecture & Traffic Flow
```
Client / Ingress Gateway (:8080)
               │
               ▼
   [Coraza WAF Service (:8080 internal)]
               │
      [OWASP CRS Rules Engine]
       ├── SQL Injection (REQUEST-942-APPLICATION-ATTACK-SQLI)
       ├── Cross-Site Scripting (REQUEST-941-APPLICATION-ATTACK-XSS)
       ├── Local File Inclusion (REQUEST-930-APPLICATION-ATTACK-LFI)
       ├── Remote Code Execution (REQUEST-932-APPLICATION-ATTACK-RCE)
       ├── Protocol Enforcement (REQUEST-920-PROTOCOL-ENFORCEMENT)
       └── Anomaly Evaluation (REQUEST-949-BLOCKING-EVALUATION)
               │
      Decision Gate:
       ├── If Rule Match & WAF_MODE=BLOCK ────► HTTP 403 Forbidden (Origin NOT reached)
       │                                         └── Structured Event logged & ingested into DB
       └── If Normal Request or DETECTION ────► Forward to Protected Origin (:8088)
```

## Configurable WAF Modes:
- `CORAZA_RULE_ENGINE=On` (Blocking mode: drops malicious requests with HTTP 403)
- `CORAZA_RULE_ENGINE=DetectionOnly` (Detection mode: logs violations but forwards traffic)

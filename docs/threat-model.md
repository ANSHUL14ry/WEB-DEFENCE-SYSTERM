# AEGIS Ω — Threat Model & Defensive Security Principles

## 1. Scope & Defensive Mandate
AEGIS Ω is explicitly designed as a defensive security system. 
All attack simulation tools provided within this platform operate strictly in safe, controlled, reproducible environments against explicitly authorized local targets.

### Prohibited Capabilities:
- Unauthorized penetration testing
- Real-world credential harvesting
- Active exploitation frameworks or malware distribution
- Persistence techniques or lateral movement across networks

---

## 2. Threat Actor Profiles

### 2.1 Automated Reconnaissance & Scrapers
- **Pattern:** High velocity, sweeping directory discovery (`/admin`, `/config`, `/.git`, `/api/users`), repetitive enumeration.
- **AEGIS Defense:** AgentShield detects rapid sequence variance and elevated request velocity, triggering early decoy redirection.

### 2.2 Agentic & LLM-Driven Autonomous Attackers
- **Pattern:** Adaptive probing, chain progression (Recon -> Discovery -> Auth Probing -> Parameter Manipulation).
- **AEGIS Defense:** Explainable behavioral indicators identify the structured attack chain rather than relying on brittle signatures alone.

### 2.3 Web Application Attackers (OWASP Top 10)
- **Pattern:** SQLi, XSS, Path Traversal, SSRF, Command Injection.
- **AEGIS Defense:** Coraza WAF with OWASP Core Rule Set (CRS) evaluates anomalous payloads with strict anomaly thresholds.

---

## 3. Deception Isolation & Sandbox Principles
- **No Production Data in Honeypots:** Decoys use 100% synthetic mock tables and synthetic session tokens.
- **Network Isolation:** Honeypots have zero route access to real databases or production backends.
- **Non-Bypass Rule:** A WAF-blocked request is never automatically bypassed into a honeypot; deception occurs strictly through explicit Policy Engine qualification.

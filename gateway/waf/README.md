# AEGIS Ω — Web Application Firewall (Coraza + OWASP CRS)

## Operational Status: PHASE 3 ACTIVE
The WAF layer sits directly between the AEGIS Ingress Gateway and upstream backends.

## Components:
- **Engine**: Coraza WAF v3
- **Ruleset**: OWASP Core Rule Set (CRS) v4.30.0
- **Service Container**: `aegis-waf`
- **Internal Port**: `8080` (network: `aegis-net`)
- **Upstream Target**: `http://origin:8088`

# AEGIS Ω — Adaptive Isolated Honeypot

## Overview
An isolated decoy service providing synthetic endpoints and mock data to contain, study, and extract evidence from high-confidence automated attackers.

## Core Security Rules:
- Never contains real credentials or production secrets.
- Never connects to production databases or internal networks.
- Logs every interaction and generates cryptographic evidence receipts.

## Milestones
- **Phase 8**: Adaptive Decoys (`/decoy-admin`, `/decoy-login`, `/decoy-api`, etc.)

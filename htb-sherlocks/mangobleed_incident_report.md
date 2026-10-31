# Incident Investigation Report: MangoBleed

## 1. Scenario 
> **Alert Summary:** Unauthorized Remote Exploitation and Privilege Escalation on MongoDB Host
A high severity security alert flagged suspicious connection spikes and inbound network activity targeting a MongoDB v8.0.16 instance (`uac-mongodbsync-linux-triage`). 
- **Initial Access Vector:** Exploitation via **CVE-2025-14847** originating from external IP address `65.0.76.43`.
- **Subsequent Activity:** The initial compromise leaked sensitive information, leading to credential-based SSH authentication for the `mongoadmin` user, in-memory enumeration via `LinPEAS`, and a staged data exfiltration attempt using a local Python HTTP server.

## 2. Initial triage 
During the initial triage phase of the `uac-mongodbsync-linux-triage` artifact set, the investigation focused on pinpointing the exact timeline of compromise and identifying external threat vectors.
- **MongoDB Log Analysis (`var/log/mongodb/mongod.log`):** Checked first to isolate the earliest confirmed malicious event associated with the external attacker IP (`65.0.76.43`). This identified the initial exploit connection timestamp at `2025-12-29 05:25:52` and established the total connection volume.
- **Authentication Log Analysis (`var/log/auth.log`):** Inspected next to track subsequent lateral movement or remote access. This revealed that the attacker successfully established an interactive SSH session via the `mongoadmin` user account at `2025-12-29 05:39:24`.

 ## 3. Investigation 
The investigation uncovered clear indicators of compromise (IOCs) and post-exploitation actions across log files and command history artifacts:
- **Initial Exploit Activity:** The attacker (`65.0.76.43`) leveraged **CVE-2025-14847**, generating connection spikes starting at `2025-12-29 05:25:52`.
- **Remote Access & Enumeration:** Following successful brute-force SSH access to the `mongoadmin` account at `05:39:24`, the attacker executed **LinPEAS** via an in-memory script (`curl ... | sh`) to perform local privilege escalation enumeration.
- **Data Staging & Exfiltration:** The attacker targeted the `/var/lib/mongodb` directory, installed `zip` to archive sensitive contents, and launched a Python HTTP server on port `6969` (`python3 -m http.server 6969`) to facilitate data exfiltration.

- ## 4. Verdict — True positive or false positive? Why?
- **Verdict:** True Positive
- **Justification:** The alert and subsequent forensic artifacts conclusively demonstrated unauthorized external compromise. The combination of exploitation via CVE-2025-14847, explicit external IP connection spikes (`65.0.76.43`), successful brute-force SSH access (`mongoadmin`), in-memory privilege escalation enumeration (`LinPEAS`), and data archiving (`zip`) followed by data exfiltration via a Python HTTP server leaves no doubt that this was a genuine, active security breach.

## 5. Action taken 
 **Immediate Containment:** Escalate the incident as a confirmed breach, terminate active attacker sessions associated with the `mongoadmin` user, and block the threat actor's IP address (`65.0.76.43`) at the firewall/network edge.
 **Remediation & Next Steps:** 
  1. Patch the MongoDB instance immediately to remediate **CVE-2025-14847**.
  2. Invalidate and rotate all administrative credentials, database keys, and SSH keys.
  3. Conduct a full integrity check on `/var/lib/mongodb` to measure the scope of exfiltrated data.

## 6. Lesson learned 
- **Detection Gaps:** The environment lacked strict egress filtering and anomaly detection for unexpected outbound ports/protocols (such as the Python HTTP server running on port `6969`) and in-memory script execution (`curl | sh`).
- **Lessons Learned:** 
  1. **Proactive Patch Management:** Ensure rapid patching cycles for database services to prevent known Remote Code Execution vulnerabilities like CVE-2025-14847.
  2. **Behavioral Monitoring:** Implement endpoint detection rules to alert on suspicious command piping (e.g., fetching scripts from GitHub directly into `sh`) and unauthorized file staging.
  3. **Network Segmentation:** Enforce strict firewall policies and egress controls to prevent attackers from establishing ad-hoc exfiltration channels.
  5. Perform host hardening by restricting remote database exposure and auditing sudo/SSH access privileges.
 
- 

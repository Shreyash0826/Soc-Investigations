# SOC Incident Analysis Report: Harvest Ransomware Triage

## 1. Scenario
* **Alert**: Execution of an unrecognized binary (`harvest`) exhibiting suspicious file enumeration, network connections to Tor onion infrastructure, and self-destruction routines.

## 2. Initial Triage
* **Alert Details**: Reviewed process execution logs and identified manual execution of the compiled binary with custom configuration flags.
* **Process Tree & Context**: Inspected parent-child relationships and environment parameters on the local Linux test lab machine to determine execution context and intended scope.

## 3. Investigation
* **Evidence Gathered**:
  * **Static Indicators**: Extracted target configuration parameters including victim identifier format (`B%04d`), chunk size (`4096` bytes), and signal interception (`SIGINT`).
  * **Network Artifacts**: Identified hardcoded C2 infrastructure (`kd24u5e4ggp2m4k4w23lm5fu1nurmme6ugrwi9btachx83lpw1t6qlxf.onion`) and FTP exfiltration handlers.
  * **File Handling**: Discovered automated filename sanitization substituting spaces with underscores (`_`) prior to transmission.
  * **Execution Flags**: Verified that passing `--destruct` controls binary self-deletion behavior during dynamic analysis.
  * *[Attach Terminal Output / Disassembly Screenshots here]*

## 4. Verdict
* **True Positive**: Verified malicious ransomware behavior through string extraction and disassembly (`objdump`), confirming file staging, exfiltration routines, and self-destruction features.

## 5. Action Taken
* **Isolate & Escalate**: Isolated the affected test host from the network, blocked outbound access to `.onion` routing nodes, and documented Indicators of Compromise (IoCs) for SOC tracking. Next steps include engineering EDR detection rules for the custom execution flags.

## 6. Lesson Learned
* **Detection Gap**: Standard process monitoring may miss binaries executed with suppression arguments like `--destruct`. Improved telemetry should focus on monitoring anomalous file renaming patterns (space-to-underscore conversions) and rapid mass modifications across targeted file extensions before network exfiltration.

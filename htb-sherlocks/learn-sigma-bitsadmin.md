# Lab Writeup: Learn Sigma 


**Lab Target:** `proc_creation_win_bitsadmin_download.yml`  
**Focus Area:** Detection Logic Analysis, Living-off-the-Land Binaries (LOLBins), MITRE ATT&CK Mapping  

---

## Executive Summary
This exercise involved analyzing a Sigma detection rule designed to identify potentially malicious file transfers executed via the built-in Windows utility `bitsadmin.exe`. BITS (Background Intelligent Transfer Service) is commonly abused by threat actors to download secondary payloads while evading security controls.

---

## Rule Breakdown

| Field | Analyzed Value |
| :--- | :--- |
| **Target Binary** | `bitsadmin.exe` |
| **Log Category** | `process_creation` |
| **Primary Tactic Tag** | `attack.defense_evasion` |
| **Captured Event Fields** | `CommandLine`, `ParentCommandLine` |

---

## Detection Logic & Command-Line Analysis

### 1. Key Matching Criteria
The rule triggers when process execution logs capture `bitsadmin.exe` running with specific network transfer parameters:
* **Transfer Flag:** `/transfer` (indicates an active BITS transfer job)
* **Protocol Target:** `http` (detects remote downloads over HTTP/HTTPS)

### 2. Logical Condition
```yaml
condition: selection_img and (selection_cmd or all of selection_cli_*)

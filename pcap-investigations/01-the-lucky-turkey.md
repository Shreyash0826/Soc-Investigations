# SOC Incident Investigation Report — The Lucky Turkey

**Incident ID:** `IR-2026-1110-01`  
**Date of Activity:** 10 November 2026 (13:19 – 15:24 EST)  
**Artifact Analyzed:** `2026-11-10-traffic-analysis-exercise.pcap`  
**Severity:** High  
**Status:** Confirmed Compromise — Containment Required  

---

## 1. Executive Summary

On **10 November 2026**, workstation **`DESKTOP-5OMVI3L`** (`10.11.10.147`) in the **`theluckyturkey.com`** Active Directory domain was compromised under user account **`edward.winslow`** via a **ClickFix social-engineering lure**. Following initial web redirects, PowerShell executed an external loader from `vericheckusgo.com` (`96.62.224.200`), staged an embedded Python 3.12.7 runtime, downloaded a disguised payload carrier (`5555.mp4`), and deployed **NetSupport RAT**. Sustained plaintext HTTP command-and-control (C2) beaconing to **`dasiiiitt.com` (`93.152.209.36:443`)** persisted every ~60 seconds through the end of the capture (`15:24:25 EST`). No SMB lateral movement or Active Directory enumeration was observed on the wire.

---

## 2. Affected Assets & Account Details

| Attribute | Value |
| :--- | :--- |
| **Domain** | `theluckyturkey.com` |
| **Domain Controller** | `LUCKYTURKEY-DC` (`10.11.10.10`) |
| **Compromised Host** | `DESKTOP-5OMVI3L` |
| **Internal IP / MAC** | `10.11.10.147` / `00:12:f0:e5:17:43` |
| **Compromised User** | `edward.winslow` (RID `1105`) |
| **Domain SID** | `S-1-5-21-1320389422-2284452533-1497837395` |

---

## 3. Correlated Attack Timeline (EST)

| Time (EST) | Frame(s) | Protocol / Stream | Event Description |
| :--- | :--- | :--- | :--- |
| `13:19:55 – 13:20:27` | `1–1200` | DHCP / Kerberos / SMB | `10.11.10.147` (`DESKTOP-5OMVI3L`) joins network; `edward.winslow` authenticates. Baseline GPO fetch and single-user SAMR lookup (`RID 1105`). |
| `13:20:43 – 13:20:45` | `3795–5488` | DNS / TLS | User visits `crownherliving.com` (`66.223.49.89`) and traverses ad/redirect chain (`wuntred.com`, `adsmanagertgo.click`, `manageradsforsites.com`). |
| `13:21:49.712` | `11072–11073` | DNS | Resolves ClickFix lure domain `vericheckusgo.com` -> `96.62.224.200`. |
| `13:21:49.930` | `11078, 11092` | HTTP (`tcp.stream 129`) | `WindowsPowerShell/5.1.26100.9711` sends `GET /` to `vericheckusgo.com`; receives `15,995`-byte PowerShell loader. |
| `13:21:51.991` | `11096–11101` | DNS / TLS | Resolves `www.python.org` (`167.82.48.223`) and fetches Python 3.12.7 over HTTPS (`port 443`). |
| `13:21:59.047` | `19855, 24634` | HTTP | Python worker fetches `GET http://96.62.224.200/5555.mp4` (`6,045,311` bytes, `video/mp4` carrier containing encrypted agent). |
| `13:22:05.893` | `24668–24671` | DNS | Resolves C2 domain `dasiiiitt.com` -> `93.152.209.36`. |
| `13:22:07.728` | `24672, 24675` | HTTP/443 (`tcp.stream 132`) | First NetSupport RAT C2 check-in (`POST http://93.152.209.36/fakeurl.htm`, `User-Agent: NetSupport Manager/1.3`). |
| `13:22:08 – 15:24:25` | `24678–30177` | HTTP/443 | Continuous C2 beaconing (`CMD=POLL` / `CMD=ENCD`) every ~60 seconds until capture end. |

---

## 4. Technical Analysis & Findings

* **Initial Execution (ClickFix -> PowerShell):**  
  In `tcp.stream 129` (`Frame 11078`), `WindowsPowerShell/5.1.26100.9711` issued a `GET /` request to `vericheckusgo.com`, proving command execution outside the browser. The returned `15,995`-byte script checked `ComputerName` against `*CLEAN*`/`CLEN`, hid the console window via `ShowWindow(..., 0)`, dropped a Python worker to `%TEMP%\ch_w_<guid>.py`, staged Python 3.12.7 into `%LOCALAPPDATA%\.v16c936eb5ae\py-embed\312`, and wrote an anchor file at `%ProgramData%\.ch_d5855b208b12`.
* **Payload Delivery (`5555.mp4` Carrier):**  
  At `Frame 19855`, the Python worker requested `http://96.62.224.200/5555.mp4` (`6,045,311` bytes). The script parses an embedded MP4 `"uuid"` box, XOR-decrypts and decompresses the payload into `%TEMP%\chk_<random>.py`, and launches the final RAT agent.
* **C2 Attribution (NetSupport RAT over TCP/443):**  
  Traffic to `93.152.209.36:443` (`dasiiiitt.com`) used **plaintext HTTP over port 443** without TLS. Client requests used `POST http://93.152.209.36/fakeurl.htm` (`User-Agent: NetSupport Manager/1.3`, `CMD=POLL`), and the C2 replied with `Server: NetSupport Gateway/1.92 (Windows NT)` (`CMD=ENCD`, `ES=1`).
* **Lateral Movement & Internal Activity:**  
  SMB/DCE-RPC review confirmed standard AD GPO refreshes, a single SAMR user lookup for `edward.winslow` (`RID 1105`), and benign Windows Explorer checks on `\\LUCKYTURKEY-DC\Shared` (`Desktop.ini` / `AutoRun.inf` -> `STATUS_OBJECT_NAME_NOT_FOUND`). No lateral movement or secondary external C2 channels were detected.

---

## 5. Indicators of Compromise (IOCs)

### Network IOCs
* **C2 Domain / IP:** `dasiiiitt.com` | `93.152.209.36:443` (Plaintext HTTP `POST /fakeurl.htm`)
* **Staging Domain / IP:** `vericheckusgo.com` | `96.62.224.200:80`
* **Payload URL:** `http://96.62.224.200/5555.mp4`
* **Lure / Redirect Domains:** `crownherliving.com` (`66.223.49.89`), `wuntred.com`, `adsmanagertgo.click`, `manageradsforsites.com`
* **HTTP Signatures:** `User-Agent: NetSupport Manager/1.3` | `Server: NetSupport Gateway/1.92 (Windows NT)`

### Host Artifacts (Extracted from Stage-1 Script)
* `%ProgramData%\.ch_d5855b208b12` (Execution anchor file)
* `%LOCALAPPDATA%\.v16c936eb5ae\py-embed\312\python.exe` (Staged Python runtime)
* `%TEMP%\ch_w_<guid>.py` & `%TEMP%\chk_<hex>.py` (Stage-2 Python scripts)

---

## 6. Recommended Containment & Remediation

1. **Isolate Endpoint:** Network-quarantine `DESKTOP-5OMVI3L` (`10.11.10.147`) immediately via EDR/NAC.
2. **Block IOCs at Perimeter:** Block `93.152.209.36`, `96.62.224.200`, `dasiiiitt.com`, and `vericheckusgo.com` across firewall, proxy, and DNS sinkholes.
3. **Credential Reset:** Reset Active Directory credentials and revoke active Kerberos/cloud tokens for `edward.winslow`.
4. **Host Forensics & Cleanup:** Collect memory/disk triage from `DESKTOP-5OMVI3L`, inspect scheduled tasks/Run keys for NetSupport RAT persistence, and purge `%LOCALAPPDATA%\.v16c936eb5ae`, `%ProgramData%\.ch_d5855b208b12`, and `%TEMP%\ch*` artifacts.
5. **Detection Rule:** Alert on non-TLS HTTP traffic over TCP/443 and outbound `User-Agent: NetSupport Manager/*` or `WindowsPowerShell/*` requests to uncategorized domains.

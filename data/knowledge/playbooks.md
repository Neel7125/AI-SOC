# Security Investigation Playbooks

## Playbook: SSH / RDP Brute Force
Indicators: many failed logins or many short connections to ports 22, 3389 or 21 from one source within minutes; failed password for invalid user entries; later a successful login from the same source.
Investigation steps:
1. Count failed logins per source IP and per target account in the alert window.
2. Check whether a successful login follows the failures (possible compromise).
3. Check source IP reputation and whether the source is internal automation or an authorised scanner.
4. Review the target host for new accounts, new SSH keys and unusual commands after login.
Response (requires human approval): block or rate-limit the source at the firewall, enforce MFA/key-only SSH, reset credentials of targeted accounts, monitor for repeat attempts.
MITRE: T1110.001 Password Guessing, T1021.004 Remote Services SSH, T1078 Valid Accounts.

## Playbook: Port Scan / Network Service Discovery
Indicators: one source sends tiny SYN flows (1-3 packets) to many destination ports, often with RST replies, within a short window; slow scans spread over many minutes evade per-minute thresholds.
Investigation steps:
1. Determine whether the source is an approved vulnerability scanner (check asset inventory and change tickets).
2. Count distinct destination ports and hosts probed and the time span.
3. Look for follow-up activity (exploit attempts, logins) from the same source against discovered services.
Response (requires human approval): block unapproved scanning sources, review exposed services, add the source to watchlists.
MITRE: T1046 Network Service Discovery, T1595.001 Scanning IP Blocks.

## Playbook: Denial of Service / SYN Flood
Indicators: very high packets per second towards one service with few response packets, many SYN flags and resets, bursts from one or many sources.
Investigation steps:
1. Confirm service degradation (latency, error rates) on the target host.
2. Identify top sources and whether they are spoofed or distributed.
3. Check upstream/CDN protections and rate limits.
Response (requires human approval): enable SYN cookies and rate limiting, engage upstream DDoS mitigation, block abusive sources, scale capacity if appropriate.
MITRE: T1498 Network Denial of Service, T1499 Endpoint Denial of Service.

## Playbook: Data Exfiltration / Large Outbound Transfer
Indicators: very large outbound byte counts to external addresses, long duration flows, uncommon destination ports (21, 53, 8443), transfers from servers that normally do not upload.
Investigation steps:
1. Identify the source host, user and process responsible for the transfer.
2. Verify whether the destination is a known backup or cloud-sync service (scheduled backups look similar).
3. Inspect what data was accessed or staged (archives, database dumps) before the transfer.
Response (requires human approval): restrict egress to the destination, preserve evidence, assess data sensitivity and notification obligations.
MITRE: T1048 Exfiltration Over Alternative Protocol, T1567 Exfiltration Over Web Service, T1041, T1074 Data Staged.

## Playbook: Suspicious PowerShell Execution
Indicators: powershell.exe with -enc / -EncodedCommand, DownloadString, IEX, hidden window, spawned by Office applications, wscript or cmd; obfuscated string concatenation.
Investigation steps:
1. Decode any Base64 payload and review the script safely in an isolated environment.
2. Review the parent process chain (for example winword.exe spawning PowerShell suggests macro execution).
3. Check network connections and file writes from the process in the following minutes.
4. Distinguish approved admin scripts (known paths such as C:\Scripts, scheduled-task parent).
Response (requires human approval): isolate the host after analyst confirmation, collect memory and script block logs, reset exposed credentials, block the download URL.
MITRE: T1059.001 PowerShell, T1027 Obfuscated Files, T1105 Ingress Tool Transfer, T1204 User Execution.

## Playbook: Privilege Escalation Indicators
Indicators: net localgroup administrators /add, whoami /priv enumeration, sekurlsa or mimikatz strings, service binPath changes, unexpected tools in public folders.
Investigation steps:
1. Identify the account that ran the command and whether it is authorised for administration.
2. Check whether new local admin accounts or group memberships were created.
3. Look for credential dumping and lateral movement from the same host afterwards.
Response (requires human approval): remove unauthorised group members, reset affected credentials, rebuild the host if credential theft is confirmed.
MITRE: T1098 Account Manipulation, T1548, T1003 OS Credential Dumping, T1033, T1069.

## Playbook: Suspicious File Activity and Ransomware Precursors
Indicators: executables or scripts written to Temp folders, vssadmin delete shadows, files renamed with .locked or similar extensions, README_DECRYPT notes, archives staged in public folders.
Investigation steps:
1. Determine the process that created the files and its parent.
2. Check for mass file modification across user directories and shares.
3. Verify backups are intact and offline copies are available.
Response (requires human approval): isolate affected hosts, disable affected accounts, preserve disk images, begin ransomware response plan.
MITRE: T1486 Data Encrypted for Impact, T1490 Inhibit System Recovery, T1074 Data Staged, T1560.

## Playbook: Command and Control over Non-Standard Ports
Indicators: outbound connections from non-browser processes to ports such as 4444, 1337, 8888, repeating beacons, executables from public folders.
Investigation steps:
1. Identify the process and its file path and hash.
2. Check destination reputation and other hosts connecting to it.
3. Review prior alerts for the host (PowerShell, file drops).
Response (requires human approval): block the destination, isolate the host after confirmation, collect forensic artefacts.
MITRE: T1571 Non-Standard Port, T1071 Application Layer Protocol, T1105.

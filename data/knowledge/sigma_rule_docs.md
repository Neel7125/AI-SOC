# Detection Rule Documentation

## NET-001 Port scan
Fires when a single source contacts at least 20 distinct destination ports within a 60 second window using flows of 3 or fewer packets. Known false positives: authorised vulnerability scanners. Known blind spot: slow scans below the per-minute threshold. SPL equivalent: siem/spl_queries/port_scan.spl.

## NET-002 SYN or packet flood
Fires when a flow shows at least 1500 packets per second and at least 100 forward packets. Blind spot: low-rate application layer DoS.

## NET-003 Brute force on auth ports
Fires when a source opens at least 10 flows per minute to port 22, 3389 or 21. False positives: SSH automation and monitoring probes. Blind spot: slow brute force.

## NET-004 Large outbound transfer
Fires when a flow to an external address sends at least 2 MB. False positives: scheduled cloud backups. Blind spot: slow low-volume exfiltration.

## EP-001 Suspicious PowerShell
Regex rule over Sysmon process creation: encoded command, DownloadString, IEX, Invoke-Expression, FromBase64String or hidden window style. Blind spot: obfuscated string concatenation. False positives: hidden-window admin scripts.

## EP-002 Privilege escalation
Regex rule for net localgroup administrators /add, whoami /priv, sekurlsa, mimikatz, service binPath changes. Blind spot: renamed tools.

## EP-003 Suspicious file activity
Executables or scripts in Temp, .locked extension, README_DECRYPT, vssadmin delete shadows. False positives: legitimate installers writing to Temp.

## EP-004 SSH brute force
At least 5 failed SSH password events per source within 5 minutes in auth.log.

## EP-005 Suspicious outbound port
Sysmon network connection to ports 4444, 1337, 6667 or 31337.

## Sigma format
Detection rules are also provided in Sigma YAML under siem/detection_rules. Sigma separates detection logic (selection, condition) from metadata (title, level, tags such as attack.t1059.001) so that rules can be converted to SPL or other SIEM languages.

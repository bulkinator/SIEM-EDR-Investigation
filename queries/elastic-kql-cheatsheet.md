# Elastic KQL Cheatsheet

A practical Kibana Query Language (KQL) reference for SOC investigations, threat hunting, endpoint analysis, and detection engineering.

---

# 1. KQL Basics

KQL is used to filter events in:

- Kibana Discover
- Elastic Security
- Detection Rules
- Dashboards
- Timeline
- Threat Hunting

> KQL filters events. It does not perform SPL-style `stats`, aggregation, sorting, or transformation.

---

## Basic Field Search

```kql
user.name: admin
```

Search for a hostname:

```kql
host.name: WORKSTATION-05
```

Search for an IP:

```kql
source.ip: 192.168.1.100
```

Search for a process:

```kql
process.name: powershell.exe
```

---

# 2. Boolean Operators

## AND

Both conditions must match.

```kql
process.name: powershell.exe AND user.name: jsmith
```

---

## OR

Either condition can match.

```kql
process.name: powershell.exe OR process.name: cmd.exe
```

---

## NOT

Exclude matching events.

```kql
NOT user.name: SYSTEM
```

Example:

```kql
process.name: powershell.exe AND NOT user.name: SYSTEM
```

---

## Parentheses

Use parentheses to control query logic.

```kql
process.name: (powershell.exe OR cmd.exe) AND user.name: jsmith
```

---

# 3. Search Multiple Values

Instead of:

```kql
process.name: powershell.exe OR process.name: cmd.exe
```

Use:

```kql
process.name: (powershell.exe OR cmd.exe)
```

Another example:

```kql
destination.port: (22 OR 3389 OR 445)
```

---

# 4. Check Whether a Field Exists

```kql
source.ip: *
```

Process command line exists:

```kql
process.command_line: *
```

File hash exists:

```kql
file.hash.sha256: *
```

---

# 5. Range Queries

Greater than:

```kql
network.bytes > 1000000
```

Greater than or equal:

```kql
destination.port >= 1024
```

Less than:

```kql
destination.port < 1024
```

Combined range:

```kql
destination.port >= 1024 AND destination.port <= 65535
```

---

# 6. Time Queries

Events during the last hour:

```kql
@timestamp >= now-1h
```

Events during the last 24 hours:

```kql
@timestamp >= now-24h
```

Events older than 7 days:

```kql
@timestamp < now-7d
```

Specific time range:

```kql
@timestamp >= "2026-08-24T08:00:00" AND @timestamp <= "2026-08-24T09:00:00"
```

---

# 7. Wildcards

Starts with PowerShell:

```kql
process.name: powershell*
```

Windows hosts:

```kql
host.name: WIN*
```

> Leading wildcards such as `*shell.exe` are disabled by default in many Kibana configurations because they can be expensive.

---

# 8. Common Elastic ECS Fields

| Field | Meaning |
|---|---|
| `@timestamp` | Event timestamp |
| `event.code` | Event ID |
| `event.category` | Event category |
| `event.type` | Event type |
| `event.action` | Event action |
| `event.outcome` | success / failure |
| `host.name` | Hostname |
| `user.name` | Username |
| `source.ip` | Source IP |
| `source.port` | Source port |
| `destination.ip` | Destination IP |
| `destination.port` | Destination port |
| `process.name` | Process name |
| `process.executable` | Full process path |
| `process.command_line` | Command line |
| `process.parent.name` | Parent process |
| `process.parent.executable` | Parent process path |
| `file.name` | Filename |
| `file.path` | File path |
| `file.extension` | File extension |
| `file.hash.sha256` | SHA256 hash |
| `registry.path` | Registry path |
| `network.protocol` | Network protocol |
| `network.transport` | TCP / UDP |
| `network.bytes` | Network bytes |

---

# Authentication Investigation

# 9. Failed Windows Logins — Event ID 4625

```kql
event.code: "4625"
```

Alternative depending on the dataset:

```kql
winlog.event_id: 4625
```

Failed login for a particular user:

```kql
event.code: "4625" AND user.name: jsmith
```

Failed login from a particular IP:

```kql
event.code: "4625" AND source.ip: 192.168.1.100
```

---

# 10. Successful Windows Logins — Event ID 4624

```kql
event.code: "4624"
```

Specific user:

```kql
event.code: "4624" AND user.name: jsmith
```

Specific source:

```kql
event.code: "4624" AND source.ip: 192.168.1.100
```

---

# 11. Successful RDP Login

Windows Logon Type 10 represents RemoteInteractive / RDP.

Depending on the Windows integration:

```kql
event.code: "4624" AND winlog.event_data.LogonType: "10"
```

Or:

```kql
winlog.event_id: 4624 AND winlog.event_data.LogonType: "10"
```

---

# 12. Failed RDP Logins

```kql
event.code: "4625" AND winlog.event_data.LogonType: "10"
```

---

# 13. Authentication Activity for One Account

```kql
event.code: ("4624" OR "4625") AND user.name: jsmith
```

---

# 14. Authentication Activity From One IP

```kql
event.code: ("4624" OR "4625") AND source.ip: 192.168.1.100
```

---

# Brute Force Detection

# 15. Brute Force Base Filter

```kql
event.code: "4625"
```

Use this filter in an Elastic **Threshold Rule**.

Example rule logic:

```text
Query:
event.code: "4625"

Group by:
source.ip

Threshold:
10

Time window:
5 minutes
```

---

# 16. Password Spraying

Look for authentication failures:

```kql
event.code: "4625"
```

For a detection rule:

```text
Group by:
source.ip

Look for:
One source IP attempting many different usernames
```

---

# 17. Failed Login Followed by Success

Base filter:

```kql
event.code: ("4624" OR "4625")
```

Then investigate whether repeated 4625 failures were followed by a 4624 success from the same:

```text
source.ip
user.name
host.name
```

---

# Windows Process Investigation

# 18. Windows Process Creation — Event ID 4688

```kql
event.code: "4688"
```

Search PowerShell:

```kql
event.code: "4688" AND process.name: powershell.exe
```

Search CMD:

```kql
event.code: "4688" AND process.name: cmd.exe
```

---

# Sysmon Investigation

# 19. Sysmon Events

Common Sysmon Event IDs:

| Event ID | Description |
|---|---|
| 1 | Process Creation |
| 3 | Network Connection |
| 7 | Image / DLL Load |
| 10 | Process Access |
| 11 | File Creation |
| 13 | Registry Modification |

---

# 20. Confirm Sysmon Events

```kql
winlog.provider_name: "Microsoft-Windows-Sysmon"
```

Specific Sysmon Event:

```kql
winlog.provider_name: "Microsoft-Windows-Sysmon" AND event.code: "1"
```

---

# 21. Sysmon Process Creation — Event 1

```kql
event.code: "1" AND winlog.provider_name: "Microsoft-Windows-Sysmon"
```

PowerShell process:

```kql
event.code: "1"
AND winlog.provider_name: "Microsoft-Windows-Sysmon"
AND process.name: powershell.exe
```

---

# PowerShell Detection

# 22. PowerShell Execution

```kql
process.name: powershell.exe
```

Also check PowerShell Core:

```kql
process.name: (powershell.exe OR pwsh.exe)
```

---

# 23. Suspicious PowerShell Commands

```kql
process.name: (powershell.exe OR pwsh.exe)
AND process.command_line: (
    "Invoke-Expression"
    OR "Invoke-WebRequest"
    OR "DownloadString"
    OR "Net.WebClient"
)
```

---

# 24. Encoded PowerShell

```kql
process.name: (powershell.exe OR pwsh.exe)
AND process.command_line: (
    "-enc"
    OR "-encodedcommand"
    OR "EncodedCommand"
    OR "FromBase64String"
)
```

---

# 25. PowerShell Download Activity

```kql
process.name: powershell.exe
AND process.command_line: (
    "Invoke-WebRequest"
    OR "DownloadString"
    OR "WebClient"
    OR "Start-BitsTransfer"
)
```

---

# 26. Hidden PowerShell Window

```kql
process.name: powershell.exe
AND process.command_line: (
    "-w hidden"
    OR "-windowstyle hidden"
)
```

---

# 27. PowerShell Execution Policy Bypass

```kql
process.name: powershell.exe
AND process.command_line: (
    "-ExecutionPolicy Bypass"
    OR "-ep bypass"
)
```

---

# LOLBin Detection

# 28. Office Application Spawning PowerShell

```kql
process.parent.name: (
    WINWORD.EXE
    OR EXCEL.EXE
    OR POWERPNT.EXE
    OR OUTLOOK.EXE
)
AND process.name: (
    powershell.exe
    OR pwsh.exe
)
```

---

# 29. Office Application Spawning CMD

```kql
process.parent.name: (
    WINWORD.EXE
    OR EXCEL.EXE
    OR POWERPNT.EXE
    OR OUTLOOK.EXE
)
AND process.name: cmd.exe
```

---

# 30. Office Spawning Suspicious Child Process

```kql
process.parent.name: (
    WINWORD.EXE
    OR EXCEL.EXE
    OR POWERPNT.EXE
    OR OUTLOOK.EXE
)
AND process.name: (
    cmd.exe
    OR powershell.exe
    OR pwsh.exe
    OR wscript.exe
    OR cscript.exe
    OR mshta.exe
    OR rundll32.exe
)
```

---

# 31. Common Windows LOLBins

```kql
process.name: (
    certutil.exe
    OR rundll32.exe
    OR regsvr32.exe
    OR mshta.exe
    OR bitsadmin.exe
    OR wmic.exe
    OR installutil.exe
)
```

---

# 32. Certutil Execution

```kql
process.name: certutil.exe
```

Possible download activity:

```kql
process.name: certutil.exe
AND process.command_line: (
    "-urlcache"
    OR "-split"
)
```

---

# 33. Rundll32 Execution

```kql
process.name: rundll32.exe
```

Investigate unusual parent processes:

```kql
process.name: rundll32.exe
AND process.parent.name: (
    WINWORD.EXE
    OR EXCEL.EXE
    OR powershell.exe
    OR cmd.exe
)
```

---

# 34. Regsvr32 Execution

```kql
process.name: regsvr32.exe
```

Suspicious command line:

```kql
process.name: regsvr32.exe
AND process.command_line: (
    "/s"
    OR "/u"
    OR "/i"
)
```

---

# 35. MSHTA Execution

```kql
process.name: mshta.exe
```

Suspicious parent:

```kql
process.name: mshta.exe
AND process.parent.name: (
    WINWORD.EXE
    OR EXCEL.EXE
    OR outlook.exe
)
```

---

# Credential Access

# 36. LSASS Access — Sysmon Event 10

```kql
event.code: "10"
AND winlog.provider_name: "Microsoft-Windows-Sysmon"
AND winlog.event_data.TargetImage: "C:\\Windows\\system32\\lsass.exe"
```

Field mappings vary between datasets.

Another useful filter:

```kql
event.code: "10" AND process.name: *
```

Then inspect:

```text
process.name
process.executable
winlog.event_data.TargetImage
winlog.event_data.GrantedAccess
```

---

# 37. Possible Credential Dumping Tools

```kql
process.name: (
    mimikatz.exe
    OR procdump.exe
    OR comsvcs.dll
)
```

---

# 38. Search for Mimikatz Indicators

```kql
process.command_line: (
    mimikatz
    OR sekurlsa
    OR lsadump
)
```

---

# 39. Procdump Targeting LSASS

```kql
process.name: procdump.exe
AND process.command_line: lsass
```

---

# 40. Comsvcs MiniDump Technique

```kql
process.name: rundll32.exe
AND process.command_line: (
    comsvcs.dll
    AND MiniDump
)
```

---

# Discovery Activity

# 41. Common Reconnaissance Commands

```kql
process.name: (
    whoami.exe
    OR hostname.exe
    OR ipconfig.exe
    OR systeminfo.exe
    OR net.exe
    OR net1.exe
    OR nltest.exe
    OR quser.exe
    OR qwinsta.exe
)
```

---

# 42. Account Discovery

```kql
process.name: (net.exe OR net1.exe)
AND process.command_line: user
```

Domain account discovery:

```kql
process.name: (net.exe OR net1.exe)
AND process.command_line: (
    user
    AND "/domain"
)
```

---

# 43. Group Discovery

```kql
process.name: (net.exe OR net1.exe)
AND process.command_line: group
```

---

# 44. Domain Discovery

```kql
process.name: nltest.exe
```

---

# 45. Network Configuration Discovery

```kql
process.name: (
    ipconfig.exe
    OR arp.exe
    OR route.exe
    OR netstat.exe
)
```

---

# Lateral Movement

# 46. PsExec Execution

```kql
process.name: (
    psexec.exe
    OR psexec64.exe
)
```

---

# 47. PsExec Service

PsExec commonly creates a service named `PSEXESVC`.

```kql
service.name: PSEXESVC
```

Search Windows service installation:

```kql
event.code: "7045" AND service.name: PSEXESVC
```

---

# 48. WMI Execution

```kql
process.name: wmic.exe
```

Possible remote WMI:

```kql
process.name: wmic.exe
AND process.command_line: (
    "/node"
    OR "process call create"
)
```

---

# 49. WMI Provider Spawning Suspicious Process

```kql
process.parent.name: WmiPrvSE.exe
AND process.name: (
    cmd.exe
    OR powershell.exe
    OR rundll32.exe
)
```

---

# 50. Remote Desktop Activity

```kql
event.code: "4624"
AND winlog.event_data.LogonType: "10"
```

---

# 51. SMB Activity

```kql
destination.port: 445
```

Specific destination:

```kql
destination.ip: 10.0.0.10 AND destination.port: 445
```

---

# 52. Administrative Share Access

Windows Event ID 5145:

```kql
event.code: "5145"
```

Look for administrative shares:

```kql
event.code: "5145"
AND winlog.event_data.ShareName: (
    "\\\\*\\C$"
    OR "\\\\*\\ADMIN$"
)
```

> Exact field values can differ depending on the Windows log integration.

---

# 53. WinRM

Typical WinRM ports:

```kql
destination.port: (5985 OR 5986)
```

---

# Persistence

# 54. Registry Modification — Sysmon Event 13

```kql
event.code: "13"
AND winlog.provider_name: "Microsoft-Windows-Sysmon"
```

---

# 55. Registry Run Key Persistence

```kql
registry.path: (
    *\\Software\\Microsoft\\Windows\\CurrentVersion\\Run*
    OR *\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce*
)
```

> This query requires leading wildcards to be allowed in the Kibana configuration.

Where leading wildcards are disabled, search a more specific path used by your dataset.

---

# 56. Scheduled Task Creation

Windows Event:

```kql
event.code: "4698"
```

Process-based detection:

```kql
process.name: schtasks.exe
```

Scheduled task creation:

```kql
process.name: schtasks.exe
AND process.command_line: "/create"
```

---

# 57. Service Creation

Windows System Event 7045:

```kql
event.code: "7045"
```

Using sc.exe:

```kql
process.name: sc.exe
AND process.command_line: create
```

---

# 58. New User Account

Windows Event 4720:

```kql
event.code: "4720"
```

---

# 59. User Added to a Security Group

```kql
event.code: (
    "4728"
    OR "4732"
    OR "4756"
)
```

---

# 60. Startup Folder Persistence

```kql
file.path: *\\Microsoft\\Windows\\Start\ Menu\\Programs\\Startup\\*
```

> A leading wildcard may need to be enabled depending on Kibana configuration.

---

# Network Investigation

# 61. Network Connections

```kql
event.category: network
```

Connections from a specific host:

```kql
host.name: WORKSTATION-05
AND event.category: network
```

---

# 62. Sysmon Network Connection — Event 3

```kql
event.code: "3"
AND winlog.provider_name: "Microsoft-Windows-Sysmon"
```

---

# 63. PowerShell Network Connections

```kql
process.name: powershell.exe
AND destination.ip: *
```

---

# 64. Connections to a Known IOC

```kql
destination.ip: 203.0.113.50
```

Multiple malicious IPs:

```kql
destination.ip: (
    203.0.113.50
    OR 198.51.100.20
    OR 192.0.2.10
)
```

---

# 65. Connections From a Compromised Host

```kql
host.name: WORKSTATION-05
AND destination.ip: *
```

---

# 66. Suspicious Destination Ports

```kql
destination.port: (
    4444
    OR 5555
    OR 6666
    OR 8081
    OR 1337
)
```

> A non-standard port is not automatically malicious. Validate against the environment.

---

# 67. Remote Administration Ports

```kql
destination.port: (
    22
    OR 3389
    OR 445
    OR 5985
    OR 5986
)
```

---

# DNS Investigation

# 68. DNS Activity

```kql
event.category: network AND dns.question.name: *
```

---

# 69. Specific Domain

```kql
dns.question.name: malicious.example
```

---

# 70. Domain Pattern

```kql
dns.question.name: evil*
```

---

# 71. DNS Activity From One Host

```kql
host.name: WORKSTATION-05
AND dns.question.name: *
```

---

# File Investigation

# 72. Sysmon File Creation — Event 11

```kql
event.code: "11"
AND winlog.provider_name: "Microsoft-Windows-Sysmon"
```

---

# 73. Executable File Creation

```kql
file.extension: exe
```

---

# 74. Script File Creation

```kql
file.extension: (
    ps1
    OR bat
    OR cmd
    OR vbs
    OR js
)
```

---

# 75. Archive Creation

```kql
file.extension: (
    zip
    OR rar
    OR 7z
)
```

Useful when hunting for data staging before exfiltration.

---

# 76. Files Created in Temp

```kql
file.path: C\:\\Windows\\Temp\\*
```

User temporary directory:

```kql
file.path: C\:\\Users\\*
```

---

# Data Staging & Exfiltration

# 77. Archive Utilities

```kql
process.name: (
    7z.exe
    OR 7za.exe
    OR rar.exe
    OR winrar.exe
    OR tar.exe
)
```

---

# 78. Suspicious Archive Creation

```kql
process.name: (
    7z.exe
    OR 7za.exe
    OR rar.exe
    OR winrar.exe
)
AND process.command_line: *
```

Investigate whether sensitive directories are being archived.

---

# 79. Large Network Transfers

If your dataset provides `network.bytes`:

```kql
network.bytes > 100000000
```

100 MB is approximately:

```text
100,000,000 bytes
```

---

# 80. Large Outbound Transfer From a Host

```kql
host.name: WORKSTATION-05
AND network.bytes > 100000000
```

---

# 81. Large Transfer to External Destination

```kql
network.direction: outbound
AND network.bytes > 100000000
```

---

# 82. Common Exfiltration Tools

```kql
process.name: (
    rclone.exe
    OR curl.exe
    OR wget.exe
    OR ftp.exe
)
```

---

# 83. Rclone Execution

```kql
process.name: rclone.exe
```

Investigate command line:

```kql
process.name: rclone.exe
AND process.command_line: *
```

---

# Malware Investigation

# 84. Suspicious Script Interpreters

```kql
process.name: (
    powershell.exe
    OR pwsh.exe
    OR cmd.exe
    OR wscript.exe
    OR cscript.exe
    OR mshta.exe
)
```

---

# 85. Script Interpreter From Office

```kql
process.parent.name: (
    WINWORD.EXE
    OR EXCEL.EXE
    OR POWERPNT.EXE
    OR OUTLOOK.EXE
)
AND process.name: (
    powershell.exe
    OR cmd.exe
    OR wscript.exe
    OR cscript.exe
    OR mshta.exe
)
```

---

# 86. Suspicious Temporary Directory Execution

```kql
process.executable: C\:\\Users\\*
AND process.name: *
```

Investigate binaries executing from locations such as:

```text
AppData
Temp
Downloads
Public
```

---

# Ransomware Investigation

# 87. Ransomware-Like File Extensions

If the malware creates a known extension:

```kql
file.extension: encrypted
```

Or:

```kql
file.extension: locked
```

---

# 88. Ransom Note Files

```kql
file.name: (
    README*
    OR DECRYPT*
    OR RECOVER*
    OR RANSOM*
)
```

---

# 89. Shadow Copy Deletion

```kql
process.name: vssadmin.exe
AND process.command_line: (
    delete
    AND shadows
)
```

---

# 90. WMIC Shadow Copy Deletion

```kql
process.name: wmic.exe
AND process.command_line: (
    shadowcopy
    AND delete
)
```

---

# 91. Backup Catalog Deletion

```kql
process.name: wbadmin.exe
AND process.command_line: delete
```

---

# 92. BCDEdit Recovery Modification

```kql
process.name: bcdedit.exe
AND process.command_line: (
    recoveryenabled
    OR bootstatuspolicy
)
```

---

# Defense Evasion

# 93. Windows Defender Modification

```kql
process.name: powershell.exe
AND process.command_line: Set-MpPreference
```

---

# 94. Defender Exclusion Added

```kql
process.name: powershell.exe
AND process.command_line: Add-MpPreference
```

---

# 95. Security Tool Stopped

```kql
process.name: (
    sc.exe
    OR net.exe
)
AND process.command_line: stop
```

---

# 96. Event Log Clearing

Windows Event ID:

```kql
event.code: "1102"
```

Command-line activity:

```kql
process.name: wevtutil.exe
AND process.command_line: cl
```

---

# 97. Log Deletion

```kql
process.name: wevtutil.exe
AND process.command_line: (
    cl
    OR clear-log
)
```

---

# Threat Hunting

# 98. All Process Creation Events

```kql
event.category: process AND event.type: start
```

---

# 99. Processes Executed by a User

```kql
user.name: jsmith AND event.category: process
```

---

# 100. Activity on One Host

```kql
host.name: WORKSTATION-05
```

---

# 101. Activity From One Source IP

```kql
source.ip: 192.168.1.100
```

---

# 102. Activity to One Destination

```kql
destination.ip: 203.0.113.50
```

---

# 103. Search for a Known Hash

SHA256:

```kql
file.hash.sha256: "a3e4f2b1c8d7..."
```

MD5:

```kql
file.hash.md5: "HASH_HERE"
```

---

# 104. Search for Known Filename

```kql
file.name: mimikatz.exe
```

---

# 105. Search Multiple IOCs

```kql
destination.ip: (
    203.0.113.50
    OR 198.51.100.20
)
OR file.hash.sha256: (
    "HASH1"
    OR "HASH2"
)
```

---

# 106. Suspicious Parent-Child Relationships

Office → PowerShell:

```kql
process.parent.name: WINWORD.EXE
AND process.name: powershell.exe
```

PowerShell → Rundll32:

```kql
process.parent.name: powershell.exe
AND process.name: rundll32.exe
```

WMI → CMD:

```kql
process.parent.name: WmiPrvSE.exe
AND process.name: cmd.exe
```

---

# 107. Shell Spawned by Web Server

```kql
process.parent.name: (
    w3wp.exe
    OR httpd.exe
    OR nginx.exe
)
AND process.name: (
    cmd.exe
    OR powershell.exe
    OR sh
    OR bash
)
```

Useful for detecting possible web shells.

---

# Detection Engineering

# 108. Brute Force Detection Rule

### KQL

```kql
event.code: "4625"
```

### Suggested Rule

```text
Rule Type:
Threshold

Group by:
source.ip

Threshold:
10

Time:
5 minutes

Severity:
Medium / High

MITRE ATT&CK:
T1110 - Brute Force
```

---

# 109. Encoded PowerShell Rule

```kql
process.name: (powershell.exe OR pwsh.exe)
AND process.command_line: (
    "-enc"
    OR "-encodedcommand"
    OR "EncodedCommand"
)
```

```text
Severity:
High

MITRE ATT&CK:
T1059.001 - PowerShell
```

---

# 110. Office → PowerShell Rule

```kql
process.parent.name: (
    WINWORD.EXE
    OR EXCEL.EXE
    OR POWERPNT.EXE
    OR OUTLOOK.EXE
)
AND process.name: (
    powershell.exe
    OR pwsh.exe
)
```

```text
Severity:
High

MITRE ATT&CK:
T1204 - User Execution
T1059.001 - PowerShell
```

---

# 111. Credential Dumping Rule

```kql
event.code: "10"
AND winlog.provider_name: "Microsoft-Windows-Sysmon"
AND winlog.event_data.TargetImage: "C:\\Windows\\system32\\lsass.exe"
```

```text
Severity:
Critical

MITRE ATT&CK:
T1003.001 - LSASS Memory
```

---

# 112. PsExec Lateral Movement Rule

```kql
process.name: (
    psexec.exe
    OR psexec64.exe
)
```

```text
Severity:
High

MITRE ATT&CK:
T1021 - Remote Services
```

---

# 113. WMI Lateral Movement Rule

```kql
process.name: wmic.exe
AND process.command_line: (
    "/node"
    OR "process call create"
)
```

```text
Severity:
High

MITRE ATT&CK:
T1047 - Windows Management Instrumentation
```

---

# 114. Registry Persistence Rule

```kql
event.code: "13"
AND winlog.provider_name: "Microsoft-Windows-Sysmon"
AND registry.path: *
```

Then scope the rule to:

```text
CurrentVersion\Run
CurrentVersion\RunOnce
```

```text
Severity:
High

MITRE ATT&CK:
T1547.001 - Registry Run Keys / Startup Folder
```

---

# 115. Data Exfiltration Rule

```kql
network.direction: outbound
AND network.bytes > 100000000
```

```text
Severity:
High

MITRE ATT&CK:
T1041 - Exfiltration Over C2 Channel
```

---

# 116. Scheduled Task Persistence Rule

```kql
event.code: "4698"
```

Or process based:

```kql
process.name: schtasks.exe
AND process.command_line: "/create"
```

```text
MITRE ATT&CK:
T1053.005 - Scheduled Task
```

---

# 117. Ransomware Defense-Evasion Rule

```kql
(
    process.name: vssadmin.exe
    AND process.command_line: (delete AND shadows)
)
OR
(
    process.name: wmic.exe
    AND process.command_line: (shadowcopy AND delete)
)
```

```text
MITRE ATT&CK:
T1490 - Inhibit System Recovery
```

---

# Useful Windows Event IDs

| Event ID | Description |
|---|---|
| 4624 | Successful Logon |
| 4625 | Failed Logon |
| 4648 | Logon With Explicit Credentials |
| 4672 | Special Privileges Assigned |
| 4688 | Process Creation |
| 4698 | Scheduled Task Created |
| 4720 | User Account Created |
| 4728 | User Added to Global Group |
| 4732 | User Added to Local Group |
| 4756 | User Added to Universal Group |
| 4768 | Kerberos TGT Requested |
| 4769 | Kerberos Service Ticket Requested |
| 4776 | NTLM Authentication |
| 5140 | Network Share Access |
| 5145 | Detailed Network Share Access |
| 7045 | Service Installed |
| 1102 | Audit Log Cleared |

---

# Sysmon Event IDs

| Event ID | Description |
|---|---|
| 1 | Process Creation |
| 2 | File Creation Time Changed |
| 3 | Network Connection |
| 5 | Process Terminated |
| 6 | Driver Loaded |
| 7 | Image Loaded |
| 8 | CreateRemoteThread |
| 10 | Process Access |
| 11 | File Created |
| 12 | Registry Object Create/Delete |
| 13 | Registry Value Set |
| 14 | Registry Object Renamed |
| 15 | FileCreateStreamHash |
| 17 | Pipe Created |
| 18 | Pipe Connected |
| 22 | DNS Query |
| 23 | File Delete |
| 25 | Process Tampering |

---

# MITRE ATT&CK Quick Reference

| Technique | ID |
|---|---|
| Brute Force | T1110 |
| Valid Accounts | T1078 |
| PowerShell | T1059.001 |
| Windows Command Shell | T1059.003 |
| Account Discovery | T1087 |
| System Owner/User Discovery | T1033 |
| System Network Configuration Discovery | T1016 |
| Process Discovery | T1057 |
| Remote Desktop Protocol | T1021.001 |
| SMB / Windows Admin Shares | T1021.002 |
| Windows Remote Management | T1021.006 |
| Windows Management Instrumentation | T1047 |
| OS Credential Dumping | T1003 |
| LSASS Memory | T1003.001 |
| Scheduled Task | T1053.005 |
| Registry Run Keys | T1547.001 |
| Inhibit System Recovery | T1490 |
| Exfiltration Over C2 Channel | T1041 |
| User Execution | T1204 |
| Clear Windows Event Logs | T1070.001 |

---

# SOC Investigation Workflow

```text
1. Review the alert
        ↓
2. Identify affected host / user
        ↓
3. Establish investigation timeframe
        ↓
4. Search authentication activity
        ↓
5. Analyze process creation
        ↓
6. Reconstruct parent-child process tree
        ↓
7. Investigate command lines
        ↓
8. Check network connections
        ↓
9. Check credential access
        ↓
10. Check persistence
        ↓
11. Check lateral movement
        ↓
12. Check data staging / exfiltration
        ↓
13. Extract IOCs
        ↓
14. Build attack timeline
        ↓
15. Map activity to MITRE ATT&CK
        ↓
16. Recommend containment / remediation
```

---

# KQL Investigation Template

When investigating an alert, start broad:

```kql
host.name: WORKSTATION-05
```

Then identify the user:

```kql
host.name: WORKSTATION-05
AND user.name: jsmith
```

Authentication activity:

```kql
host.name: WORKSTATION-05
AND event.code: ("4624" OR "4625")
```

Process execution:

```kql
host.name: WORKSTATION-05
AND event.category: process
```

PowerShell:

```kql
host.name: WORKSTATION-05
AND process.name: powershell.exe
```

Network connections:

```kql
host.name: WORKSTATION-05
AND destination.ip: *
```

Potential persistence:

```kql
host.name: WORKSTATION-05
AND event.code: ("4698" OR "7045" OR "13")
```

Potential credential access:

```kql
host.name: WORKSTATION-05
AND event.code: "10"
```

Possible lateral movement:

```kql
host.name: WORKSTATION-05
AND (
    process.name: psexec.exe
    OR process.name: wmic.exe
    OR destination.port: 3389
    OR destination.port: 445
    OR destination.port: 5985
    OR destination.port: 5986
)
```

---

# KQL vs SPL Quick Comparison

| Task | Splunk SPL | Elastic KQL |
|---|---|---|
| Field search | `user=admin` | `user.name: admin` |
| AND | `user=admin host=PC01` | `user.name: admin AND host.name: PC01` |
| OR | `user=admin OR user=test` | `user.name: (admin OR test)` |
| NOT | `NOT user=SYSTEM` | `NOT user.name: SYSTEM` |
| Field exists | `user=*` | `user.name: *` |
| Greater than | `where bytes > 1000` | `network.bytes > 1000` |
| Time | `earliest=-24h` | `@timestamp >= now-24h` |
| Aggregation | `stats count by src_ip` | Not performed by KQL |
| Sorting | `sort -count` | Not performed by KQL |
| Threshold | SPL aggregation | Elastic Threshold Rule |

---

# Important KQL Limitation

KQL is a **filtering language**.

For example, this is valid:

```kql
event.code: "4625"
```

But KQL itself cannot perform:

```text
count failures by source.ip
sort highest count
group events
calculate averages
```

For:

```text
>10 failed logins
from one IP
within 5 minutes
```

Use:

```text
KQL Filter:
event.code: "4625"

Elastic Rule Type:
Threshold

Group by:
source.ip

Threshold:
10

Time Window:
5 minutes
```

For more complex event sequences, consider:

```text
EQL
ES|QL
Elastic Security correlation rules
```

---

# Notes

- Elastic field names depend on the integration and dataset being used.
- Prefer Elastic Common Schema (ECS) fields when available.
- Common ECS fields include `source.ip`, `destination.ip`, `user.name`, `host.name`, `process.name`, and `process.command_line`.
- Some Windows integrations use `event.code`.
- Others may expose `winlog.event_id`.
- Raw Windows fields may appear under `winlog.event_data.*`.
- Sysmon events can be identified using `winlog.provider_name: "Microsoft-Windows-Sysmon"`.
- KQL supports `AND`, `OR`, `NOT`, ranges, wildcards, and field-existence searches.
- Avoid unnecessary leading wildcards because they can be expensive and are disabled by default in many Kibana configurations.
- Always validate detection rules against expected legitimate activity.
- Document false positives when creating portfolio detection rules.
- Never claim a detection accuracy or true-positive rate unless you actually measured it against labelled data.

---

# Project Detection Rules to Build

For the SIEM & EDR Investigation Project, create at least these rules:

```text
01 - Brute Force Detection
02 - Encoded PowerShell
03 - Office Spawning PowerShell
04 - LSASS Credential Dumping
05 - PsExec Lateral Movement
06 - WMI Remote Execution
07 - Registry Run Key Persistence
08 - Large Data Exfiltration
```

Recommended GitHub structure:

```text
detection-rules/
│
├── 01-brute-force.md
├── 02-encoded-powershell.md
├── 03-office-powershell.md
├── 04-credential-dumping.md
├── 05-psexec.md
├── 06-wmi.md
├── 07-registry-persistence.md
└── 08-data-exfiltration.md
```

Each rule should document:

```text
Rule Name:
Description:
Data Source:
KQL Query:
Rule Type:
Severity:
MITRE ATT&CK:
Expected True Positives:
Possible False Positives:
Investigation Steps:
Containment Recommendation:
Testing Results:
```

# Elastic KQL Cheatsheet

Quick KQL reference for SOC investigations, threat hunting, and detection engineering.

---

## Basic Searches

```kql
user.name: admin
host.name: WORKSTATION-05
source.ip: 192.168.1.100
process.name: powershell.exe
```

### Boolean Operators

```kql
process.name: powershell.exe AND user.name: jsmith
process.name: powershell.exe OR process.name: cmd.exe
NOT user.name: SYSTEM
```

### Field Exists

```kql
source.ip: *
process.command_line: *
```

### Time Range

```kql
@timestamp >= now-24h
```

---

## Common ECS Fields

| Field | Description |
|---|---|
| `event.code` | Windows/Sysmon Event ID |
| `host.name` | Hostname |
| `user.name` | Username |
| `source.ip` | Source IP |
| `destination.ip` | Destination IP |
| `destination.port` | Destination port |
| `process.name` | Process |
| `process.command_line` | Command line |
| `process.parent.name` | Parent process |
| `file.name` | Filename |
| `registry.path` | Registry path |

---

# Authentication

## Failed Login

```kql
event.code: "4625"
```

## Successful Login

```kql
event.code: "4624"
```

## RDP Login

```kql
event.code: "4624"
AND winlog.event_data.LogonType: "10"
```

## User Authentication Activity

```kql
event.code: ("4624" OR "4625")
AND user.name: jsmith
```

---

# Brute Force

Base filter:

```kql
event.code: "4625"
```

Use an Elastic Threshold Rule:

```text
Group by: source.ip
Threshold: 10
Time window: 5 minutes
```

---

# Process Investigation

## Process Creation

```kql
event.code: "4688"
```

## PowerShell

```kql
process.name: (powershell.exe OR pwsh.exe)
```

## Encoded PowerShell

```kql
process.name: powershell.exe
AND process.command_line: (
    "-enc"
    OR "-encodedcommand"
    OR "FromBase64String"
)
```

## Suspicious PowerShell

```kql
process.name: powershell.exe
AND process.command_line: (
    "Invoke-WebRequest"
    OR "DownloadString"
    OR "IEX"
)
```

---

# LOLBins

## Office → PowerShell / CMD

```kql
process.parent.name: (
    WINWORD.EXE
    OR EXCEL.EXE
    OR OUTLOOK.EXE
)
AND process.name: (
    powershell.exe
    OR cmd.exe
)
```

## Common LOLBins

```kql
process.name: (
    certutil.exe
    OR rundll32.exe
    OR regsvr32.exe
    OR mshta.exe
    OR wmic.exe
)
```

---

# Credential Dumping

## LSASS Access

```kql
event.code: "10"
AND winlog.event_data.TargetImage: "C:\\Windows\\system32\\lsass.exe"
```

## Mimikatz Indicators

```kql
process.command_line: (
    mimikatz
    OR sekurlsa
    OR lsadump
)
```

## Procdump → LSASS

```kql
process.name: procdump.exe
AND process.command_line: lsass
```

---

# Discovery

```kql
process.name: (
    whoami.exe
    OR hostname.exe
    OR ipconfig.exe
    OR systeminfo.exe
    OR net.exe
    OR nltest.exe
)
```

---

# Lateral Movement

## PsExec

```kql
process.name: (
    psexec.exe
    OR psexec64.exe
)
```

## WMI

```kql
process.name: wmic.exe
AND process.command_line: (
    "/node"
    OR "process call create"
)
```

## WMI → Shell

```kql
process.parent.name: WmiPrvSE.exe
AND process.name: (
    cmd.exe
    OR powershell.exe
)
```

## SMB

```kql
destination.port: 445
```

## RDP

```kql
destination.port: 3389
```

---

# Persistence

## Registry Run Keys

```kql
registry.path: *\\Microsoft\\Windows\\CurrentVersion\\Run*
```

## Scheduled Task

```kql
event.code: "4698"
```

Or:

```kql
process.name: schtasks.exe
AND process.command_line: "/create"
```

## Service Creation

```kql
event.code: "7045"
```

## New User

```kql
event.code: "4720"
```

---

# Network Investigation

## Network Events

```kql
event.category: network
```

## Known Malicious IP

```kql
destination.ip: 203.0.113.50
```

## Remote Access Ports

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

# Data Exfiltration

## Large Outbound Transfer

```kql
network.direction: outbound
AND network.bytes > 100000000
```

## Archive Tools

```kql
process.name: (
    7z.exe
    OR rar.exe
    OR winrar.exe
)
```

## Common Exfiltration Tools

```kql
process.name: (
    rclone.exe
    OR curl.exe
    OR wget.exe
    OR ftp.exe
)
```

---

# Ransomware

## Shadow Copy Deletion

```kql
process.name: vssadmin.exe
AND process.command_line: (
    delete
    AND shadows
)
```

## Ransom Note

```kql
file.name: (
    README*
    OR DECRYPT*
    OR RECOVER*
    OR RANSOM*
)
```

---

# Defense Evasion

## Clear Windows Logs

```kql
event.code: "1102"
```

## Disable / Modify Defender

```kql
process.name: powershell.exe
AND process.command_line: (
    Set-MpPreference
    OR Add-MpPreference
)
```

---

# Threat Hunting

## Specific Host

```kql
host.name: WORKSTATION-05
```

## Specific User

```kql
user.name: jsmith
```

## Known Hash

```kql
file.hash.sha256: "HASH_HERE"
```

## Suspicious Parent → Child

```kql
process.parent.name: WINWORD.EXE
AND process.name: powershell.exe
```

---

# Important Windows Event IDs

| Event ID | Description |
|---|---|
| 4624 | Successful Logon |
| 4625 | Failed Logon |
| 4688 | Process Creation |
| 4698 | Scheduled Task Created |
| 4720 | User Created |
| 4732 | User Added to Local Group |
| 5145 | Network Share Access |
| 7045 | Service Installed |
| 1102 | Audit Log Cleared |

---

# Important Sysmon Event IDs

| Event ID | Description |
|---|---|
| 1 | Process Creation |
| 3 | Network Connection |
| 10 | Process Access |
| 11 | File Creation |
| 13 | Registry Modification |
| 22 | DNS Query |

---

# MITRE ATT&CK Quick Reference

| Technique | ID |
|---|---|
| Brute Force | T1110 |
| Valid Accounts | T1078 |
| PowerShell | T1059.001 |
| Credential Dumping | T1003 |
| LSASS Memory | T1003.001 |
| RDP | T1021.001 |
| SMB/Admin Shares | T1021.002 |
| WMI | T1047 |
| Scheduled Task | T1053.005 |
| Registry Run Keys | T1547.001 |
| Inhibit System Recovery | T1490 |
| Exfiltration Over C2 | T1041 |

---

# Detection Rules for This Project

```text
01 - Brute Force
02 - Encoded PowerShell
03 - Office → PowerShell
04 - LSASS Credential Dumping
05 - PsExec Lateral Movement
06 - WMI Remote Execution
07 - Registry Persistence
08 - Data Exfiltration
```

---

# KQL vs SPL

| Task | Splunk | KQL |
|---|---|---|
| Search user | `user=admin` | `user.name: admin` |
| OR | `user=a OR user=b` | `user.name: (a OR b)` |
| Field exists | `user=*` | `user.name: *` |
| Time | `earliest=-24h` | `@timestamp >= now-24h` |
| Count | `stats count` | Use Elastic aggregation/rule |
| Threshold | SPL + `where` | Threshold Rule |

---

## Notes

- Field names can vary between Elastic datasets.
- Prefer ECS fields such as `user.name`, `source.ip`, `process.name`, and `host.name`.
- KQL filters events; it does not perform SPL-style `stats`.
- Use Elastic Threshold Rules for detections such as 10 failed logins in 5 minutes.
- Validate detections against benign activity before treating them as production-ready.

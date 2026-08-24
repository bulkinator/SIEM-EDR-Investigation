Splunk SPL Cheatsheet

A practical SPL reference for SOC investigations, threat hunting, and incident response.

1. Basic Search

index=main

Search a specific sourcetype:

index=main sourcetype=windows_security

Search for an event code:

index=main EventCode=4624

Search multiple event codes:

index=main (EventCode=4624 OR EventCode=4625)

Search for a specific user:

index=main user="admin"

Search for a specific source IP:

index=main src_ip="192.168.1.100"

2. Time Filtering

Last 24 hours:

index=main earliest=-24h

Last 15 minutes:

index=main earliest=-15m

Specific time range:

index=main earliest="08/24/2026:08:00:00" latest="08/24/2026:09:00:00"

3. Useful SPL Commands

table

Display selected fields:

index=main EventCode=4625
| table _time, user, src_ip, ComputerName

fields

Keep only selected fields:

index=main EventCode=4625
| fields _time, user, src_ip

Remove a field:

index=main
| fields - host

sort

Sort newest first:

index=main
| sort -_time

Sort by highest count:

index=main EventCode=4625
| stats count by src_ip
| sort -count

dedup

Remove duplicate values:

index=main
| dedup src_ip

rename

Rename fields:

index=main
| rename src_ip AS "Source IP"

4. Statistics

Count all matching events:

index=main EventCode=4625
| stats count

Count by user:

index=main EventCode=4625
| stats count by user

Count by user and source IP:

index=main EventCode=4625
| stats count by user, src_ip

Find unique hosts:

index=main
| stats dc(ComputerName) AS unique_hosts

Show all values:

index=main
| stats values(src_ip) AS source_ips by user

Authentication Investigation

5. Failed Logins — Event ID 4625

index=main EventCode=4625
| table _time, user, src_ip, ComputerName

Top source IPs generating failed logins:

index=main EventCode=4625
| stats count by src_ip
| sort -count

Top targeted users:

index=main EventCode=4625
| stats count by user
| sort -count

6. Successful Logins — Event ID 4624

index=main EventCode=4624
| table _time, user, src_ip, Logon_Type, ComputerName

Successful RDP logins:

index=main EventCode=4624 Logon_Type=10
| table _time, user, src_ip, ComputerName

Common Logon Types

Logon Type

Meaning

2

Interactive

3

Network

4

Batch

5

Service

7

Unlock

8

NetworkCleartext

10

RemoteInteractive / RDP

11

CachedInteractive

Brute Force Detection

7. Basic Brute Force Search

index=main EventCode=4625
| stats count by src_ip
| where count > 10
| sort -count

Brute force against individual accounts:

index=main EventCode=4625
| stats count by src_ip, user
| where count > 10
| sort -count

8. Brute Force Within a 5-Minute Window

index=main EventCode=4625
| bin _time span=5m
| stats count by _time, src_ip
| where count > 10
| sort -count

9. Failed Logins Followed by Success

index=main (EventCode=4624 OR EventCode=4625)
| stats count(eval(EventCode=4625)) AS failures,
        count(eval(EventCode=4624)) AS successes
        by user, src_ip
| where failures > 10 AND successes > 0

Useful for detecting successful brute-force attacks.

Windows Process Investigation

10. Process Creation — Windows Event ID 4688

index=main EventCode=4688
| table _time, user, New_Process_Name, CommandLine, ParentProcessName

Search for command prompt:

index=main EventCode=4688 New_Process_Name="*cmd.exe"

Search for PowerShell:

index=main EventCode=4688 New_Process_Name="*powershell.exe"

Sysmon Investigation

11. Sysmon Event IDs

Event ID

Description

1

Process Creation

3

Network Connection

7

Image / DLL Load

10

Process Access

11

File Creation

13

Registry Modification

12. Sysmon Process Creation — Event ID 1

index=sysmon EventCode=1
| table _time, User, Image, ParentImage, CommandLine

Search for PowerShell:

index=sysmon EventCode=1 Image="*powershell.exe"
| table _time, User, ParentImage, CommandLine

13. Encoded PowerShell

index=sysmon EventCode=1 Image="*powershell.exe"
("EncodedCommand" OR "-enc" OR "-encodedcommand")
| table _time, User, ParentImage, CommandLine

Useful indicators:

-enc
-encodedcommand
Invoke-Expression
IEX
Invoke-WebRequest
DownloadString
Net.WebClient

LOLBin Detection

14. Office Applications Spawning PowerShell / CMD

index=sysmon EventCode=1
(ParentImage="*winword.exe" OR ParentImage="*excel.exe" OR ParentImage="*outlook.exe")
(Image="*powershell.exe" OR Image="*cmd.exe")
| table _time, User, ParentImage, Image, CommandLine

15. Suspicious LOLBins

index=sysmon EventCode=1
(Image="*rundll32.exe"
OR Image="*regsvr32.exe"
OR Image="*certutil.exe"
OR Image="*mshta.exe"
OR Image="*wmic.exe")
| table _time, User, ParentImage, Image, CommandLine

Credential Access

16. Possible LSASS Credential Dumping

index=sysmon EventCode=10 TargetImage="*lsass.exe"
| table _time, ComputerName, User, SourceImage, TargetImage, GrantedAccess

Focus on unusual processes accessing LSASS:

index=sysmon EventCode=10 TargetImage="*lsass.exe"
| where NOT like(SourceImage,"%svchost.exe")
| table _time, User, SourceImage, TargetImage, GrantedAccess

17. Mimikatz Search

index=sysmon
("mimikatz" OR "sekurlsa" OR "lsadump")
| table _time, ComputerName, User, Image, CommandLine

Lateral Movement

18. PsExec Detection

index=sysmon EventCode=1 Image="*psexec.exe"
| table _time, User, ComputerName, ParentImage, CommandLine

19. WMI Detection

index=sysmon EventCode=1
(Image="*wmic.exe" OR ParentImage="*wmiprvse.exe")
| table _time, User, ComputerName, ParentImage, Image, CommandLine

20. SMB Administrative Share Access

index=windows EventCode=5145 ShareName="*\\C$"
| table _time, user, src_ip, ComputerName, ShareName

21. RDP Lateral Movement

index=windows EventCode=4624 Logon_Type=10
| stats count by user, src_ip, ComputerName
| sort -count

Persistence

22. Registry Run Key Persistence

index=sysmon EventCode=13 TargetObject="*\\CurrentVersion\\Run*"
| table _time, User, ComputerName, Image, TargetObject, Details

23. Scheduled Task Creation

index=windows EventCode=4698
| table _time, ComputerName, user, TaskName

24. New User Account Creation

index=windows EventCode=4720
| table _time, ComputerName, SubjectUserName, TargetUserName

25. User Added to Privileged Group

index=windows (EventCode=4728 OR EventCode=4732 OR EventCode=4756)
| table _time, ComputerName, SubjectUserName, MemberName, GroupName

Network Investigation

26. Sysmon Network Connections — Event ID 3

index=sysmon EventCode=3
| table _time, ComputerName, User, Image, DestinationIp, DestinationPort

PowerShell network activity:

index=sysmon EventCode=3 Image="*powershell.exe"
| table _time, ComputerName, DestinationIp, DestinationPort

27. Suspicious Destination Ports

index=sysmon EventCode=3
| where NOT DestinationPort IN (53,80,443)
| stats count by DestinationIp, DestinationPort, Image
| sort -count

Data Exfiltration

28. Large Outbound Transfers

index=proxy bytes_out > 100000000
| stats sum(bytes_out) AS total_bytes by src_ip, dest_domain
| sort -total_bytes

Convert bytes to MB:

index=proxy
| stats sum(bytes_out) AS total_bytes by src_ip, dest_domain
| eval total_MB=round(total_bytes/1024/1024,2)
| sort -total_MB

29. Suspicious Archive Creation

index=sysmon EventCode=11
(TargetFilename="*.zip" OR TargetFilename="*.rar" OR TargetFilename="*.7z")
| table _time, User, ComputerName, Image, TargetFilename

Ransomware Investigation

30. Suspicious File Encryption

index=sysmon EventCode=11
(TargetFilename="*.encrypted" OR TargetFilename="*.locked")
| stats dc(TargetFilename) AS files_modified by Image, User, ComputerName
| sort -files_modified

31. Ransom Note Detection

index=sysmon EventCode=11
(TargetFilename="*README*" OR TargetFilename="*DECRYPT*" OR TargetFilename="*RANSOM*")
| table _time, ComputerName, User, Image, TargetFilename

Threat Hunting

32. Find Rare Processes

index=sysmon EventCode=1
| stats count by Image
| sort count

33. Find Rare Parent-Child Relationships

index=sysmon EventCode=1
| stats count by ParentImage, Image
| sort count

This can reveal unusual process chains such as:

winword.exe -> powershell.exe
excel.exe -> cmd.exe
powershell.exe -> rundll32.exe

34. Search Activity for a Specific User

index=* user="jsmith"
| sort _time
| table _time, index, sourcetype, EventCode, ComputerName, src_ip

35. Search Activity for a Specific Host

index=* ComputerName="WORKSTATION-05"
| sort _time

36. Search Activity Around an Incident Time

index=* earliest="08/24/2026:14:20:00" latest="08/24/2026:15:20:00"
| sort _time

Timeline Creation

37. Create an Event Timeline

index=* user="jsmith"
| sort _time
| table _time, EventCode, ComputerName, Image, CommandLine, src_ip

38. Timeline Visualization

index=main user="admin"
| timechart count by EventCode

Useful SPL Functions

eval

Create a new field:

index=proxy
| eval MB=round(bytes_out/1024/1024,2)

where

Filter numerical results:

index=main EventCode=4625
| stats count by src_ip
| where count > 10

bin

Group events into time windows:

index=main EventCode=4625
| bin _time span=5m
| stats count by _time, src_ip

timechart

Visualize activity over time:

index=main EventCode=4625
| timechart span=5m count

transaction

Correlate related events:

index=main (EventCode=4624 OR EventCode=4625)
| transaction user maxspan=10m

Use transaction carefully because it can be expensive on large datasets.

SOC Investigation Workflow

1. Review the alert
2. Identify the affected user / host
3. Determine the timeframe
4. Search authentication logs
5. Search process creation
6. Analyze parent-child relationships
7. Check network connections
8. Check persistence
9. Check lateral movement
10. Check credential access
11. Check data exfiltration
12. Build the attack timeline
13. Extract IOCs
14. Map activity to MITRE ATT&CK
15. Recommend containment and remediation

Important Windows Event IDs

Event ID

Description

4624

Successful Logon

4625

Failed Logon

4688

Process Creation

4698

Scheduled Task Created

4720

User Account Created

4728

User Added to Global Security Group

4732

User Added to Local Security Group

4756

User Added to Universal Security Group

5145

Network Share Access

MITRE ATT&CK Quick Reference

Technique

ID

Brute Force

T1110

Valid Accounts

T1078

PowerShell

T1059.001

Account Discovery

T1087

Remote Desktop Protocol

T1021.001

Windows Admin Shares

T1021.002

OS Credential Dumping

T1003

LSASS Memory

T1003.001

Scheduled Task

T1053.005

Registry Run Keys

T1060 / T1547.001

Exfiltration Over C2 Channel

T1041

Notes

Index names and field names vary between Splunk labs.

Replace index=main, index=windows, and index=sysmon with the indexes used in your environment.

Always validate detections against benign activity before turning a search into an alert.

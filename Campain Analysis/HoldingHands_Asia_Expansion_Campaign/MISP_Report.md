# HoldingHands Asia Expansion Campaign - MISP Threat Intelligence Report

## Event Summary
- **Event ID**: TBD (To Be Determined upon MISP import)
- **Date**: 2025-10-17
- **Last Update**: 2025-10-18
- **Threat Level**: High (1)
- **Published**: No
- **Attribute Count**: 67
- **Analysis Level**: Complete (2)
- **Distribution**: TLP:WHITE
- **Campaign ID**: HHAE-2024-001

## Threat Actor Profile
- **Name**: Unidentified APT Group
- **Type**: Advanced Persistent Threat (APT)
- **First Observed**: March 2024
- **Active**: Yes (Current - October 2025)
- **Target Industries**: Government, Finance, Business
- **Geographic Focus**: Asia-Pacific (China, Taiwan, Japan, Malaysia)
- **Attack Vectors**: Spearphishing (PDF/Excel/Word attachments), Social Engineering
- **Primary TTPs**: Multi-stage malware delivery, DLL side-loading, Task Scheduler abuse, Information theft

## Campaign Overview
This comprehensive threat intelligence report documents a sophisticated multi-stage malware campaign targeting organizations across Asia from March 2024 to October 2025. The campaign demonstrates systematic geographic expansion and evolving tactics:

### Key Campaign Characteristics
- **Total IOCs**: 67 indicators
- **Malware Families**: HoldingHands (primary), Winos 4.0 (initial phase)
- **Timeline**: 20 months of continuous activity (March 2024 - October 2025)
- **Geographic Progression**: China → Taiwan → Japan → Malaysia
- **Infrastructure**: Tencent Cloud abuse + Custom domain infrastructure
- **Evasion**: Code signing, anti-VM, anti-AV, multi-stage execution

### Geographic Expansion Timeline
1. **March 2024 - China**: Initial operations using Winos 4.0 and Excel documents
2. **January 2025 - Taiwan**: Expansion with PDF-based phishing, Ministry of Finance impersonation
3. **February 2025 - Malware Evolution**: Transition from Winos 4.0 to HoldingHands
4. **March 2025 - Japan**: Japanese-language lures, Word documents, shared infrastructure
5. **October 2025 - Malaysia**: Latest campaign with advanced Task Scheduler abuse

## Indicator Categories

### Network Infrastructure (16 indicators)
- **Domains**: 9 (Malware distribution, download pages)
- **IP Addresses**: 7 (C2 servers, shared infrastructure)

### Malware Artifacts (11 indicators)
- **SHA256 Hashes**: 11 (HoldingHands and Winos 4.0 samples)
- **Filenames**: 7 (DLL loaders, DAT files, configuration files)

### Persistence & Configuration (5 indicators)
- **Registry Keys**: 2 (Configuration storage, C2 updates)
- **Debug Paths**: 1 (Development artifacts)
- **Command Lines**: 1 (Execution validation)
- **Cloud Infrastructure**: 2 (Tencent Cloud Account IDs)

### Intelligence & Context (34 indicators)
- **Malware Families**: 2
- **YARA Rules**: 2
- **Targeting Information**: 4
- **Attribution Data**: 3
- **Technical Comments**: 6
- **External References**: 1
- **Detection Information**: 2

## Associated Malware Families

### HoldingHands (Primary - February 2025 to Present)
**Description**: Multi-stage backdoor and information stealer with advanced capabilities

**Capabilities**:
- Remote access trojan (RAT) functionality
- Information theft and credential harvesting
- Dynamic C2 IP address updates via registry
- Persistent system access
- User session hijacking

**Technical Features**:
- Registry-based configuration (HKEY_CURRENT_USER\SOFTWARE\HHClient)
- C2 command 0x15 for IP updates (AdrrStrChar value)
- Termination command 0x17
- Process injection into taskhostw.exe
- WTSEnumerateSessions for session enumeration

**Debug Artifacts**:
```
D:\Workspace\HoldingHands-develop\HoldingHands-develop\Door\x64\Release\BackDoor.pdb
```

### Winos 4.0 (Initial Phase - March 2024 to February 2025)
**Description**: Malware family used in early campaign phases

**Campaigns**:
- China operations (March 2024)
- Taiwan operations (January 2025)
- Replaced by HoldingHands in February 2025

## Multi-Stage Execution Chain

### Stage 1: Initial Access (Phishing)
**Vector**: Spearphishing attachments
- **File Types**: PDF, Excel, Word documents, HTML files
- **Lures**: Ministry of Finance documents, tax regulations, purchase orders
- **Links**: Tencent Cloud storage + Custom domains (tw-pattern)
- **Geographic Localization**: Language-appropriate lures per target region

**Tencent Cloud Infrastructure**:
- Account ID: 1321729461
- Account ID: 1329400280
- Links embedded in phishing documents

### Stage 2: Malware Download
**Delivery**: Custom domain infrastructure
- **Domains**: twsww[.]xin, twswzz[.]xin, twczb[.]com
- **Method**: JavaScript-based dynamic link fetching from JSON
- **Package**: ZIP archives containing signed executables
- **Social Engineering**: "Dokumen audit cukai dan sampel bahan.exe" (tax audit document)

### Stage 3: Initial Execution (dokan2.dll)
**Technique**: DLL Side-Loading (T1574.002)
- **File**: dokan2.dll
- **Method**: Masquerades as legitimate Dokany library
- **Loader**: Legitimate Dokany control program
- **Function**: Shellcode loader for sw.dat
- **Evasion**: Code signing with legitimate digital signature

### Stage 4: Environment Setup (sw.dat)
**Function**: Privilege escalation and environment preparation
- **Anti-VM**: Physical RAM checks to detect virtual machines
- **Privilege Escalation**: TrustedInstaller service thread impersonation (T1134.001)
- **File Dropping**: Creates necessary files for subsequent stages
- **Anti-AV**: Security product process detection

### Stage 5: Persistence (TimeBrokerClient.dll)
**Technique**: Task Scheduler Abuse (T1053.005)
- **File**: TimeBrokerClient.dll
- **Trigger**: Windows Task Scheduler service restart
- **Validation**: Process name ASCII sum must equal 0x47A (svchost.exe)
- **Dependencies**: 
  - svchost.ini (contains VirtualAlloc RVA for dynamic API resolution)
  - msvchost.dat (encrypted shellcode data)
- **Decryption**: Process name (svchost.exe) used as decryption key
- **Detection Evasion**: No direct process launch required; triggered by service recovery

### Stage 6: Shellcode Execution (msvchost.dat)
**Function**: User context preparation and payload injection
- **Command Line Validation**:
  ```
  C:\windows\system32\svchost.exe -k netsvcs -p -s Schedule
  ```
- **Session Enumeration**: WTSEnumerateSessions API to find active user sessions
- **Token Duplication**: Copies logged-on user's access token
- **Process Creation**: CreateProcessAsUserW launches taskhostw.exe with user context
- **Payload Injection**: Injects decrypted system.dat (HoldingHands) into taskhostw.exe
- **Monitoring**: Checks taskhostw.exe status every 5 seconds; reinjects if terminated

### Stage 7: Final Payload (HoldingHands in taskhostw.exe)
**Function**: Backdoor and information theft
- **C2 Communication**: Connects to attacker infrastructure
- **Data Exfiltration**: Steals sensitive information
- **Dynamic Updates**: Receives C2 IP updates via command 0x15
- **Configuration**: Stored in HKEY_CURRENT_USER\SOFTWARE\HHClient

## MITRE ATT&CK Framework Mapping

This campaign demonstrates **34 unique MITRE ATT&CK techniques** across **10 tactics**:

### Reconnaissance (1 technique)
- **T1589.002**: Gather Victim Identity Information: Email Addresses

### Initial Access (2 techniques)
- **T1566.001**: Phishing: Spearphishing Attachment (PDF/Excel/Word)
- **T1566.002**: Phishing: Spearphishing Link (Embedded malicious links)

### Execution (3 techniques)
- **T1204.002**: User Execution: Malicious File
- **T1059.003**: Command and Scripting Interpreter: Windows Command Shell
- **T1053.005**: Scheduled Task/Job: Scheduled Task

### Persistence (3 techniques)
- **T1574.002**: Hijack Execution Flow: DLL Side-Loading
- **T1547.001**: Boot or Logon Autostart Execution: Registry Run Keys
- **T1053.005**: Scheduled Task/Job: Scheduled Task

### Privilege Escalation (4 techniques)
- **T1134.001**: Access Token Manipulation: Token Impersonation/Theft
- **T1055.001**: Process Injection: Dynamic-link Library Injection
- **T1574.002**: DLL Side-Loading
- **T1053.005**: Scheduled Task

### Defense Evasion (9 techniques)
- **T1140**: Deobfuscate/Decode Files or Information
- **T1027**: Obfuscated Files or Information
- **T1562.001**: Impair Defenses: Disable or Modify Tools
- **T1497.001**: Virtualization/Sandbox Evasion: System Checks
- **T1036.005**: Masquerading: Match Legitimate Name or Location
- **T1553.002**: Subvert Trust Controls: Code Signing
- **T1055.012**: Process Injection: Process Hollowing
- **T1112**: Modify Registry
- **T1574.002**: DLL Side-Loading

### Discovery (4 techniques)
- **T1082**: System Information Discovery
- **T1057**: Process Discovery
- **T1033**: System Owner/User Discovery
- **T1124**: System Time Discovery

### Collection (2 techniques)
- **T1005**: Data from Local System
- **T1113**: Screen Capture

### Command and Control (5 techniques)
- **T1071.001**: Application Layer Protocol: Web Protocols
- **T1573**: Encrypted Channel
- **T1008**: Fallback Channels (Dynamic C2 IP updates)
- **T1102**: Web Service (Tencent Cloud abuse)
- **T1219**: Remote Access Software

### Exfiltration (1 technique)
- **T1041**: Exfiltration Over C2 Channel

## Detection Recommendations

### Network Monitoring

#### Domain-Based Detection
Monitor for connections to identified malicious domains:
```
zxp0010w.vip
gjqygs.cn
zcqiyess.vip
jpjpz1.cc
jppjp.vip
jpjpz1.top
twczb.com
twsww.xin
twswzz.xin
```

**Detection Rules**:
- Alert on DNS queries to domains containing "tw" + short alphanumeric strings
- Monitor for Tencent Cloud storage downloads from Account IDs 1321729461, 1329400280
- Implement domain reputation filtering

#### IP-Based Detection
Block and monitor C2 server IP addresses:
```
206.238.199.22
206.238.221.244
206.238.221.182
154.91.64.45
156.251.17.12
156.251.17.9
38.60.203.110
```

**Detection Rules**:
- Alert on outbound connections to identified C2 IPs
- Monitor for beaconing patterns (regular intervals)
- Detect encrypted traffic to non-standard ports

#### Traffic Pattern Detection
- **Tencent Cloud Abuse**: Unusual download volumes or patterns
- **Dynamic Link Fetching**: JavaScript requests to JSON data for download URLs
- **Beaconing Behavior**: Regular C2 communication patterns

### Endpoint Detection

#### File-Based Detection

**Hash-Based Detection** (SHA256):
```
c138ff7d0b46a657c3a327f4eb266866957b4117c0507507ba81aaeb42cdefa9
03e1cdca2a9e08efa8448e20b50dc63fdbea0e850de25c3a8e04b03e743b983d
2b1719108ec52e5dea20169a225b7d383ad450195a5e6274315c79874f448caa
dc45981ff705b641434ff959de5f8d4c12341eaeda42d278bd4e46628df94ac5
0db506d018413268e441a34e6e134c9f5a33ceea338fc323d231de966401bb2c
031c916b599e17d8cfa13089bddafc2436be8522f0c9e479c7d76ba3010bbd18
c6095912671a201dad86d101e4fe619319cc22b10b4e8d74c3cd655b2175364c
804dc39c1f928964a5c02d129da72c836accf19b8f6d8dc69fc853ce5f65b4f3
1c4bc67ae4af505f58bd11399d45e196fc17cc5dd32ad1d8e6836832d59df6e6
fb9c9ed91fc70f862876bd77314d3b2275069ca7c4db045e5972e726a3e8e04c
8d25da6459c427ad658ff400e1184084db1789a7abff9b70ca85cf57f4320283
```

**Filename-Based Detection**:
- dokan2.dll (in non-Dokany directories)
- sw.dat
- TimeBrokerClient.dll (in non-system directories)
- svchost.ini (outside standard locations)
- msvchost.dat
- system.dat
- Files matching pattern: *audit*cukai*.exe

#### Registry-Based Detection

**Monitor Registry Operations**:
```
HKEY_CURRENT_USER\SOFTWARE\HHClient (Creation or modification)
HKEY_CURRENT_USER\SOFTWARE\HHClient\AdrrStrChar (Value changes)
```

**Detection Rules**:
- Alert on HHClient registry key creation
- Monitor for AdrrStrChar value modifications (C2 IP updates)
- Track unusual registry modifications by svchost.exe or taskhostw.exe

#### Process-Based Detection

**Suspicious Process Patterns**:
1. **svchost.exe spawning taskhostw.exe**: Unusual parent-child relationship
2. **Task Scheduler service restarts**: Frequent or unusual restarts
3. **DLL Loading**: 
   - dokan2.dll loaded by non-Dokany executables
   - TimeBrokerClient.dll loaded by svchost.exe from non-system paths

**API Call Monitoring**:
- WTSEnumerateSessions from unexpected processes
- CreateProcessAsUserW with unusual parameters
- VirtualAlloc with suspicious memory patterns
- Token manipulation APIs (OpenProcessToken, DuplicateTokenEx)

**Command Line Detection**:
```
C:\windows\system32\svchost.exe -k netsvcs -p -s Schedule
```
- Monitor for svchost.exe executing with Schedule service parameter
- Alert on unusual command line patterns

#### Behavioral Detection

**Anti-Analysis Behaviors**:
- Physical RAM checks (anti-VM)
- Process name ASCII sum calculations (0x47A validation)
- Security product process enumeration
- Command line validation checks

**Privilege Escalation**:
- TrustedInstaller service thread impersonation
- User token duplication
- Elevation attempts from normal user context

**Persistence Mechanisms**:
- Task Scheduler modifications
- DLL side-loading attempts
- Registry key persistence (HHClient)

### Email Security

#### Phishing Detection

**Attachment Analysis**:
- PDF files with embedded links (especially Tencent Cloud)
- Excel macros with suspicious behavior
- Word documents with external links
- HTML files redirecting to download pages

**Subject Line Patterns** (by region):
- **China**: 税务文件, 财务报告 (Tax documents, Financial reports)
- **Taiwan**: 財政部, 稅務規範 (Ministry of Finance, Tax regulations)
- **Japan**: 税務監査, 財務書類 (Tax audit, Financial documents)
- **Malaysia**: Cukai, Dokumen kewangan (Tax, Financial documents)

**Link Analysis**:
- Tencent Cloud links with Account IDs 1321729461, 1329400280
- Domains with "tw" patterns
- JavaScript-based dynamic download links

**Sender Spoofing**:
- Government ministry impersonation
- Finance department spoofing
- Fake purchase orders

## YARA Rules

### Rule 1: HoldingHands Registry Artifacts
```yara
rule HoldingHands_Registry_Artifacts {
    meta:
        description = "Detects HoldingHands malware registry artifacts"
        author = "ThreatOps-for-MISP"
        date = "2025-10-18"
        reference = "https://www.fortinet.com/blog/threat-research/tracking-malware-and-attack-expansion-a-hacker-groups-journey-across-asia"
        threat_level = "High"
        malware_family = "HoldingHands"
    
    strings:
        $reg1 = "HHClient" ascii wide
        $reg2 = "AdrrStrChar" ascii wide
        $reg3 = "SOFTWARE\\HHClient" ascii wide
        $cmd1 = "svchost.exe -k netsvcs -p -s Schedule" ascii wide
    
    condition:
        any of them
}
```

### Rule 2: HoldingHands File Artifacts
```yara
rule HoldingHands_File_Artifacts {
    meta:
        description = "Detects HoldingHands malware file artifacts"
        author = "ThreatOps-for-MISP"
        date = "2025-10-18"
        reference = "https://www.fortinet.com/blog/threat-research/tracking-malware-and-attack-expansion-a-hacker-groups-journey-across-asia"
        threat_level = "High"
        malware_family = "HoldingHands"
    
    strings:
        $f1 = "dokan2.dll" ascii wide
        $f2 = "sw.dat" ascii wide
        $f3 = "msvchost.dat" ascii wide
        $f4 = "svchost.ini" ascii wide
        $f5 = "TimeBrokerClient.dll" ascii wide
        $f6 = "system.dat" ascii wide
        $path1 = "HoldingHands-develop" ascii wide
        $path2 = "BackDoor.pdb" ascii wide
    
    condition:
        2 of ($f*) or any of ($path*)
}
```

### Rule 3: HoldingHands Behavior Detection
```yara
rule HoldingHands_Behavior_Detection {
    meta:
        description = "Detects HoldingHands malware behavioral patterns"
        author = "ThreatOps-for-MISP"
        date = "2025-10-18"
        reference = "https://www.fortinet.com/blog/threat-research/tracking-malware-and-attack-expansion-a-hacker-groups-journey-across-asia"
        threat_level = "High"
        malware_family = "HoldingHands"
    
    strings:
        $api1 = "WTSEnumerateSessions" ascii wide
        $api2 = "CreateProcessAsUserW" ascii wide
        $api3 = "VirtualAlloc" ascii wide
        $api4 = "OpenProcessToken" ascii wide
        $api5 = "DuplicateTokenEx" ascii wide
        $process1 = "taskhostw.exe" ascii wide
        $process2 = "svchost.exe" ascii wide
    
    condition:
        3 of ($api*) or (any of ($api*) and any of ($process*))
}
```

### Rule 4: HoldingHands Debug Paths
```yara
rule HoldingHands_Debug_Path {
    meta:
        description = "Detects HoldingHands development artifacts in debug paths"
        author = "ThreatOps-for-MISP"
        date = "2025-10-18"
        reference = "https://www.fortinet.com/blog/threat-research/tracking-malware-and-attack-expansion-a-hacker-groups-journey-across-asia"
        threat_level = "High"
        malware_family = "HoldingHands"
    
    strings:
        $debug_path = "D:\\Workspace\\HoldingHands-develop\\HoldingHands-develop\\Door\\x64\\Release\\BackDoor.pdb" ascii wide
        $project1 = "HoldingHands-develop" ascii wide
        $project2 = "BackDoor.pdb" ascii wide
    
    condition:
        $debug_path or (all of ($project*))
}
```

## Sigma Rules

### Rule 1: HoldingHands DLL Side-Loading Detection
```yaml
title: HoldingHands DLL Side-Loading Detection
id: a1b2c3d4-e5f6-7890-a1b2-c3d4e5f67890
status: stable
description: Detects DLL side-loading techniques used by HoldingHands malware
author: ThreatOps-for-MISP
date: 2025/10/18
references:
    - https://www.fortinet.com/blog/threat-research/tracking-malware-and-attack-expansion-a-hacker-groups-journey-across-asia
tags:
    - attack.persistence
    - attack.privilege_escalation
    - attack.defense_evasion
    - attack.t1574.002
logsource:
    category: image_load
    product: windows
detection:
    selection_dll:
        ImageLoaded|endswith:
            - '\dokan2.dll'
            - '\TimeBrokerClient.dll'
    filter_legitimate_path:
        ImageLoaded|startswith:
            - 'C:\Windows\System32\'
            - 'C:\Windows\SysWOW64\'
            - 'C:\Program Files\Dokan\'
            - 'C:\Program Files (x86)\Dokan\'
    condition: selection_dll and not filter_legitimate_path
falsepositives:
    - Legitimate Dokany software installations
level: high
```

### Rule 2: HoldingHands Task Scheduler Abuse
```yaml
title: HoldingHands Task Scheduler Service Abuse
id: b2c3d4e5-f6a7-8901-b2c3-d4e5f6a78901
status: stable
description: Detects Task Scheduler abuse for persistence used by HoldingHands malware
author: ThreatOps-for-MISP
date: 2025/10/18
references:
    - https://www.fortinet.com/blog/threat-research/tracking-malware-and-attack-expansion-a-hacker-groups-journey-across-asia
tags:
    - attack.execution
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1053.005
logsource:
    category: process_creation
    product: windows
detection:
    selection_svchost:
        Image|endswith: '\svchost.exe'
        CommandLine|contains|all:
            - '-k netsvcs'
            - '-p'
            - '-s Schedule'
    selection_child:
        ParentImage|endswith: '\svchost.exe'
        Image|endswith: '\taskhostw.exe'
    condition: selection_svchost or selection_child
falsepositives:
    - Legitimate Task Scheduler operations
level: medium
```

### Rule 3: HoldingHands Registry Persistence
```yaml
title: HoldingHands Registry Persistence Detection
id: c3d4e5f6-a7b8-9012-c3d4-e5f6a7b89012
status: stable
description: Detects HoldingHands malware registry-based persistence and configuration
author: ThreatOps-for-MISP
date: 2025/10/18
references:
    - https://www.fortinet.com/blog/threat-research/tracking-malware-and-attack-expansion-a-hacker-groups-journey-across-asia
tags:
    - attack.persistence
    - attack.defense_evasion
    - attack.t1547.001
    - attack.t1112
logsource:
    category: registry_event
    product: windows
detection:
    selection_key:
        TargetObject|contains:
            - 'SOFTWARE\HHClient'
            - 'HHClient\AdrrStrChar'
    selection_value:
        Details|re: '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'  # IP address pattern
    condition: selection_key or (selection_key and selection_value)
falsepositives:
    - Unknown legitimate software using HHClient registry key (unlikely)
level: high
```

### Rule 4: HoldingHands Token Manipulation
```yaml
title: HoldingHands Token Impersonation Detection
id: d4e5f6a7-b8c9-0123-d4e5-f6a7b8c90123
status: stable
description: Detects token impersonation techniques used by HoldingHands malware
author: ThreatOps-for-MISP
date: 2025/10/18
references:
    - https://www.fortinet.com/blog/threat-research/tracking-malware-and-attack-expansion-a-hacker-groups-journey-across-asia
tags:
    - attack.privilege_escalation
    - attack.defense_evasion
    - attack.t1134.001
logsource:
    product: windows
    category: process_access
detection:
    selection_trustedinstaller:
        TargetImage|endswith: '\TrustedInstaller.exe'
        GrantedAccess:
            - '0x1400'  # PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
            - '0x1410'  # PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_DUP_HANDLE
    selection_api:
        CallTrace|contains:
            - 'OpenProcessToken'
            - 'DuplicateTokenEx'
            - 'ImpersonateLoggedOnUser'
    condition: selection_trustedinstaller or selection_api
falsepositives:
    - System maintenance tools
    - Security software
level: high
```

### Rule 5: HoldingHands WTSEnumerateSessions API Call
```yaml
title: HoldingHands Session Enumeration Detection
id: e5f6a7b8-c9d0-1234-e5f6-a7b8c9d01234
status: stable
description: Detects suspicious WTSEnumerateSessions API calls used by HoldingHands
author: ThreatOps-for-MISP
date: 2025/10/18
references:
    - https://www.fortinet.com/blog/threat-research/tracking-malware-and-attack-expansion-a-hacker-groups-journey-across-asia
tags:
    - attack.discovery
    - attack.t1033
logsource:
    category: sysmon
    product: windows
detection:
    selection:
        EventID: 10  # Process access
        CallTrace|contains: 'WTSEnumerateSessions'
    filter_legitimate:
        SourceImage|startswith:
            - 'C:\Windows\System32\'
            - 'C:\Windows\SysWOW64\'
            - 'C:\Program Files\Windows Defender\'
    condition: selection and not filter_legitimate
falsepositives:
    - Remote desktop management tools
    - System administration software
level: medium
```

## IOCs Summary

### Critical Priority Indicators

#### C2 Infrastructure (Block Immediately)
**Domains** (9):
- zxp0010w.vip
- gjqygs.cn
- zcqiyess.vip
- jpjpz1.cc
- jppjp.vip
- jpjpz1.top
- twczb.com
- twsww.xin
- twswzz.xin

**IP Addresses** (7):
- 206.238.199.22
- 206.238.221.244
- 206.238.221.182
- 154.91.64.45
- 156.251.17.12
- 156.251.17.9 (Shared between Taiwan and Japan campaigns)
- 38.60.203.110

#### Malware Samples (11 SHA256 hashes)
All hashes listed in Attribute section above

### High Priority Indicators

#### File Artifacts
- dokan2.dll (non-Dokany directories)
- sw.dat
- TimeBrokerClient.dll (non-system paths)
- svchost.ini (non-system locations)
- msvchost.dat
- system.dat

#### Registry Indicators
- HKEY_CURRENT_USER\SOFTWARE\HHClient (any operations)
- HKEY_CURRENT_USER\SOFTWARE\HHClient\AdrrStrChar (IP address values)

### Medium Priority Indicators

#### Infrastructure Patterns
- Tencent Cloud Account IDs: 1321729461, 1329400280
- Domains with "tw" + alphanumeric patterns
- Debug paths containing "HoldingHands-develop"

#### Behavioral Patterns
- svchost.exe → taskhostw.exe process chain
- Task Scheduler service frequent restarts
- WTSEnumerateSessions API calls from unusual processes

## Threat Hunting Queries

### Hunt 1: Registry-Based C2 Configuration
```powershell
# PowerShell query to detect HHClient registry keys
Get-ChildItem -Path "HKCU:\SOFTWARE" -Recurse | Where-Object { $_.Name -like "*HHClient*" }
Get-ItemProperty -Path "HKCU:\SOFTWARE\HHClient" -Name "AdrrStrChar" -ErrorAction SilentlyContinue
```

### Hunt 2: Suspicious DLL Files
```powershell
# Search for HoldingHands-related DLL files
Get-ChildItem -Path C:\ -Recurse -Include dokan2.dll,TimeBrokerClient.dll -ErrorAction SilentlyContinue | 
    Where-Object { $_.DirectoryName -notlike "*Dokan*" -and $_.DirectoryName -notlike "*System32*" }
```

### Hunt 3: DAT Files in Suspicious Locations
```powershell
# Search for .dat files commonly used by HoldingHands
Get-ChildItem -Path C:\ -Recurse -Include sw.dat,msvchost.dat,system.dat -ErrorAction SilentlyContinue
```

### Hunt 4: Task Scheduler Service Activity
```powershell
# Check for unusual Task Scheduler service restarts
Get-EventLog -LogName System -Source "Service Control Manager" | 
    Where-Object { $_.Message -like "*Schedule*" -and $_.EntryType -eq "Warning" }
```

### Hunt 5: Process Token Manipulation
```powershell
# Sysmon Event ID 10 - TrustedInstaller access
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=10} | 
    Where-Object { $_.Message -like "*TrustedInstaller.exe*" }
```

### Hunt 6: Network Connections to C2 IPs
```powershell
# Check for connections to known C2 IPs
$C2IPs = @('206.238.199.22','206.238.221.244','206.238.221.182','154.91.64.45','156.251.17.12','156.251.17.9','38.60.203.110')
Get-NetTCPConnection | Where-Object { $C2IPs -contains $_.RemoteAddress }
```

## Fortinet Protection

### FortiGuard Antivirus Signatures
The following signatures detect HoldingHands and related malware:

- **XML/Agent.EFA9!tr**: Phishing document detection
- **W64/ShellcodeRunner.ARG!tr**: Shellcode loader detection (dokan2.dll, sw.dat)
- **W64/Agent.BDN!tr**: HoldingHands malware detection

### Fortinet Product Coverage

#### FortiGate
- **Real-time threat detection**: Blocks malware at network perimeter
- **IPS Protection**: Detects multi-stage execution patterns
- **Application Control**: Blocks unauthorized cloud storage access
- **DNS Filtering**: Blocks malicious domains

#### FortiMail
- **Phishing Detection**: Identifies government document impersonation
- **Virus Scanning**: Detects malicious attachments (PDF/Excel/Word)
- **Antivirus Signature Updates**: FortiGuard signatures applied
- **URL Reputation**: Blocks embedded malicious links

#### FortiClient
- **Endpoint Protection**: Real-time malware scanning
- **Vulnerability Scanning**: Identifies vulnerable systems
- **Threat Intelligence**: Synchronized with FortiGuard updates
- **Application Firewall**: Blocks unauthorized network connections

#### FortiEDR
- **Behavioral Analysis**: Detects multi-stage execution chains
- **Process Monitoring**: Identifies DLL side-loading and injection
- **Registry Monitoring**: Alerts on HHClient key creation/modification
- **Automated Response**: Isolates compromised endpoints

#### FortiSandbox
- **Dynamic Analysis**: Executes suspicious files in isolated environment
- **Anti-Phishing**: Real-time analysis of email attachments
- **Network Behavior**: Detects C2 communication patterns
- **Integration**: Feeds intelligence to FortiGate and FortiMail

#### FortiGuard CDR (Content Disarm & Reconstruction)
- **Document Sanitization**: Removes macros and embedded objects
- **PDF Processing**: Strips malicious links from PDF documents
- **Office Document Security**: Disarms Excel and Word macros
- **Availability**: FortiGate and FortiMail integration

### Recommended Fortinet Configuration

1. **Enable FortiGuard Antivirus**: Ensure real-time updates
2. **Deploy FortiSandbox**: For advanced attachment analysis
3. **Configure Email Filtering**: Block government document keywords in suspicious emails
4. **Enable CDR**: For all document attachments (PDF/Office)
5. **IPS Signatures**: Enable signatures for DLL side-loading and Task Scheduler abuse
6. **Application Control**: Restrict cloud storage access (Tencent Cloud)
7. **Web Filtering**: Block identified malicious domains
8. **Endpoint Protection**: Deploy FortiClient to all workstations

## Mitigation Strategies

### Immediate Actions (0-24 hours)

1. **Block Network IOCs**
   - Add all domains and IPs to block lists
   - Configure DNS sinkholing for identified domains
   - Enable network segmentation to limit lateral movement

2. **Hunt for Compromise**
   - Search for HHClient registry keys across environment
   - Scan for identified file hashes
   - Review email logs for phishing attempts

3. **User Awareness**
   - Alert users about government document impersonation
   - Warn against opening unexpected PDF/Excel/Word attachments
   - Report suspicious emails to security team

### Short-Term Actions (1-7 days)

1. **Enhanced Monitoring**
   - Deploy Sigma rules for Task Scheduler abuse
   - Monitor for DLL side-loading attempts
   - Alert on registry modifications (HHClient)
   - Track svchost.exe → taskhostw.exe process chains

2. **Email Security**
   - Implement advanced attachment scanning
   - Deploy CDR for all Office documents and PDFs
   - Block Tencent Cloud links from Account IDs 1321729461, 1329400280
   - Enhance phishing simulation training

3. **Endpoint Hardening**
   - Deploy YARA rules across endpoints
   - Enable application whitelisting
   - Configure Task Scheduler auditing
   - Restrict DLL loading policies

### Long-Term Strategies (1-3 months)

1. **Architecture Improvements**
   - Implement Zero Trust architecture
   - Deploy EDR/XDR solutions
   - Enhance network segmentation
   - Implement microsegmentation for critical systems

2. **User Training**
   - Conduct phishing awareness training (Fortinet NSE FCF)
   - Region-specific social engineering education
   - Government document verification procedures
   - Incident reporting processes

3. **Threat Intelligence**
   - Subscribe to Asia-Pacific threat feeds
   - Monitor for campaign evolution
   - Track new domains with "tw" patterns
   - Collaborate with regional CERTs

4. **Incident Response**
   - Develop multi-stage malware playbooks
   - Test response procedures
   - Establish communication channels
   - Define escalation procedures

## Additional Context

### Campaign Attribution Confidence
- **Infrastructure Reuse**: HIGH - Same Tencent Cloud accounts and domain patterns
- **Code Reuse**: HIGH - Identical JavaScript download page code across campaigns
- **Geographic Expansion**: HIGH - Clear progression with shared C2 infrastructure
- **Development Artifacts**: MEDIUM - Debug paths reveal project structure
- **Threat Actor Identity**: LOW - No specific attribution to known APT groups

### Victim Impact Assessment
- **Severity**: HIGH
- **Data at Risk**: Credentials, sensitive documents, system information
- **Business Impact**: Data theft, persistent access, potential espionage
- **Recovery Complexity**: HIGH - Multi-stage malware requires thorough remediation

### Intelligence Gaps
1. **Attribution**: Specific threat actor identity unknown
2. **Data Exfiltration**: Exact types of data targeted unclear
3. **Command Structure**: Full C2 protocol and commands not documented
4. **Additional Payloads**: Possible secondary payloads or modules unknown
5. **Future Targets**: Next geographic expansion destination uncertain

### Recommended Follow-Up Actions
1. Share IOCs with regional threat intelligence communities
2. Collaborate with CERTs in China, Taiwan, Japan, Malaysia
3. Monitor for new domain registrations with "tw" patterns
4. Track HoldingHands malware development via debug path artifacts
5. Engage Fortinet Global FortiGuard Incident Response if compromised

## References

### Primary Source
- **Fortinet FortiGuard Labs**: "Tracking Malware and Attack Expansion: A Hacker Group's Journey across Asia"
  - URL: https://www.fortinet.com/blog/threat-research/tracking-malware-and-attack-expansion-a-hacker-groups-journey-across-asia
  - Publication Date: October 17, 2025
  - Author: Pei Han Liao

### Additional Resources
- **Fortinet NSE Training**: FCF - Fortinet Certified Fundamentals (Free phishing awareness training)
- **FortiGuard Incident Response**: Contact for suspected compromise
- **MITRE ATT&CK Framework**: v14 (Enterprise)

## MISP Event Export

This threat intelligence can be imported into MISP using the accompanying JSON file:
- **File**: `HoldingHands_Asia_Expansion_Campaign_MISP_Event.json`
- **Format**: MISP Core Format
- **Attributes**: 67 indicators
- **Tags**: 24 tags (TLP, MITRE ATT&CK, country targeting, malware classification)
- **Galaxies**: Threat Actor, Tool, MITRE ATT&CK patterns

### Import Instructions
1. Access MISP web interface
2. Navigate to Events → Add Event
3. Import JSON file
4. Review attributes and relationships
5. Publish to sharing communities (optional)

## Contact Information

For additional information or to report incidents related to this campaign:
- **Fortinet Global FortiGuard Incident Response**: Contact through official channels
- **Repository**: ThreatOps-for-MISP (GitHub)
- **Classification**: TLP:WHITE (Unrestricted sharing)

---

**Document Classification**: TLP:WHITE  
**Report Date**: October 18, 2025  
**Last Updated**: October 18, 2025  
**Version**: 1.0  
**Analyst**: ThreatOps-for-MISP  
**Review Status**: Complete


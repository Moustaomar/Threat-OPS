# Colombian Judicial Notification SVG AsyncRAT Campaign - Comprehensive Threat Analysis

## Executive Summary

In October 2025, security researchers at Seqrite identified a sophisticated phishing campaign targeting Colombian users with judicial notification lures. The campaign leverages Scalable Vector Graphics (SVG) files—a rarely exploited attack vector—to deliver AsyncRAT, an open-source remote access trojan. The operation demonstrates advanced social engineering through impersonation of Colombian judicial institutions, specifically the 17th Municipal Civil Court of Bogotá, combined with a multi-stage infection chain designed to evade detection.

**Source**: Seqrite Security Research  
**Reference**: https://www.seqrite.com/blog/judicial-notification-phish-colombia-svg-asyncrat/  
**Publication Date**: October 13, 2025  
**Campaign Status**: Active (October 2025)

### Key Findings

- **Geographic Focus**: Colombia (specifically Bogotá)
- **Language**: Spanish-language campaign with localized content
- **Attack Vector**: Phishing emails with malicious .SVG attachments
- **Final Payload**: AsyncRAT Remote Access Trojan
- **Infection Stages**: 7-stage multi-layered infection chain
- **Target Injection**: Legitimate MSBuild.exe process
- **Sophistication**: High (geotargeting, institutional impersonation, advanced evasion)

## Threat Overview

### Campaign Characteristics

**Target Region**: Colombia (Capital: Bogotá)  
**Primary Vector**: Phishing with .SVG attachment  
**Impersonated Entity**: Juzgado 17 Civil Municipal del Circuito de Bogotá  
**Malware Family**: AsyncRAT (C# .NET Remote Access Trojan)  
**Severity Level**: High  
**Affected Platform**: Microsoft Windows (.NET Framework 4.0+)

### Social Engineering Context

The campaign exploits Colombia's judicial system for social engineering, specifically impersonating:
- **Institution**: 17th Municipal Civil Court of Bogotá Circuit
- **Authority**: Attorney General's Office (Fiscalía General de la Nación)
- **Document Type**: Official judicial notifications and lawsuit documents

Bogotá, as Colombia's capital, hosts numerous government institutions including courts, ministries, and official bodies, making such impersonation highly credible to local recipients.

## Initial Access - Phishing Campaign

### Email Composition

**Subject Line** (Spanish):  
`Demanda judicial en su contra – Juzgado 17 Civil Municipal`

**Translation**:  
`Judicial lawsuit against you - Municipal Civil Court 17`

**Email Body** (Spanish):
```
Adjunto encontrará una demanda judicial interpuesta en su contra.
Juzgado 17 Civil Municipal del Circuito de Bogotá
11 de septiembre de 2025
Atentamente,
Sistema de Notificaciones Judiciales
```

**Translation**:
```
Attached is a lawsuit filed against you.
17th Municipal Civil Court of the Bogotá Circuit
September 11, 2025
Sincerely,
Judicial Notification System
```

### Social Engineering Tactics

1. **Authority Impersonation**: Uses official judicial institution names
2. **Urgency Creation**: Legal lawsuit notification creates immediate concern
3. **Legitimacy Indicators**: Formal language, institutional naming, date stamping
4. **Geographic Relevance**: References capital city institutions familiar to Colombians
5. **Fear Exploitation**: Threat of legal action compels immediate attention

### Attachment Details

**Filename**: `Fiscalia General De La Nacion Juzgado Civil 17.svg`  
**Translation**: "Attorney General's Office Civil Court 17.svg"  
**File Type**: SVG (Scalable Vector Graphics)  
**File Size**: 2.66 MB  
**Notable**: Unusually large for SVG due to embedded Base64 payloads

## Multi-Stage Infection Chain Analysis

### Stage 1: SVG File Exploitation

#### Why SVG Files?

Scalable Vector Graphics (SVG) files are XML-based image format that can embed:
- JavaScript code
- External resource references
- Base64-encoded content
- Interactive elements

**Attacker Advantages**:
- **Low Detection**: Many security solutions don't scan SVG files deeply
- **Legitimate Format**: Not typically blocked by email filters
- **FUD Status**: Fully Undetected at campaign launch (very low AV detection)
- **Execution Context**: Opens in web browser, bypassing some OS-level protections

#### SVG Technical Analysis

The malicious SVG contains several key elements:

```xml
<style="cursor:pointer;">
```
- Makes the image appear clickable

```javascript
onclick="openDocument()"
```
- JavaScript function triggered on click

**Function: openDocument()**
1. Accepts Base64-encoded embedded data
2. Decodes it to attacker-controlled HTML blob
3. Creates temporary URL object for blob
4. Opens URL in new browser tab

**Embedded Content**: Fake judicial web page with download trigger

### Stage 2: Fake Web Page & HTA Dropper

#### Fake Judicial Portal

The decoded SVG opens a convincing fake web page featuring:
- **Title**: Attorney General's Office and Citizen's Consultation Portal
- **Elements**: 
  - Judicial Information System logo
  - Fake consultation registration number
  - "Rama Judicial" (Judicial Branch) branding
  - Progress bar UI (fake loading animation)
- **Call-to-Action**: "DOWNLOAD DOCUMENT" button

#### HTA File Deployment

**Technical Process**:
1. JavaScript decodes another Base64 blob
2. Creates download for `DOCUMENTO_OFICIAL_JUZGADO.HTA`
3. Browser forces automatic download

**File**: DOCUMENTO_OFICIAL_JUZGADO.HTA  
**Translation**: "OFFICIAL_COURT_DOCUMENT.HTA"  
**Size**: 577.36 KB  
**Type**: HTML Application (executes Windows scripts)

**HTA Characteristics**:
- Contains extensive junk code for obfuscation
- Embeds large Base64-encoded VBS dropper
- Decodes and writes `actualiza.vbs` to disk
- Executes VBS automatically

### Stage 3: Visual Basic Script Dropper

**File**: actualiza.vbs  
**Size**: 376.85 KB  
**Encoding**: UTF-16 LE (Little Endian)

#### Obfuscation Techniques

1. **Junk Code**: Repetitive meaningless lines
2. **Character Substitution**: "9&" used instead of "A"
3. **Base64 Encoding**: Additional encoding layer
4. **Variable Naming**: Obfuscated variable names (GftsOTSaty)

#### Functionality

Writes embedded PowerShell script to disk:
- **Output File**: veooZ.ps1
- **Method**: Decodes Base64 after character replacement
- **Execution**: Runs PowerShell script

### Stage 4: PowerShell Downloader

**File**: veooZ.ps1  
**Primary Function**: Download encoded payload from external source

#### Download Process

```powershell
# Connects to dpaste domain
# Downloads: Ysemg.txt (plain text file)
```

**Downloaded File**: Ysemg.txt  
**Content**: Raw text with encoded .NET assembly

#### Decoding Process

1. Replace "$$" with letter "A"
2. Base64 decode resulting string
3. Output: ClassLibrary3.dll (.NET assembly)

#### DLL Invocation

```powershell
# Invokes method: MSqBIbY
# Passes two arguments:
# 1. Base64-encoded URL string
# 2. Path to .vbs file (backslashes replaced with "$")
```

### Stage 5: .NET Downloader/Loader (ClassLibrary3.dll)

**File**: ClassLibrary3.dll  
**Size**: 15.00 KB  
**Type**: PE32 DLL (.NET v4.0.30319)  
**Compiler**: VB.NET

#### Obfuscation

- Heavy code obfuscation
- XOR encryption
- Bit shifting operations
- String manipulation

#### Anti-VM Technique

**WMI Query**: Checks for virtualization indicators
```csharp
SELECT * FROM Win32_ComputerSystem
```

**Checks**:
- Manufacturer field for "VMware", "VirtualBox", "QEMU", "Xen"
- Model field for virtual machine indicators

**Action**: If VM detected, terminates execution

#### Persistence Technique

**Registry Modification**:
```
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
Key: [Malware Name]
Value: [Malware Path]
```

**Purpose**: Execute malware on user login

#### Download and Loader Function

**First Download** (from embedded URL):
- Downloads text file with Base64 content and stars ("*")
- After reversal: "TVqQ" → Base64-encoded "MZ" header (PE file marker)
- Replaces stars with "A"
- Result: MoNtReaL.dll (injector)

**Second Download** (from argument-passed URL):
- Downloads reversed, Base64-encoded file
- Result: Client.exe (AsyncRAT payload)

**Injection Process**:
```csharp
// Load injector DLL
AppDomain.CurrentDomain.Load(MoNtReaL.dll)

// Invoke injection method with two arguments:
// 1. Target process (MSBuild.exe)
// 2. Payload to inject (AsyncRAT)
```

### Stage 6: .NET Injector (MoNtReaL.dll)

**File**: MoNtReaL.dll  
**Size**: 12.00 KB  
**Type**: PE32 DLL (.NET v4.0.30319)  
**Compiler**: VB.NET

#### Process Injection Function

The DLL implements process injection to insert AsyncRAT into MSBuild.exe:

**Injection Steps**:
1. **Process Creation**: Start MSBuild.exe in suspended state
2. **Memory Allocation**: VirtualAllocEx in target process
3. **Payload Write**: WriteProcessMemory to inject AsyncRAT
4. **Thread Creation**: CreateRemoteThread to execute payload
5. **Resume**: Resume target process with malicious code

**Target Process**: MSBuild.exe  
**Reason**: Legitimate Microsoft Build Engine process, trusted by security tools

### Stage 7: AsyncRAT Payload (Client.exe)

**File**: Client.exe  
**Size**: 47.50 KB  
**Type**: PE32 EXE (.NET v4.0.30319)  
**Compiler**: VB.NET  
**Language**: C# (AsyncRAT is open-source C# RAT)

## AsyncRAT Technical Analysis

### Overview

AsyncRAT is an open-source Remote Access Trojan written in C#. The analyzed sample was not obfuscated, allowing detailed analysis of capabilities.

### Persistence Mechanisms

#### Privilege-Based Persistence

**Elevated Privileges** (Administrator):
```cmd
schtasks /create /f /sc onlogon /rl highest /tn "<filename>" /tr "<fullpath>"
```
- Creates scheduled task
- Runs on user logon
- Highest privilege level

**Standard Privileges** (Regular User):
```
Registry: HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\
Value: [Malware Path]
```

### Anti-Analysis Techniques

1. **Anti-VM Detection**
   - WMI queries for virtualization
   - Process name checks
   - Hardware fingerprinting

2. **Anti-Sandbox**
   - Behavioral checks
   - Sleep delays
   - User interaction requirements

3. **AMSI Bypass**
   - Disables Windows Antimalware Scan Interface
   - Prevents script content inspection

4. **Mutex Check**
   - Name: "DcRatMutex_qwqdanchun"
   - Prevents multiple infections

### Surveillance Capabilities

#### Webcam Detection
```csharp
// Checks for camera availability
// Used for later spying/surveillance
```

#### Process Monitoring
**Terminates Analysis Tools**:
- Taskmgr.exe (Task Manager)
- ProcessHacker.exe
- procexp.exe (Process Explorer)
- Other security/monitoring tools

### System Information Gathering

**Collected Data**:
- HWID (Hardware ID)
- Operating System version
- User privileges (admin/standard)
- Camera presence
- Installed antivirus products
- System configuration

### Command & Control

#### Connection Establishment
- TLS-encrypted TCP connection
- MessagePack serialization format
- Secure data transmission

#### Data Transmission
- Packs gathered data into MessagePack objects
- Splits large messages into chunks
- Transmits over encrypted channel

#### Plugin System
- Dynamically loads plugins from C2 server
- Executes additional modules on demand
- Extensible functionality

### Core Capabilities

1. **Remote Desktop Access**: Full GUI control
2. **Keystroke Logging**: Capture keyboard input
3. **File Operations**: Upload/download files
4. **Process Execution**: Run arbitrary commands
5. **Credential Theft**: Extract stored credentials
6. **Screen Capture**: Take screenshots
7. **Webcam Access**: Capture camera feed
8. **Microphone Access**: Record audio
9. **Registry Manipulation**: Modify Windows registry
10. **Data Exfiltration**: Steal sensitive files

## MITRE ATT&CK Mapping

### Reconnaissance
- **T1589.002**: Gather Victim Identity Information: Email Addresses

### Initial Access
- **T1566.001**: Phishing: Spearphishing Attachment (.SVG file)

### Execution
- **T1218.005**: System Binary Proxy Execution: Mshta (HTA execution)
- **T1059.001**: Command and Scripting Interpreter: PowerShell
- **T1059.005**: Command and Scripting Interpreter: Visual Basic

### Persistence
- **T1547.001**: Boot or Logon Autostart Execution: Registry Run Keys
- **T1053.005**: Scheduled Task/Job: Scheduled Task

### Defense Evasion
- **T1027**: Obfuscated Files or Information (Base64, reversed strings, junk code)
- **T1562.001**: Impair Defenses: Disable or Modify Tools (kills monitoring tools, AMSI bypass)
- **T1055**: Process Injection (AsyncRAT into MSBuild.exe)
- **T1497**: Virtualization/Sandbox Evasion (VM/sandbox detection)
- **T1112**: Modify Registry (persistence, configuration)
- **T1070**: Indicator Removal (registry key deletion)

### Discovery
- **T1057**: Process Discovery (enumerates running processes)
- **T1082**: System Information Discovery (OS, HWID, privileges)
- **T1012**: Query Registry (system configuration)

### Collection
- **T1125**: Video Capture (checks webcam presence)
- **T1056.001**: Input Capture: Keylogging
- **T1113**: Screen Capture

### Command and Control
- **T1071.001**: Application Layer Protocol: Web Protocols (HTTP/HTTPS)
- **T1573**: Encrypted Channel (TLS-wrapped TCP)
- **T1105**: Ingress Tool Transfer (downloads injector and payload modules)
- **T1543**: Create or Modify System Process
- **T1609**: Container Administration Command (loads plugins)

### Exfiltration
- **T1041**: Exfiltration Over C2 Channel (encrypted, chunked transmission)

## Indicators of Compromise

### File Hashes

#### SVG Dropper
- **MD5**: b1ed63ee45ec48b324bf126446fdc888
- **SHA-1**: 30780d6c0c092f31635fafafabc7fd51201cbe32
- **SHA-256**: 05d0e4b3be0f2e98fdb18d80d90036109797ae68ed8459d4fd2930dca1c74a10

#### HTA File
- **MD5**: 817081c745aa14fcb15d76f029e80e15
- **SHA-256**: a30e619c87f3f47265cf43ae3e868392a2e3bfdf1ce09a6b0d4e315080d889db

#### VBS Dropper
- **MD5**: 6da792b17c4bba72ca995061e040f984
- **SHA-256**: 6f8cce7829a7033b15f28b551fc0528247c996f69734649f78d318a575f7ae83

#### ClassLibrary3.dll
- **MD5**: f3b56b3cfe462e4f8a32c989cd0c5a7c
- **SHA-256**: f6f1d85437d887e5872f2395670307182626453de15416e08c81a7108759a555

#### MoNtReaL.dll (Injector)
- **MD5**: 5fad0c5b6e5a758059c5a4e633424555
- **SHA-256**: d3c19be06cf4d3c02cede7b7d4bcc2926c0449739e570f95643e7fe94a4751fc

#### AsyncRAT Payload
- **MD5**: fe0fc2949addeefa6506b50215329ed9
- **SHA-256**: 96ae863780107947c8e262f187e96b85f8cd96d66fe2d7e39dc8cef2ae669445

### Filenames
- Fiscalia General De La Nacion Juzgado Civil 17.svg
- DOCUMENTO_OFICIAL_JUZGADO.hta
- actualiza.vbs
- veooZ.ps1
- Ysemg.txt
- ClassLibrary3.dll
- MoNtReaL.dll
- Client.exe

### Registry Keys
```
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\[Malware Name]
```

### Mutex
```
DcRatMutex_qwqdanchun
```

### Network Indicators
- dpaste.com domain usage for payload hosting

## Detection Strategies

### Email Security

1. **SVG File Scanning**: Implement deep inspection of SVG attachments
2. **Keyword Detection**: Monitor for Spanish judicial terms:
   - "Demanda judicial"
   - "Juzgado"
   - "Fiscalía General"
   - "Notificaciones Judiciales"
3. **Attachment Size**: Flag unusually large SVG files (>1MB)
4. **Sender Verification**: Validate judicial institution emails

### Network Detection

1. **Dpaste Monitoring**: Flag downloads from text hosting services
2. **Base64 Traffic**: Detect large Base64-encoded transfers
3. **PowerShell Network**: Monitor PowerShell web requests
4. **TLS Inspection**: Analyze encrypted C2 traffic patterns

### Endpoint Detection

1. **File Creation Monitoring**:
   - .HTA files from browser downloads
   - .VBS files in user directories
   - .ps1 files created by VBS scripts
   - .DLL files in temp/appdata directories

2. **Process Behavior**:
   - Browser spawning HTA execution (mshta.exe)
   - HTA spawning VBScript (wscript.exe/cscript.exe)
   - VBScript spawning PowerShell
   - PowerShell downloading files
   - MSBuild.exe with suspicious network activity

3. **Registry Monitoring**:
   - Run key modifications
   - Scheduled task creation with "onlogon" trigger

4. **Process Injection**:
   - Code injection into MSBuild.exe
   - VirtualAllocEx/WriteProcessMemory/CreateRemoteThread API calls

### Behavioral Detection

1. **Anti-VM Queries**: WMI queries for virtualization
2. **Process Termination**: Killing of monitoring tools
3. **Webcam Enumeration**: Unusual camera device checks
4. **Mutex Creation**: "DcRatMutex_qwqdanchun"
5. **AMSI Bypass Attempts**

## Quick Heal / Seqrite Detections

- **Trojan.InjectorCiR** - Injector module (MoNtReaL.dll)
- **Html.Asyncrat.49974.GC** - SVG/HTML dropper
- **Script.Trojan.49969.GC** - HTA/VBS scripts
- **Backdoor.MsilFC.S13564499** - AsyncRAT payload
- **Trojandownloader.AgentCiR** - Downloader modules

## Mitigation Recommendations

### Immediate Actions

1. **Block IOCs**: Implement all file hashes and network indicators
2. **Email Filtering**: Block .SVG attachments or subject to strict scanning
3. **User Awareness**: Educate Colombian users about judicial impersonation scams
4. **Process Monitoring**: Alert on MSBuild.exe network connections

### Short-Term Measures

1. **Application Whitelisting**: Prevent unauthorized script execution
2. **PowerShell Logging**: Enable enhanced PowerShell logging
3. **Registry Auditing**: Monitor Run key and scheduled task modifications
4. **Network Segmentation**: Limit lateral movement opportunities

### Long-Term Strategy

1. **User Training**: Spanish-language phishing awareness specific to Colombian context
2. **Email Authentication**: Implement DMARC/DKIM/SPF for judicial institutions
3. **Endpoint Protection**: Deploy EDR with behavioral analysis
4. **Threat Intelligence**: Subscribe to Latin America-focused threat feeds
5. **Incident Response**: Develop playbooks for multi-stage malware incidents

## Threat Intelligence Insights

### Campaign Sophistication

**High-Level Indicators**:
1. **Geotargeting**: Specific to Colombian users and institutions
2. **Language Localization**: Proper Spanish with legal terminology
3. **Cultural Context**: Understanding of Colombian judicial system
4. **Technical Complexity**: 7-stage infection chain with multiple evasion techniques

### Threat Actor Profile

**Likely Characteristics**:
- Spanish language proficiency
- Knowledge of Colombian legal system
- Access to AsyncRAT source code and customization
- Experience with multi-stage malware development
- Understanding of evasion techniques

### Attribution

- **Malware Family**: AsyncRAT (open-source, widely used)
- **Actor Type**: Likely cybercriminal (RAT deployment suggests financial motivation)
- **Geographic Focus**: Colombia-specific (unusual for most AsyncRAT campaigns)
- **Skill Level**: Intermediate to Advanced

### Future Predictions

1. **Geographic Expansion**: May target other Latin American countries
2. **Institution Variation**: Could impersonate other government agencies
3. **File Format Evolution**: May experiment with other formats beyond SVG
4. **Payload Diversification**: Could deploy ransomware, banking trojans, or other malware

## Conclusion

The Colombian Judicial Notification SVG AsyncRAT Campaign represents a sophisticated, geo-targeted phishing operation that combines social engineering, technical complexity, and advanced evasion techniques. The use of SVG files as an initial vector is particularly noteworthy, as this file format is not commonly exploited and often bypasses traditional security controls.

The campaign's success relies on:
1. **Credible Impersonation**: Authentic-looking judicial notifications
2. **Low Detection**: SVG files evade many security solutions
3. **Multi-Stage Architecture**: Complicates analysis and detection
4. **Advanced Evasion**: Anti-VM, anti-sandbox, process injection
5. **Persistent Access**: AsyncRAT provides full remote control

**Priority Actions**:
1. Implement all provided IOCs in security infrastructure
2. Enhance email security for SVG file attachments
3. Deploy behavioral detection for multi-stage script execution
4. Train users on Colombian judicial institution impersonation tactics
5. Monitor MSBuild.exe for suspicious network activity

Organizations in Colombia and throughout Latin America should prioritize defenses against this threat, as the campaign demonstrates the increasing sophistication of regionally-targeted cybercrime operations.

## References

- Seqrite Security Research: "Judicial Notification Phish Targets Colombian Users – .SVG Attachment Deploys Info-stealer Malware" (October 13, 2025)
  https://www.seqrite.com/blog/judicial-notification-phish-colombia-svg-asyncrat/
- AsyncRAT GitHub Repository (Open Source RAT)
- MITRE ATT&CK Framework v17

---

**Document Classification**: TLP:WHITE  
**Analysis Date**: October 19, 2025  
**Analyst**: ThreatOps-for-MISP  
**Version**: 1.0


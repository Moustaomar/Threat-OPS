# HoldingHands Asia Expansion Campaign - MITRE ATT&CK Mapping

## Campaign Overview
**Campaign Name**: HoldingHands Asia Expansion Campaign  
**Malware Families**: HoldingHands, Winos 4.0  
**Threat Actor**: Unidentified APT Group  
**Target Regions**: China, Taiwan, Japan, Malaysia  
**Reference**: https://www.fortinet.com/blog/threat-research/tracking-malware-and-attack-expansion-a-hacker-groups-journey-across-asia

---

## MITRE ATT&CK Framework Mapping

### Reconnaissance

#### T1589.002 - Gather Victim Identity Information: Email Addresses
**Tactic**: Reconnaissance  
**Description**: Threat actor gathers email addresses for targeted phishing campaigns across Asia.  
**Evidence**: Coordinated phishing campaigns targeting specific regions (China, Taiwan, Japan, Malaysia)

---

### Initial Access

#### T1566.001 - Phishing: Spearphishing Attachment
**Tactic**: Initial Access  
**Description**: Threat actor sends phishing emails with malicious PDF, Excel, and Word document attachments containing embedded malicious links.  
**Evidence**: 
- PDF attachments mimicking Ministry of Finance documents
- Excel documents used in China-focused attacks (March 2024)
- Word documents in Japan-focused attacks
- HTML attachments redirecting to download pages

#### T1566.002 - Phishing: Spearphishing Link
**Tactic**: Initial Access  
**Description**: Documents contain embedded links to malware download pages hosted on Tencent Cloud and custom domains.  
**Evidence**: 
- Tencent Cloud storage links with Account IDs 1321729461, 1329400280
- Custom domains with "tw" pattern (twsww[.]xin, twswzz[.]xin, twczb[.]com)

---

### Execution

#### T1204.002 - User Execution: Malicious File
**Tactic**: Execution  
**Description**: User executes downloaded malicious files disguised as legitimate documents.  
**Evidence**: 
- "Dokumen audit cukai dan sampel bahan.exe" (tax audit document lure)
- ZIP archives containing malicious executables

#### T1059.003 - Command and Scripting Interpreter: Windows Command Shell
**Tactic**: Execution  
**Description**: Execution of shellcode and malicious commands through Windows processes.  
**Evidence**: Multi-stage shellcode execution through dokan2.dll, sw.dat, and msvchost.dat

#### T1053.005 - Scheduled Task/Job: Scheduled Task
**Tactic**: Execution, Persistence, Privilege Escalation  
**Description**: Abuse of Windows Task Scheduler service to trigger malicious DLL loading.  
**Evidence**: 
- Task Scheduler service restart triggers TimeBrokerClient.dll loading
- Execution command line: `C:\windows\system32\svchost.exe -k netsvcs -p -s Schedule`
- Recovery setting configured to restart service after failure

---

### Persistence

#### T1574.002 - Hijack Execution Flow: DLL Side-Loading
**Tactic**: Persistence, Privilege Escalation, Defense Evasion  
**Description**: Malicious DLL (dokan2.dll) loaded via legitimate Dokany control program; TimeBrokerClient.dll loaded by svchost.exe.  
**Evidence**: 
- dokan2.dll masquerading as legitimate Dokany library
- TimeBrokerClient.dll loaded during Task Scheduler service execution

#### T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
**Tactic**: Persistence, Privilege Escalation  
**Description**: Registry keys used for persistence and configuration storage.  
**Evidence**: 
- HKEY_CURRENT_USER\SOFTWARE\HHClient (configuration)
- HKEY_CURRENT_USER\SOFTWARE\HHClient\AdrrStrChar (C2 IP address)

#### T1053.005 - Scheduled Task/Job: Scheduled Task
**Tactic**: Execution, Persistence, Privilege Escalation  
**Description**: Task Scheduler service abuse provides persistent execution mechanism.  
**Evidence**: Automatic restart of Task Scheduler triggers malware execution without direct process launch

---

### Privilege Escalation

#### T1134.001 - Access Token Manipulation: Token Impersonation/Theft
**Tactic**: Privilege Escalation, Defense Evasion  
**Description**: Impersonation of TrustedInstaller service thread to obtain highest privilege; duplication of user access tokens.  
**Evidence**: 
- sw.dat impersonates TrustedInstaller service thread
- msvchost.dat duplicates logged-on user's access token via WTSEnumerateSessions

#### T1055.001 - Process Injection: Dynamic-link Library Injection
**Tactic**: Privilege Escalation, Defense Evasion  
**Description**: HoldingHands payload injected into taskhostw.exe process.  
**Evidence**: Payload injection into taskhostw.exe with user security context

---

### Defense Evasion

#### T1140 - Deobfuscate/Decode Files or Information
**Tactic**: Defense Evasion  
**Description**: Multi-stage decryption of shellcode and payloads using process names as decryption keys.  
**Evidence**: 
- Process name (svchost.exe) used as decryption key for msvchost.dat
- Encrypted data in sw.dat, msvchost.dat, system.dat

#### T1027 - Obfuscated Files or Information
**Tactic**: Defense Evasion  
**Description**: Use of .dat files to hide malicious code; dynamic filename generation; encrypted shellcode.  
**Evidence**: 
- sw.dat, msvchost.dat, system.dat contain obfuscated shellcode
- Filenames generated dynamically from loading process name
- JSON-based dynamic link fetching prevents direct webpage-to-download association

#### T1562.001 - Impair Defenses: Disable or Modify Tools
**Tactic**: Defense Evasion  
**Description**: Anti-AV checks to detect and potentially evade security products.  
**Evidence**: Multiple anti-virus process detection checks performed by sw.dat and msvchost.dat

#### T1497.001 - Virtualization/Sandbox Evasion: System Checks
**Tactic**: Defense Evasion, Discovery  
**Description**: Anti-VM detection through physical RAM checks.  
**Evidence**: sw.dat checks physically installed RAM to detect virtual machines

#### T1036.005 - Masquerading: Match Legitimate Name or Location
**Tactic**: Defense Evasion  
**Description**: Malicious DLLs named to match legitimate system libraries.  
**Evidence**: 
- dokan2.dll masquerades as legitimate Dokany library
- TimeBrokerClient.dll mimics legitimate Windows component

#### T1553.002 - Subvert Trust Controls: Code Signing
**Tactic**: Defense Evasion  
**Description**: Malicious executables carry legitimate digital signatures to evade detection.  
**Evidence**: EXE files with legitimate digital signatures observed in Japan campaign

#### T1055.012 - Process Injection: Process Hollowing
**Tactic**: Defense Evasion, Privilege Escalation  
**Description**: Injection of HoldingHands payload into taskhostw.exe for execution in user context.  
**Evidence**: CreateProcessAsUserW launches taskhostw.exe; payload injected into it

#### T1112 - Modify Registry
**Tactic**: Defense Evasion  
**Description**: Registry modifications for configuration and C2 updates.  
**Evidence**: 
- HHClient registry key for configuration
- AdrrStrChar value for dynamic C2 IP updates

---

### Discovery

#### T1082 - System Information Discovery
**Tactic**: Discovery  
**Description**: Collection of system information including RAM, process names, and command lines.  
**Evidence**: 
- Physical RAM checks for anti-VM
- Process name ASCII sum calculations (must equal 0x47A)
- Command line validation

#### T1057 - Process Discovery
**Tactic**: Discovery  
**Description**: Enumeration of running processes to detect security products and validate execution environment.  
**Evidence**: 
- Anti-AV process checks
- Process name validation
- Monitoring of taskhostw.exe execution

#### T1033 - System Owner/User Discovery
**Tactic**: Discovery  
**Description**: Enumeration of user sessions to identify active logged-on users.  
**Evidence**: WTSEnumerateSessions API call to retrieve terminal sessions

#### T1124 - System Time Discovery
**Tactic**: Discovery  
**Description**: Potential system time checks for execution timing.  
**Evidence**: Task Scheduler timing-based execution

---

### Collection

#### T1005 - Data from Local System
**Tactic**: Collection  
**Description**: HoldingHands payload collects sensitive information from compromised systems.  
**Evidence**: Information stealing capabilities of HoldingHands malware

#### T1113 - Screen Capture
**Tactic**: Collection  
**Description**: Potential screen capture capability (typical of information stealers).  
**Evidence**: Inferred from information stealing malware classification

---

### Command and Control

#### T1071.001 - Application Layer Protocol: Web Protocols
**Tactic**: Command and Control  
**Description**: C2 communication over standard web protocols.  
**Evidence**: Communication with C2 servers at identified IP addresses

#### T1573 - Encrypted Channel
**Tactic**: Command and Control  
**Description**: Encrypted communications between malware and C2 infrastructure.  
**Evidence**: Encrypted shellcode and data transfer mechanisms

#### T1008 - Fallback Channels
**Tactic**: Command and Control  
**Description**: Dynamic C2 IP address update capability provides fallback communication channels.  
**Evidence**: 
- Command 0x15 for C2 IP update via registry
- Registry key: HKEY_CURRENT_USER\SOFTWARE\HHClient\AdrrStrChar

#### T1102 - Web Service
**Tactic**: Command and Control  
**Description**: Abuse of Tencent Cloud storage for malware distribution.  
**Evidence**: Tencent Cloud Account IDs 1321729461, 1329400280 used for payload hosting

#### T1219 - Remote Access Software
**Tactic**: Command and Control  
**Description**: HoldingHands provides backdoor/remote access capabilities.  
**Evidence**: Remote access trojan functionality

---

### Exfiltration

#### T1041 - Exfiltration Over C2 Channel
**Tactic**: Exfiltration  
**Description**: Stolen information exfiltrated over established C2 channels.  
**Evidence**: Data exfiltration through HoldingHands C2 communication

---

## ATT&CK Navigator Layer

### Tactics Coverage
- **Reconnaissance**: 1 technique
- **Initial Access**: 2 techniques
- **Execution**: 3 techniques
- **Persistence**: 3 techniques
- **Privilege Escalation**: 4 techniques
- **Defense Evasion**: 9 techniques
- **Discovery**: 4 techniques
- **Collection**: 2 techniques
- **Command and Control**: 5 techniques
- **Exfiltration**: 1 technique

**Total Techniques**: 34 unique MITRE ATT&CK techniques

---

## Key Technique Clusters

### Multi-Stage Execution Chain
1. **T1566.001** - Spearphishing Attachment (Initial Access)
2. **T1204.002** - User Execution (Execution)
3. **T1574.002** - DLL Side-Loading (Persistence/Evasion)
4. **T1053.005** - Scheduled Task (Persistence/Execution)
5. **T1055.001** - Process Injection (Privilege Escalation)

### Advanced Evasion Cluster
1. **T1140** - Deobfuscate/Decode Files
2. **T1027** - Obfuscated Files
3. **T1497.001** - Virtualization/Sandbox Evasion
4. **T1553.002** - Code Signing
5. **T1562.001** - Impair Defenses
6. **T1036.005** - Masquerading

### Privilege and Access Cluster
1. **T1134.001** - Token Impersonation (TrustedInstaller)
2. **T1055.012** - Process Hollowing
3. **T1053.005** - Scheduled Task Abuse

---

## Detection Opportunities by MITRE Technique

### High-Fidelity Detection Opportunities

#### T1574.002 - DLL Side-Loading
**Detection**: Monitor for unusual DLL loads by legitimate executables
- Alert on dokan2.dll loaded by non-Dokany processes
- Monitor TimeBrokerClient.dll loads outside standard system paths

#### T1053.005 - Scheduled Task Abuse
**Detection**: Monitor Task Scheduler service behavior
- Alert on unusual Task Scheduler restarts
- Monitor svchost.exe spawning taskhostw.exe
- Track Task Scheduler service recovery actions

#### T1134.001 - Token Impersonation
**Detection**: Monitor for token manipulation
- Alert on TrustedInstaller token duplication
- Monitor WTSEnumerateSessions API calls from unusual processes
- Track CreateProcessAsUserW calls

#### T1112 - Modify Registry
**Detection**: Monitor registry modifications
- Alert on HHClient registry key creation/modification
- Monitor HKEY_CURRENT_USER\SOFTWARE\HHClient\AdrrStrChar changes

### Network-Based Detection

#### T1071.001 - Web Protocols
**Detection**: Network traffic analysis
- Monitor connections to identified malicious IPs
- Detect communication patterns with C2 servers
- Alert on connections to domains with "tw" pattern

#### T1102 - Web Service
**Detection**: Cloud service abuse
- Monitor Tencent Cloud downloads from suspicious account IDs
- Alert on unusual cloud storage access patterns

---

## ATT&CK Heatmap Priority

### Critical Priority (Red)
- T1566.001 - Spearphishing Attachment
- T1574.002 - DLL Side-Loading
- T1053.005 - Scheduled Task
- T1134.001 - Token Impersonation
- T1008 - Fallback Channels (C2 IP update)

### High Priority (Orange)
- T1140 - Deobfuscate/Decode
- T1027 - Obfuscated Files
- T1497.001 - Sandbox Evasion
- T1055.001 - Process Injection
- T1112 - Modify Registry

### Medium Priority (Yellow)
- T1553.002 - Code Signing
- T1562.001 - Impair Defenses
- T1036.005 - Masquerading
- T1071.001 - Web Protocols
- T1102 - Web Service

---

## Recommendations by ATT&CK Tactic

### Initial Access
- Implement advanced email filtering for phishing detection
- Train users on government document impersonation tactics
- Scan all document attachments for embedded links

### Execution
- Application whitelisting to prevent unauthorized executable execution
- Monitor and restrict Task Scheduler modifications
- Implement EDR for shellcode detection

### Persistence
- Registry monitoring for HHClient key creation
- DLL load monitoring and verification
- Scheduled task auditing and baseline establishment

### Privilege Escalation
- Restrict token impersonation capabilities
- Monitor TrustedInstaller access
- Implement least privilege principles

### Defense Evasion
- Deploy multi-layered security controls
- Implement behavioral analysis for obfuscated code
- Monitor for anti-VM and anti-AV checks
- Certificate pinning and signature validation

### Command and Control
- Network segmentation and egress filtering
- Monitor for dynamic C2 patterns
- Block identified malicious domains and IPs
- Cloud service access controls

---

## MITRE ATT&CK Navigator JSON

```json
{
  "name": "HoldingHands Asia Expansion Campaign",
  "versions": {
    "attack": "14",
    "navigator": "4.9.1",
    "layer": "4.5"
  },
  "domain": "enterprise-attack",
  "description": "MITRE ATT&CK techniques used by HoldingHands Asia Expansion Campaign targeting China, Taiwan, Japan, and Malaysia (2024-2025)",
  "filters": {
    "platforms": ["windows"]
  },
  "sorting": 0,
  "layout": {
    "layout": "side",
    "aggregateFunction": "average",
    "showID": false,
    "showName": true,
    "showAggregateScores": false,
    "countUnscored": false
  },
  "hideDisabled": false,
  "techniques": [
    {
      "techniqueID": "T1589.002",
      "tactic": "reconnaissance",
      "color": "#ff6666",
      "comment": "Email address gathering for phishing campaigns",
      "enabled": true,
      "metadata": [],
      "links": [],
      "showSubtechniques": false
    },
    {
      "techniqueID": "T1566.001",
      "tactic": "initial-access",
      "color": "#ff0000",
      "comment": "PDF/Excel/Word phishing attachments",
      "enabled": true,
      "metadata": [],
      "links": [],
      "showSubtechniques": false
    },
    {
      "techniqueID": "T1566.002",
      "tactic": "initial-access",
      "color": "#ff0000",
      "comment": "Embedded malicious links in documents",
      "enabled": true,
      "metadata": [],
      "links": [],
      "showSubtechniques": false
    },
    {
      "techniqueID": "T1204.002",
      "tactic": "execution",
      "color": "#ff6666",
      "comment": "User executes malicious files",
      "enabled": true,
      "metadata": [],
      "links": [],
      "showSubtechniques": false
    },
    {
      "techniqueID": "T1059.003",
      "tactic": "execution",
      "color": "#ff9900",
      "comment": "Windows Command Shell execution",
      "enabled": true,
      "metadata": [],
      "links": [],
      "showSubtechniques": false
    },
    {
      "techniqueID": "T1053.005",
      "tactic": "execution",
      "color": "#ff0000",
      "comment": "Task Scheduler abuse for execution",
      "enabled": true,
      "metadata": [],
      "links": [],
      "showSubtechniques": false
    },
    {
      "techniqueID": "T1574.002",
      "tactic": "persistence",
      "color": "#ff0000",
      "comment": "DLL side-loading (dokan2.dll, TimeBrokerClient.dll)",
      "enabled": true,
      "metadata": [],
      "links": [],
      "showSubtechniques": false
    },
    {
      "techniqueID": "T1547.001",
      "tactic": "persistence",
      "color": "#ff9900",
      "comment": "Registry Run Keys (HHClient)",
      "enabled": true,
      "metadata": [],
      "links": [],
      "showSubtechniques": false
    },
    {
      "techniqueID": "T1053.005",
      "tactic": "persistence",
      "color": "#ff0000",
      "comment": "Task Scheduler for persistence",
      "enabled": true,
      "metadata": [],
      "links": [],
      "showSubtechniques": false
    },
    {
      "techniqueID": "T1134.001",
      "tactic": "privilege-escalation",
      "color": "#ff0000",
      "comment": "TrustedInstaller impersonation, token duplication",
      "enabled": true,
      "metadata": [],
      "links": [],
      "showSubtechniques": false
    },
    {
      "techniqueID": "T1055.001",
      "tactic": "privilege-escalation",
      "color": "#ff9900",
      "comment": "DLL injection into taskhostw.exe",
      "enabled": true,
      "metadata": [],
      "links": [],
      "showSubtechniques": false
    },
    {
      "techniqueID": "T1140",
      "tactic": "defense-evasion",
      "color": "#ff0000",
      "comment": "Multi-stage decryption using process names",
      "enabled": true,
      "metadata": [],
      "links": [],
      "showSubtechniques": false
    },
    {
      "techniqueID": "T1027",
      "tactic": "defense-evasion",
      "color": "#ff0000",
      "comment": "Obfuscated .dat files, encrypted shellcode",
      "enabled": true,
      "metadata": [],
      "links": [],
      "showSubtechniques": false
    },
    {
      "techniqueID": "T1562.001",
      "tactic": "defense-evasion",
      "color": "#ff9900",
      "comment": "Anti-AV process checks",
      "enabled": true,
      "metadata": [],
      "links": [],
      "showSubtechniques": false
    },
    {
      "techniqueID": "T1497.001",
      "tactic": "defense-evasion",
      "color": "#ff0000",
      "comment": "Anti-VM via physical RAM checks",
      "enabled": true,
      "metadata": [],
      "links": [],
      "showSubtechniques": false
    },
    {
      "techniqueID": "T1036.005",
      "tactic": "defense-evasion",
      "color": "#ffcc00",
      "comment": "DLL masquerading",
      "enabled": true,
      "metadata": [],
      "links": [],
      "showSubtechniques": false
    },
    {
      "techniqueID": "T1553.002",
      "tactic": "defense-evasion",
      "color": "#ff9900",
      "comment": "Legitimate digital signatures",
      "enabled": true,
      "metadata": [],
      "links": [],
      "showSubtechniques": false
    },
    {
      "techniqueID": "T1055.012",
      "tactic": "defense-evasion",
      "color": "#ff9900",
      "comment": "Process hollowing into taskhostw.exe",
      "enabled": true,
      "metadata": [],
      "links": [],
      "showSubtechniques": false
    },
    {
      "techniqueID": "T1112",
      "tactic": "defense-evasion",
      "color": "#ff9900",
      "comment": "Registry modifications (HHClient, AdrrStrChar)",
      "enabled": true,
      "metadata": [],
      "links": [],
      "showSubtechniques": false
    },
    {
      "techniqueID": "T1082",
      "tactic": "discovery",
      "color": "#ff9900",
      "comment": "System information discovery (RAM, process names)",
      "enabled": true,
      "metadata": [],
      "links": [],
      "showSubtechniques": false
    },
    {
      "techniqueID": "T1057",
      "tactic": "discovery",
      "color": "#ff9900",
      "comment": "Process discovery for security products",
      "enabled": true,
      "metadata": [],
      "links": [],
      "showSubtechniques": false
    },
    {
      "techniqueID": "T1033",
      "tactic": "discovery",
      "color": "#ff9900",
      "comment": "User discovery via WTSEnumerateSessions",
      "enabled": true,
      "metadata": [],
      "links": [],
      "showSubtechniques": false
    },
    {
      "techniqueID": "T1124",
      "tactic": "discovery",
      "color": "#ffcc00",
      "comment": "System time discovery",
      "enabled": true,
      "metadata": [],
      "links": [],
      "showSubtechniques": false
    },
    {
      "techniqueID": "T1005",
      "tactic": "collection",
      "color": "#ff9900",
      "comment": "Data collection from local system",
      "enabled": true,
      "metadata": [],
      "links": [],
      "showSubtechniques": false
    },
    {
      "techniqueID": "T1113",
      "tactic": "collection",
      "color": "#ffcc00",
      "comment": "Screen capture capability",
      "enabled": true,
      "metadata": [],
      "links": [],
      "showSubtechniques": false
    },
    {
      "techniqueID": "T1071.001",
      "tactic": "command-and-control",
      "color": "#ffcc00",
      "comment": "Web protocols for C2",
      "enabled": true,
      "metadata": [],
      "links": [],
      "showSubtechniques": false
    },
    {
      "techniqueID": "T1573",
      "tactic": "command-and-control",
      "color": "#ff9900",
      "comment": "Encrypted C2 channel",
      "enabled": true,
      "metadata": [],
      "links": [],
      "showSubtechniques": false
    },
    {
      "techniqueID": "T1008",
      "tactic": "command-and-control",
      "color": "#ff0000",
      "comment": "Dynamic C2 IP update via registry",
      "enabled": true,
      "metadata": [],
      "links": [],
      "showSubtechniques": false
    },
    {
      "techniqueID": "T1102",
      "tactic": "command-and-control",
      "color": "#ffcc00",
      "comment": "Tencent Cloud abuse",
      "enabled": true,
      "metadata": [],
      "links": [],
      "showSubtechniques": false
    },
    {
      "techniqueID": "T1219",
      "tactic": "command-and-control",
      "color": "#ff9900",
      "comment": "Remote access capabilities",
      "enabled": true,
      "metadata": [],
      "links": [],
      "showSubtechniques": false
    },
    {
      "techniqueID": "T1041",
      "tactic": "exfiltration",
      "color": "#ff9900",
      "comment": "Exfiltration over C2 channel",
      "enabled": true,
      "metadata": [],
      "links": [],
      "showSubtechniques": false
    }
  ],
  "gradient": {
    "colors": [
      "#ff0000",
      "#ffcc00",
      "#ffffff"
    ],
    "minValue": 0,
    "maxValue": 100
  },
  "legendItems": [
    {
      "label": "Critical Priority",
      "color": "#ff0000"
    },
    {
      "label": "High Priority",
      "color": "#ff9900"
    },
    {
      "label": "Medium Priority",
      "color": "#ffcc00"
    }
  ],
  "metadata": [],
  "links": [],
  "showTacticRowBackground": false,
  "tacticRowBackground": "#dddddd"
}
```

---

**Document Classification**: TLP:WHITE  
**Analysis Date**: October 18, 2025  
**Framework Version**: MITRE ATT&CK v14  
**Analyst**: ThreatOps-for-MISP  
**Version**: 1.0


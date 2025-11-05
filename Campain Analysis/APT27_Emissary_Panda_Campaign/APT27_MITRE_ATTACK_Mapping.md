# APT27 (Emissary Panda) MITRE ATT&CK Framework Mapping

## Overview
This document provides a comprehensive mapping of APT27 (Emissary Panda) activities to the MITRE ATT&CK framework, based on observed tactics, techniques, and procedures (TTPs) from threat intelligence sources.

## MITRE ATT&CK Mapping

### Initial Access
| Technique | ID | Description | APT27 Usage |
|-----------|----|-------------|-------------|
| Exploit Public-Facing Application | T1190 | Exploiting vulnerabilities in internet-facing applications | Used to target Zoho ManageEngine ADSelfService Plus (CVE-2021-40539) |
| Spearphishing Attachment | T1566.001 | Malicious email attachments in targeted campaigns | Primary initial access vector using malicious documents |
| Drive-by Compromise | T1189 | Compromising websites frequented by targets | Watering-hole attacks against target organizations |
| External Remote Services | T1133 | Exploiting VPN and remote access solutions | Targeting external remote access infrastructure |

### Execution
| Technique | ID | Description | APT27 Usage |
|-----------|----|-------------|-------------|
| Command & Scripting Interpreter: PowerShell | T1059.001 | Using PowerShell for command execution | Post-exploitation command execution |
| Command & Scripting Interpreter: Windows Cmd | T1059.003 | Using Windows Command Shell | System command execution |
| Process Injection: Process Hollowing | T1055.012 | Injecting malicious code into legitimate processes | HyperBro and SysUpdate malware capabilities |
| Windows Management Instrumentation | T1047 | Using WMI for system management | Remote system management and execution |
| Exploitation for Client Execution | T1203 | Exploiting client-side vulnerabilities | Browser and application exploitation |

### Persistence
| Technique | ID | Description | APT27 Usage |
|-----------|----|-------------|-------------|
| Server Software Component: Web Shell | T1505.003 | Installing web shells on servers | Multiple ASPX web shells (stylecs.aspx, test.aspx, etc.) |
| Create/Modify System Process: Windows Service | T1543.003 | Creating or modifying Windows services | SysUpdate service installation |
| Registry Run Keys/Startup Folder | T1547.001 | Modifying registry for persistence | Registry-based persistence mechanisms |
| Scheduled Task/Job | T1053 | Creating scheduled tasks for persistence | Automated task execution |
| Modify Registry | T1112 | Modifying Windows registry | Registry modifications for persistence |

### Privilege Escalation
| Technique | ID | Description | APT27 Usage |
|-----------|----|-------------|-------------|
| Exploitation for Privilege Escalation | T1068 | Exploiting vulnerabilities for privilege escalation | Local privilege escalation |
| Bypass User Account Control | T1548.002 | Bypassing UAC mechanisms | UAC bypass techniques |

### Credential Access
| Technique | ID | Description | APT27 Usage |
|-----------|----|-------------|-------------|
| OS Credential Dumping | T1003 | Extracting credentials from operating system | Using Mimikatz and WCE |
| Credentials from Password Stores | T1555 | Extracting credentials from password stores | Browser and application credential theft |
| Input Capture: Keylogging | T1056.001 | Capturing keystrokes | Keylogging capabilities in malware |

### Collection
| Technique | ID | Description | APT27 Usage |
|-----------|----|-------------|-------------|
| Screen Capture | T1113 | Capturing screenshots | SysUpdate screenshot capabilities |

### Discovery
| Technique | ID | Description | APT27 Usage |
|-----------|----|-------------|-------------|
| Network Service Scanning | T1046 | Scanning for network services | Network reconnaissance |
| Remote System Discovery | T1018 | Discovering remote systems | Network mapping |
| Account Discovery: Local Account | T1087 | Discovering local accounts | User enumeration |
| System Network Configuration Discovery | T1016 | Discovering network configuration | Network topology mapping |
| System Network Connections Discovery | T1049 | Discovering network connections | Connection enumeration |
| Data from Local System | T1005 | Collecting data from local system | Data collection from compromised systems |

### Lateral Movement
| Technique | ID | Description | APT27 Usage |
|-----------|----|-------------|-------------|
| Exploitation of Remote Services | T1210 | Exploiting remote services for lateral movement | Network lateral movement |
| Lateral Tool Transfer | T1570 | Transferring tools across network | Tool distribution within network |

### Resource Development
| Technique | ID | Description | APT27 Usage |
|-----------|----|-------------|-------------|
| Obtain Capabilities: Code Signing Certificates | T1588.003 | Obtaining code signing certificates | Certificate acquisition |
| Obtain Capabilities: Tool | T1588.002 | Obtaining tools and capabilities | Tool acquisition |
| Stage Capabilities: Upload Malware | T1608.001 | Uploading malware to infrastructure | Malware staging |
| Stage Capabilities: Upload Tool | T1608.002 | Uploading tools to infrastructure | Tool staging |
| Stage Capabilities: Drive-by Target | T1608.004 | Setting up drive-by compromise sites | Watering-hole preparation |

### Command and Control
| Technique | ID | Description | APT27 Usage |
|-----------|----|-------------|-------------|
| Application Layer Protocol: Web Protocols | T1071.001 | Using web protocols for C2 | HTTP/HTTPS C2 communication |

### Exfiltration
| Technique | ID | Description | APT27 Usage |
|-----------|----|-------------|-------------|
| Data Staged: Local | T1074.001 | Staging data locally before exfiltration | Local data staging |
| Data Staged: Remote | T1074.002 | Staging data on remote systems | Remote data staging |
| Archive Collected Data | T1560.001 | Archiving collected data | Data compression and archiving |
| Exfiltration Over Web Service: To Cloud Storage (Dropbox) | T1567.002 | Exfiltrating data to cloud storage | Dropbox exfiltration |
| Exfiltration Over C2 Channel | T1041 | Exfiltrating data over C2 channels | C2-based data exfiltration |

### Defense Evasion
| Technique | ID | Description | APT27 Usage |
|-----------|----|-------------|-------------|
| DLL Side-Loading | T1574.001 | Loading malicious DLLs through legitimate processes | DLL hijacking techniques |
| Obfuscated/Compressed Files & Info | T1027 | Obfuscating or compressing files | File obfuscation |
| Indicator Removal | T1070 | Removing forensic artifacts | Log clearing and artifact removal |
| Impair Defenses: Disable Windows Event Logging | T1562.002 | Disabling Windows event logging | Logging disablement |
| Deobfuscate/Decode Files or Information | T1140 | Deobfuscating files or information | File deobfuscation |

## Malware-Specific Mappings

### HyperBro
- **Primary Use**: In-memory backdoor/RAT
- **ATT&CK Techniques**: T1055.012 (Process Injection), T1113 (Screen Capture), T1041 (Exfiltration Over C2 Channel)
- **C2 Infrastructure**: 185.12.45.134:443/ajax

### SysUpdate
- **Primary Use**: Modular backdoor for Windows and Linux
- **ATT&CK Techniques**: T1543.003 (Windows Service), T1113 (Screen Capture), T1041 (Exfiltration Over C2 Channel)
- **Cross-Platform**: Windows and Linux support

### PlugX (Korplug)
- **Primary Use**: Modular RAT
- **ATT&CK Techniques**: T1055.012 (Process Injection), T1003 (OS Credential Dumping), T1113 (Screen Capture)
- **Capabilities**: Command execution, screen capture, keylogging, file operations

### Web Shells
- **Primary Use**: Server-side persistence
- **ATT&CK Techniques**: T1505.003 (Web Shell), T1059.001 (PowerShell), T1112 (Modify Registry)
- **Files**: stylecs.aspx, stylecss.aspx, test.aspx, error2.aspx

## Campaign-Specific TTPs

### Healthcare Sector Targeting (2021)
- **Initial Access**: T1190 (Exploit Public-Facing Application) - Zoho ManageEngine vulnerability
- **Targets**: German pharmaceutical companies, U.S. healthcare organizations
- **Objectives**: Trade secrets and intellectual property theft

### Government and Defense Targeting
- **Initial Access**: T1566.001 (Spearphishing Attachment)
- **Persistence**: T1505.003 (Web Shell), T1543.003 (Windows Service)
- **Collection**: T1113 (Screen Capture), T1005 (Data from Local System)

## Detection Recommendations

### Network-Based Detection
- Monitor for connections to known C2 infrastructure (185.12.45.134)
- Detect unusual outbound traffic patterns
- Monitor for data exfiltration to cloud storage services

### Endpoint-Based Detection
- Monitor for execution of known APT27 malware families
- Detect DLL side-loading activities
- Monitor for credential dumping activities
- Track scheduled task creation and modification

### Email Security
- Implement advanced phishing detection
- Monitor for spear-phishing campaigns
- Analyze email attachments for malicious content

### Web Application Security
- Monitor for web shell uploads and execution
- Implement application-layer monitoring
- Regular vulnerability assessments

## Mitigation Strategies

### Technical Controls
- Implement multi-factor authentication
- Regular patching of public-facing applications
- Network segmentation
- Endpoint detection and response (EDR)
- Email security gateways

### Administrative Controls
- Security awareness training
- Regular security assessments
- Incident response planning
- Vendor risk management

### Monitoring and Detection
- 24/7 SOC monitoring
- Threat hunting activities
- Regular IOC updates
- Behavioral analytics

## References
- [MITRE ATT&CK APT27](https://attack.mitre.org/groups/G0027/)
- [DeXpose APT27 Profile](https://www.dexpose.io/threat-actor-profile-apt27/)
- [FBI IC3 PSA on APT27](https://www.ic3.gov/PSA/2025/PSA250305)
- [HHS Sector Alert on APT27](https://www.hhs.gov/sites/default/files/chinese-cyberspionage-campaign-targets-multiple-industries.pdf)

---
**Document Version**: 1.0  
**Last Updated**: January 2025  
**Threat Level**: High  
**Confidence Level**: High

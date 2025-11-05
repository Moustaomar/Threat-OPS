# AlienVault Banking Phishing Campaign - MITRE ATT&CK Mapping

## Campaign Overview
- **Campaign Name**: AlienVault Banking Phishing Campaign
- **Threat Type**: Banking Phishing Infrastructure
- **Target**: Banking customers and financial institutions
- **Date**: October 12, 2025
- **Source**: AlienVault Banking PhishTank

## MITRE ATT&CK Framework Mapping

### Initial Access
| Technique ID | Technique Name | Description | Usage in Campaign |
|--------------|----------------|-------------|-------------------|
| T1566.001 | Spearphishing Attachment | Malicious attachments in emails | Banking-themed phishing emails with malicious attachments |
| T1566.002 | Spearphishing Link | Malicious links in emails | Banking phishing emails with malicious links to fake banking sites |
| T1566.003 | Spearphishing via Service | Phishing through third-party services | Phishing through social media and messaging platforms |
| T1078.004 | Valid Accounts: Cloud Accounts | Use of compromised cloud accounts | Use of compromised cloud hosting for phishing infrastructure |

### Execution
| Technique ID | Technique Name | Description | Usage in Campaign |
|--------------|----------------|-------------|-------------------|
| T1059 | Command and Scripting Interpreter | Execution of commands and scripts | JavaScript and PowerShell execution on phishing sites |
| T1059.001 | PowerShell | PowerShell command execution | PowerShell scripts for credential harvesting |
| T1059.007 | JavaScript | JavaScript execution | Client-side JavaScript for form manipulation and data collection |
| T1204.002 | User Execution: Malicious File | User execution of malicious files | Users executing malicious banking applications |

### Persistence
| Technique ID | Technique Name | Description | Usage in Campaign |
|--------------|----------------|-------------|-------------------|
| T1078.004 | Valid Accounts: Cloud Accounts | Cloud account persistence | Maintaining access through compromised cloud accounts |
| T1505.003 | Server Software Component: Web Shell | Web shell installation | Web shells on compromised banking infrastructure |

### Privilege Escalation
| Technique ID | Technique Name | Description | Usage in Campaign |
|--------------|----------------|-------------|-------------------|
| T1078.004 | Valid Accounts: Cloud Accounts | Cloud account privilege escalation | Escalating privileges through compromised cloud accounts |

### Defense Evasion
| Technique ID | Technique Name | Description | Usage in Campaign |
|--------------|----------------|-------------|-------------------|
| T1027 | Obfuscated Files or Information | File and information obfuscation | Obfuscated JavaScript and HTML on phishing sites |
| T1140 | Deobfuscate/Decode Files or Information | File deobfuscation | Dynamic deobfuscation of phishing payloads |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Legitimate name/location masquerading | Banking domain impersonation and typosquatting |
| T1564.001 | Hidden Files and Directories | File and directory hiding | Hidden directories on phishing infrastructure |

### Credential Access
| Technique ID | Technique Name | Description | Usage in Campaign |
|--------------|----------------|-------------|-------------------|
| T1110 | Brute Force | Brute force attacks | Automated credential brute forcing |
| T1110.001 | Brute Force: Password Brute Force | Password brute forcing | Password brute forcing against banking accounts |
| T1110.002 | Brute Force: Password Spraying | Password spraying | Password spraying across multiple accounts |
| T1056 | Input Capture | Input capture techniques | Keylogging and form grabbing on phishing sites |
| T1056.001 | Input Capture: Keylogging | Keystroke logging | Keyloggers embedded in phishing sites |
| T1056.002 | Input Capture: GUI Input Capture | GUI input capture | Screen capture and form data collection |
| T1056.003 | Input Capture: Web Portal Capture | Web portal capture | Banking portal credential capture |
| T1555 | Credentials from Password Stores | Password store access | Accessing browser password stores |
| T1555.001 | Credentials from Password Stores: Keychain | Keychain access | macOS keychain credential extraction |
| T1555.002 | Credentials from Password Stores: Credentials from Web Browsers | Browser credential access | Browser-stored credential extraction |
| T1555.003 | Credentials from Password Stores: Credentials from Windows Credential Manager | Windows credential access | Windows Credential Manager access |

### Discovery
| Technique ID | Technique Name | Description | Usage in Campaign |
|--------------|----------------|-------------|-------------------|
| T1083 | File and Directory Discovery | System file enumeration | Discovering user files and banking documents |
| T1082 | System Information Discovery | System information gathering | Collecting system information from victims |
| T1016 | System Network Configuration Discovery | Network configuration discovery | Network topology discovery |
| T1046 | Network Service Scanning | Network service scanning | Scanning for banking services and infrastructure |

### Lateral Movement
| Technique ID | Technique Name | Description | Usage in Campaign |
|--------------|----------------|-------------|-------------------|
| T1021 | Remote Services | Remote service usage | Using remote services for lateral movement |
| T1021.001 | Remote Desktop Protocol | RDP usage | RDP for lateral movement in banking networks |
| T1021.002 | SMB/Windows Admin Shares | SMB share access | SMB for file sharing and lateral movement |

### Collection
| Technique ID | Technique Name | Description | Usage in Campaign |
|--------------|----------------|-------------|-------------------|
| T1005 | Data from Local System | Local data collection | Collecting banking data from compromised systems |
| T1039 | Data from Information Repositories | Repository data access | Accessing banking databases and information systems |
| T1114 | Email Collection | Email data collection | Collecting email communications |
| T1114.001 | Email Collection: Local Email Collection | Local email collection | Local email client data collection |
| T1114.002 | Email Collection: Remote Email Collection | Remote email collection | Web-based email collection |
| T1114.003 | Email Collection: Email Forwarding Rules | Email forwarding rules | Email forwarding for data exfiltration |

### Command and Control
| Technique ID | Technique Name | Description | Usage in Campaign |
|--------------|----------------|-------------|-------------------|
| T1071 | Application Layer Protocol | C2 communication protocols | HTTP/HTTPS for C2 communication |
| T1071.001 | Web Protocols | Web-based C2 | HTTP-based command and control |
| T1102 | Web Service | Web service C2 | Using web services for C2 communication |
| T1102.001 | Web Service: Dead Drop Resolver | Dead drop resolver | Dead drop domains for C2 |
| T1102.002 | Web Service: Bidirectional Communication | Bidirectional communication | Two-way communication with C2 |
| T1102.003 | Web Service: OneDrive | OneDrive C2 | OneDrive for C2 communication |
| T1104 | Multi-Stage Channels | Multi-stage C2 | Complex C2 infrastructure with multiple stages |

### Exfiltration
| Technique ID | Technique Name | Description | Usage in Campaign |
|--------------|----------------|-------------|-------------------|
| T1041 | Exfiltration Over C2 Channel | C2-based exfiltration | Data exfiltration through C2 channels |
| T1041.001 | Exfiltration Over C2 Channel: HTTP | HTTP exfiltration | HTTP-based data exfiltration |
| T1567 | Exfiltration Over Web Service | Web service exfiltration | Using web services for data exfiltration |
| T1567.001 | Exfiltration Over Web Service: Webmail | Webmail exfiltration | Email-based data exfiltration |
| T1567.002 | Exfiltration Over Web Service: Cloud Storage | Cloud storage exfiltration | Cloud storage for data exfiltration |
| T1048 | Exfiltration Over Alternative Protocol | Alternative protocol exfiltration | DNS and other protocol exfiltration |

### Impact
| Technique ID | Technique Name | Description | Usage in Campaign |
|--------------|----------------|-------------|-------------------|
| T1499 | Endpoint Denial of Service | Endpoint DoS | Banking system disruption |
| T1499.001 | Endpoint Denial of Service: OS Exhaustion Flood | OS exhaustion flood | System resource exhaustion |
| T1499.002 | Endpoint Denial of Service: Service Exhaustion Flood | Service exhaustion flood | Banking service disruption |
| T1499.003 | Endpoint Denial of Service: Application Exhaustion Flood | Application exhaustion flood | Banking application disruption |
| T1499.004 | Endpoint Denial of Service: Application or System Exploitation | Application/system exploitation | Banking system exploitation |

## Tactics Summary

### Primary Tactics
1. **Initial Access**: Spearphishing with banking themes
2. **Execution**: JavaScript and PowerShell execution
3. **Credential Access**: Multiple credential harvesting techniques
4. **Collection**: Banking data collection
5. **Exfiltration**: Data exfiltration through various channels

### Advanced Techniques
- **Domain Impersonation**: Sophisticated banking domain impersonation
- **Credential Harvesting**: Multiple credential collection methods
- **Data Exfiltration**: Various exfiltration techniques
- **Infrastructure**: Complex phishing infrastructure

## Detection Recommendations

### Network-Based Detection
- Monitor for connections to identified phishing domains
- Detect HTTP/HTTPS traffic to suspicious banking domains
- Monitor for unusual network communication patterns
- Track data exfiltration activities

### Endpoint Detection
- Monitor for credential harvesting activities
- Detect phishing site interactions
- Track data collection and exfiltration
- Monitor for banking application abuse

### Behavioral Detection
- Detect phishing behavioral patterns
- Monitor for credential dumping activities
- Track data collection and exfiltration
- Detect banking system abuse

## Mitigation Strategies

### Technical Controls
- **Email Security**: Advanced email filtering for phishing
- **Web Security**: Web filtering and sandboxing
- **Endpoint Protection**: EDR solutions with behavioral analysis
- **Network Monitoring**: Phishing traffic detection and blocking

### Administrative Controls
- **User Training**: Security awareness for phishing attacks
- **Access Controls**: Principle of least privilege
- **Network Segmentation**: Isolate banking systems
- **Incident Response**: Rapid response procedures

### Monitoring and Detection
- **SIEM Integration**: Centralized logging and monitoring
- **Threat Hunting**: Proactive threat hunting activities
- **IOC Monitoring**: Track known threat indicators
- **Behavioral Analytics**: Advanced behavioral analysis

## References
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [AlienVault Banking PhishTank](https://raw.githubusercontent.com/romainmarcoux/malicious-domains/refs/heads/main/sources/alienvault-banking-phishtank)
- [Phishing Attack Techniques](https://attack.mitre.org/techniques/T1566/)
- [Credential Access Techniques](https://attack.mitre.org/tactics/TA0006/)

---
**Report Date**: October 12, 2025  
**Threat Level**: Medium  
**Confidence Level**: High  
**Source**: AlienVault Banking PhishTank

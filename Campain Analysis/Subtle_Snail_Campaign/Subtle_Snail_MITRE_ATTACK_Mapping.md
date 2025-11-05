# Subtle Snail Campaign - MITRE ATT&CK Mapping

## Overview

This document provides a comprehensive mapping of the Subtle Snail threat actor to the MITRE ATT&CK framework. The analysis covers various attack techniques used by this advanced persistent threat (APT) actor, including initial access, persistence, defense evasion, and data exfiltration techniques.

## Campaign Summary

- **Campaign Name**: Subtle Snail Campaign
- **Date**: October 8, 2025
- **Source**: [Prodaft Catalyst Report - Modus Operandi of Subtle Snail](https://catalyst.prodaft.com/public/report/modus-operandi-of-subtle-snail/overview)
- **Threat Level**: High
- **Threat Actor**: Subtle Snail (APT)

## MITRE ATT&CK Technique Mapping

### 1. Initial Access (TA0001)

#### T1566.001 - Spearphishing Attachment
- **Description**: Attackers use malicious email attachments to gain initial access
- **Implementation**: Highly customized phishing emails with malicious attachments
- **Detection**: Monitor for suspicious email attachments, especially from external sources
- **Mitigation**: Email security gateways, user training, attachment scanning

#### T1566.002 - Spearphishing Link
- **Description**: Phishing attacks using malicious links in emails
- **Implementation**: Emails containing links to compromised websites
- **Detection**: Monitor for suspicious URLs in emails, especially external links
- **Mitigation**: URL filtering, user training, web security gateways

#### T1189 - Drive-by Compromise
- **Description**: Malicious content delivered through compromised websites
- **Implementation**: Watering hole attacks targeting websites frequented by victims
- **Detection**: Monitor for connections to suspicious websites, especially watering holes
- **Mitigation**: Web filtering, browser security, user training

#### T1190 - Exploit Public-Facing Application
- **Description**: Exploitation of vulnerabilities in public-facing applications
- **Implementation**: Zero-day exploits and known vulnerabilities in web applications
- **Detection**: Monitor for exploitation attempts on public-facing applications
- **Mitigation**: Regular patching, web application firewalls, vulnerability management

#### T1078.004 - Valid Accounts: Cloud Accounts
- **Description**: Abuse of legitimate cloud accounts for access
- **Implementation**: Compromised cloud service accounts, guest user abuse
- **Detection**: Monitor for unusual cloud account activity, especially external access
- **Mitigation**: Cloud access controls, account monitoring, multi-factor authentication

### 2. Execution (TA0002)

#### T1059.001 - Command and Scripting Interpreter: PowerShell
- **Description**: PowerShell execution for malicious activities
- **Implementation**: PowerShell scripts for system reconnaissance and command execution
- **Detection**: Monitor PowerShell execution, especially with suspicious parameters
- **Mitigation**: PowerShell logging, execution policy restrictions, script signing

#### T1059.003 - Command and Scripting Interpreter: Windows Command Shell
- **Description**: Command shell execution for malicious activities
- **Implementation**: Batch files and command scripts for system operations
- **Detection**: Monitor command shell execution, especially from suspicious sources
- **Mitigation**: Command monitoring, application control, user training

#### T1059.005 - Command and Scripting Interpreter: Visual Basic
- **Description**: VBScript execution for malicious activities
- **Implementation**: VBScript files for system manipulation and persistence
- **Detection**: Monitor VBScript execution, especially with suspicious content
- **Mitigation**: Script monitoring, application control, user training

#### T1204.002 - User Execution: Malicious File
- **Description**: User execution of malicious files delivered via various methods
- **Implementation**: Malicious executables, documents, and scripts
- **Detection**: Monitor file execution, especially from suspicious sources
- **Mitigation**: File scanning, application control, user training

### 3. Persistence (TA0003)

#### T1543.003 - Create/Modify System Process: Windows Service
- **Description**: Creation of Windows services for persistence
- **Implementation**: Malicious services installed for long-term persistence
- **Detection**: Monitor for new service creation, especially by suspicious processes
- **Mitigation**: Service monitoring, application control, least privilege access

#### T1547.001 - Registry Run Keys/Startup Folder
- **Description**: Registry modifications for persistence
- **Implementation**: Adding malicious entries to Windows registry run keys
- **Detection**: Monitor registry modifications, especially in run keys
- **Mitigation**: Registry monitoring, application control, system hardening

#### T1053 - Scheduled Task/Job
- **Description**: Scheduled task creation for persistence
- **Implementation**: Automated execution of malicious payloads through scheduled tasks
- **Detection**: Monitor for scheduled task creation, especially by suspicious processes
- **Mitigation**: Task scheduler monitoring, application control, least privilege access

#### T1505.003 - Server Software Component: Web Shell
- **Description**: Web shell deployment for persistence
- **Implementation**: Malicious web shells installed on compromised servers
- **Detection**: Monitor for web shell uploads and execution
- **Mitigation**: Web application security, file monitoring, access controls

### 4. Privilege Escalation (TA0004)

#### T1068 - Exploitation for Privilege Escalation
- **Description**: Exploitation of vulnerabilities for privilege escalation
- **Implementation**: Zero-day exploits and known vulnerabilities for privilege escalation
- **Detection**: Monitor for privilege escalation attempts
- **Mitigation**: Regular patching, privilege monitoring, access controls

#### T1548.002 - Bypass User Account Control
- **Description**: Bypassing UAC for privilege escalation
- **Implementation**: UAC bypass techniques for elevated privileges
- **Detection**: Monitor for UAC bypass attempts
- **Mitigation**: UAC monitoring, application control, system hardening

#### T1055.012 - Process Injection: Process Hollowing
- **Description**: Process hollowing for privilege escalation
- **Implementation**: Injecting malicious code into legitimate processes
- **Detection**: Monitor for process injection activities
- **Mitigation**: Process monitoring, application control, system hardening

### 5. Defense Evasion (TA0005)

#### T1027 - Obfuscated Files or Information
- **Description**: File obfuscation to evade detection
- **Implementation**: Encrypted, compressed, or obfuscated malicious files
- **Detection**: Monitor for obfuscated files and suspicious file operations
- **Mitigation**: File analysis, behavioral detection, sandboxing

#### T1562.001 - Impair Defenses: Disable or Modify Tools
- **Description**: Disabling security tools and logging
- **Implementation**: Disabling antivirus, firewalls, and logging mechanisms
- **Detection**: Monitor for security tool modifications and disablement
- **Mitigation**: Security tool protection, monitoring, system hardening

#### T1070 - Indicator Removal
- **Description**: Clearing logs and forensic artifacts
- **Implementation**: Deleting event logs, clearing command history
- **Detection**: Monitor for log deletion and indicator removal activities
- **Mitigation**: Log protection, monitoring, forensic capabilities

#### T1140 - Deobfuscate/Decode Files or Information
- **Description**: Deobfuscation of malicious files
- **Implementation**: Decoding encrypted or obfuscated payloads
- **Detection**: Monitor for file deobfuscation activities
- **Mitigation**: File analysis, behavioral detection, sandboxing

### 6. Credential Access (TA0006)

#### T1003 - OS Credential Dumping
- **Description**: Credential extraction from system memory
- **Implementation**: Using tools like Mimikatz for credential dumping
- **Detection**: Monitor for credential dumping activities
- **Mitigation**: Credential protection, monitoring, system hardening

#### T1555 - Credentials from Password Stores
- **Description**: Extraction of stored credentials
- **Implementation**: Accessing password managers and credential stores
- **Detection**: Monitor for access to credential stores
- **Mitigation**: Credential store protection, monitoring, access controls

#### T1056.001 - Input Capture: Keylogging
- **Description**: Keylogging for credential capture
- **Implementation**: Hardware and software keyloggers
- **Detection**: Monitor for keylogging activities
- **Mitigation**: Input monitoring, user training, system hardening

#### T1552.001 - Unsecured Credentials: Credentials In Files
- **Description**: Credential extraction from files
- **Implementation**: Searching for credentials in configuration files
- **Detection**: Monitor for credential file access
- **Mitigation**: File monitoring, credential protection, access controls

### 7. Discovery (TA0007)

#### T1087.004 - Account Discovery: Cloud Account
- **Description**: Discovery of cloud accounts
- **Implementation**: Enumerating cloud service accounts and permissions
- **Detection**: Monitor for account enumeration activities
- **Mitigation**: Account monitoring, access controls, logging

#### T1018 - Remote System Discovery
- **Description**: Discovery of remote systems
- **Implementation**: Network scanning and system enumeration
- **Detection**: Monitor for network discovery activities
- **Mitigation**: Network monitoring, access controls, segmentation

#### T1046 - Network Service Scanning
- **Description**: Network service scanning
- **Implementation**: Port scanning and service enumeration
- **Detection**: Monitor for network scanning activities
- **Mitigation**: Network monitoring, firewalls, intrusion detection

#### T1083 - File and Directory Discovery
- **Description**: File and directory enumeration
- **Implementation**: Searching for sensitive files and directories
- **Detection**: Monitor for file system enumeration activities
- **Mitigation**: File monitoring, access controls, data classification

### 8. Lateral Movement (TA0008)

#### T1210 - Exploitation of Remote Services
- **Description**: Exploitation of remote services for lateral movement
- **Implementation**: Exploiting vulnerabilities in remote services
- **Detection**: Monitor for remote service exploitation
- **Mitigation**: Service hardening, monitoring, patching

#### T1570 - Lateral Tool Transfer
- **Description**: Transfer of tools for lateral movement
- **Implementation**: Moving tools and payloads between systems
- **Detection**: Monitor for lateral tool transfers
- **Mitigation**: Network monitoring, access controls, segmentation

#### T1021.001 - Remote Services: Remote Desktop Protocol
- **Description**: RDP for lateral movement
- **Implementation**: Using RDP for remote access and control
- **Detection**: Monitor for RDP connections and usage
- **Mitigation**: RDP monitoring, access controls, network segmentation

### 9. Collection (TA0009)

#### T1005 - Data from Local System
- **Description**: Collection of local system data
- **Implementation**: Gathering sensitive information from local systems
- **Detection**: Monitor for data collection activities
- **Mitigation**: Data loss prevention, monitoring, access controls

#### T1113 - Screen Capture
- **Description**: Screen capture for intelligence gathering
- **Implementation**: Capturing user screens and activities
- **Detection**: Monitor for screen capture activities
- **Mitigation**: Screen sharing controls, monitoring, user awareness

#### T1114.003 - Email Collection: Email Forwarding Rules
- **Description**: Email collection through forwarding rules
- **Implementation**: Setting up email forwarding for data collection
- **Detection**: Monitor for email forwarding rule changes
- **Mitigation**: Email monitoring, access controls, user training

#### T1119 - Automated Collection
- **Description**: Automated data collection
- **Implementation**: Automated scripts for data gathering
- **Detection**: Monitor for automated collection activities
- **Mitigation**: Process monitoring, access controls, data protection

### 10. Command and Control (TA0011)

#### T1071.001 - Application Layer Protocol: Web Protocols
- **Description**: C2 communication over web protocols
- **Implementation**: HTTPS communication with C2 servers
- **Detection**: Monitor for C2 communication patterns
- **Mitigation**: Network monitoring, C2 detection, traffic analysis

#### T1071.004 - Application Layer Protocol: DNS
- **Description**: DNS-based C2 communication
- **Implementation**: DNS tunneling for command and control
- **Detection**: Monitor for DNS-based C2 communication
- **Mitigation**: DNS monitoring, filtering, traffic analysis

#### T1102.003 - Web Service: OneDrive
- **Description**: C2 communication via OneDrive
- **Implementation**: Using OneDrive for command and control
- **Detection**: Monitor for OneDrive C2 activities
- **Mitigation**: OneDrive monitoring, access controls, data protection

#### T1104 - Multi-Stage Channels
- **Description**: Multi-stage C2 communication
- **Implementation**: Complex C2 infrastructure with multiple stages
- **Detection**: Monitor for multi-stage C2 communication
- **Mitigation**: Network monitoring, traffic analysis, C2 detection

### 11. Exfiltration (TA0010)

#### T1041 - Exfiltration Over C2 Channel
- **Description**: Data exfiltration over C2 channels
- **Implementation**: Data theft through command and control channels
- **Detection**: Monitor for data exfiltration activities
- **Mitigation**: Data loss prevention, network monitoring, traffic analysis

#### T1567.002 - Exfiltration Over Web Service: To Cloud Storage
- **Description**: Data exfiltration to cloud storage
- **Implementation**: Uploading stolen data to cloud storage services
- **Detection**: Monitor for cloud storage exfiltration
- **Mitigation**: Cloud access controls, monitoring, data protection

#### T1048.003 - Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol
- **Description**: Data exfiltration over unencrypted protocols
- **Implementation**: Data theft through unencrypted communication channels
- **Detection**: Monitor for unencrypted data exfiltration
- **Mitigation**: Encryption monitoring, data loss prevention, traffic analysis

## Detection Strategies

### Network-Based Detection
- **C2 Communication**: Monitor for connections to known C2 infrastructure
- **Domain Fronting**: Detect domain fronting patterns
- **Encrypted Traffic**: Monitor for unusual encrypted communication
- **DNS Queries**: Track suspicious DNS query patterns

### Endpoint Detection
- **Process Monitoring**: Monitor for suspicious process creation
- **Registry Changes**: Track registry modifications
- **File System Changes**: Monitor for suspicious file operations
- **Network Connections**: Track outbound network connections

### Behavioral Detection
- **Living-off-the-Land**: Detect abuse of legitimate system tools
- **Process Injection**: Monitor for process injection activities
- **Credential Dumping**: Detect credential theft attempts
- **Screen Capture**: Monitor for screen capture activities

## Mitigation Strategies

### Technical Controls
- **Endpoint Detection and Response (EDR)**: Advanced endpoint protection
- **Network Monitoring**: Comprehensive network traffic analysis
- **Email Security**: Advanced email threat protection
- **Web Application Firewalls**: Protection for web applications
- **Network Segmentation**: Isolating critical systems

### Administrative Controls
- **Security Awareness Training**: Educating users about threats
- **Incident Response Planning**: Preparing for security incidents
- **Regular Security Assessments**: Ongoing security evaluations
- **Vendor Risk Management**: Managing third-party risks
- **Access Controls**: Implementing least privilege access

### Monitoring and Detection
- **24/7 Security Operations Center**: Continuous monitoring
- **Threat Hunting**: Proactive threat detection
- **Behavioral Analytics**: Advanced behavioral analysis
- **IOC Monitoring**: Tracking known threat indicators
- **Threat Intelligence Integration**: Leveraging threat intelligence

## Key Takeaways

1. **Advanced Persistent Threat**: Subtle Snail represents a sophisticated APT with long-term objectives
2. **Living-off-the-Land**: Legitimate system tools can be weaponized for malicious purposes
3. **Persistence is Key**: APT actors focus on maintaining long-term access
4. **Multi-layered Defense**: Comprehensive security measures are essential
5. **Threat Intelligence**: Continuous threat intelligence is critical for defense

## References

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Prodaft Catalyst Report - Modus Operandi of Subtle Snail](https://catalyst.prodaft.com/public/report/modus-operandi-of-subtle-snail/overview)
- [Advanced Persistent Threat (APT) Analysis](https://attack.mitre.org/groups/)
- [Threat Actor Profiling](https://attack.mitre.org/groups/)
- [Defense Evasion Techniques](https://attack.mitre.org/tactics/TA0005/)

---

**Analysis Date**: October 8, 2025  
**Threat Level**: High  
**Confidence Level**: High  
**Last Updated**: October 8, 2025

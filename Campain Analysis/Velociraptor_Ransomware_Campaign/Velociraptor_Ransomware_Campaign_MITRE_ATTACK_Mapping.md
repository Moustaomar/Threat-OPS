# Velociraptor Ransomware Campaign - MITRE ATT&CK Mapping

## Overview

This document provides a comprehensive mapping of the Velociraptor Ransomware Campaign to the MITRE ATT&CK framework. The campaign demonstrates sophisticated abuse of legitimate DFIR tools and cloud infrastructure for ransomware operations.

## Campaign Summary

- **Campaign Name**: Velociraptor Ransomware Campaign
- **Date**: October 6, 2025
- **Source**: Cisco Talos Intelligence
- **Associated Ransomware**: LockBit, Babuk Ransomware
- **Threat Group**: AEGIS
- **Threat Level**: High

## MITRE ATT&CK Technique Mapping

### Initial Access (TA0001)

#### T1078.004 - Valid Accounts: Cloud Accounts
- **Description**: Adversaries may obtain and abuse credentials of a cloud account to gain initial access to a cloud environment.
- **Campaign Usage**: Threat actors compromise legitimate cloud accounts to establish C2 infrastructure
- **Indicators**: 
  - Azure blob storage abuse (stoaccinfoniqaveeambkp.blob.core.windows.net)
  - Cloudflare Workers abuse (velo.qaubctgg.workers.dev)
- **Detection**: Monitor for unusual cloud service usage patterns
- **Mitigation**: Implement cloud access controls and monitoring

#### T1584.003 - Virtual Private Server
- **Description**: Adversaries may compromise third-party Virtual Private Servers (VPSs) that can be used during targeting.
- **Campaign Usage**: Use of compromised VPS infrastructure for C2 operations
- **Indicators**: IP address 65.38.121.226
- **Detection**: Monitor for connections to suspicious IP addresses
- **Mitigation**: Implement network segmentation and monitoring

### Execution (TA0002)

#### T1059.001 - Command and Scripting Interpreter: PowerShell
- **Description**: Adversaries may abuse PowerShell commands and scripts for execution.
- **Campaign Usage**: PowerShell execution through Velociraptor abuse
- **Indicators**: PowerShell command execution in DFIR tool context
- **Detection**: Monitor PowerShell execution patterns
- **Mitigation**: Implement PowerShell logging and monitoring

#### T1053 - Scheduled Task/Job
- **Description**: Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code.
- **Campaign Usage**: Scheduled tasks for persistence and execution
- **Indicators**: Unusual scheduled task creation
- **Detection**: Monitor scheduled task creation and execution
- **Mitigation**: Implement task scheduling controls

#### T1055 - Process Injection
- **Description**: Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges.
- **Campaign Usage**: Process injection for evasion and persistence
- **Indicators**: Unusual process injection activities
- **Detection**: Monitor for process injection techniques
- **Mitigation**: Implement process monitoring and protection

### Persistence (TA0003)

#### T1053 - Scheduled Task/Job
- **Description**: Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code.
- **Campaign Usage**: Scheduled tasks for long-term persistence
- **Indicators**: Persistent scheduled tasks
- **Detection**: Monitor scheduled task persistence
- **Mitigation**: Implement task scheduling governance

#### T1078.004 - Valid Accounts: Cloud Accounts
- **Description**: Adversaries may obtain and abuse credentials of a cloud account to maintain persistent access to a cloud environment.
- **Campaign Usage**: Persistent cloud account access for C2 operations
- **Indicators**: Persistent cloud service usage
- **Detection**: Monitor cloud account persistence
- **Mitigation**: Implement cloud access governance

### Defense Evasion (TA0005)

#### T1027 - Obfuscated Files or Information
- **Description**: Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents.
- **Campaign Usage**: Obfuscation of malicious files and communications
- **Indicators**: Obfuscated files and communications
- **Detection**: Monitor for obfuscation techniques
- **Mitigation**: Implement file analysis and monitoring

#### T1140 - Deobfuscate/Decode Files or Information
- **Description**: Adversaries may use obfuscated files or information to hide artifacts of an intrusion from analysis.
- **Campaign Usage**: Deobfuscation of malicious content
- **Indicators**: Deobfuscation activities
- **Detection**: Monitor for deobfuscation techniques
- **Mitigation**: Implement content analysis and monitoring

#### T1562.001 - Impair Defenses: Disable or Modify Tools
- **Description**: Adversaries may disable or modify security tools to avoid possible detection of their malware/tools and activities.
- **Campaign Usage**: Disabling security tools and defenses
- **Indicators**: Security tool tampering
- **Detection**: Monitor for security tool tampering
- **Mitigation**: Implement security tool protection

### Credential Access (TA0006)

#### T1003 - OS Credential Dumping
- **Description**: Adversaries may attempt to dump credentials to obtain account login and credential material, normally in the form of a hash or a clear text password.
- **Campaign Usage**: Credential dumping through Velociraptor abuse
- **Indicators**: Credential dumping activities
- **Detection**: Monitor for credential dumping techniques
- **Mitigation**: Implement credential protection

#### T1555 - Credentials from Password Stores
- **Description**: Adversaries may search for common password storage locations to obtain user credentials.
- **Campaign Usage**: Access to password stores through DFIR tool abuse
- **Indicators**: Password store access
- **Detection**: Monitor for password store access
- **Mitigation**: Implement password store protection

#### T1056.001 - Input Capture: Keylogging
- **Description**: Adversaries may log user keystrokes to intercept credentials as the user types them.
- **Campaign Usage**: Keylogging through Velociraptor capabilities
- **Indicators**: Keylogging activities
- **Detection**: Monitor for keylogging techniques
- **Mitigation**: Implement input protection

### Discovery (TA0007)

#### T1087.004 - Account Discovery: Cloud Account
- **Description**: Adversaries may attempt to get a listing of cloud accounts.
- **Campaign Usage**: Discovery of cloud accounts for targeting
- **Indicators**: Cloud account enumeration
- **Detection**: Monitor for cloud account discovery
- **Mitigation**: Implement cloud account monitoring

#### T1018 - Remote System Discovery
- **Description**: Adversaries may attempt to get a listing of other systems by IP address, hostname, or other logical identifier on a network that may be used for lateral movement.
- **Campaign Usage**: Network discovery through Velociraptor abuse
- **Indicators**: Network discovery activities
- **Detection**: Monitor for network discovery
- **Mitigation**: Implement network segmentation

#### T1046 - Network Service Scanning
- **Description**: Adversaries may attempt to get a listing of services running on remote hosts and local network infrastructure devices.
- **Campaign Usage**: Service scanning through DFIR tool capabilities
- **Indicators**: Service scanning activities
- **Detection**: Monitor for service scanning
- **Mitigation**: Implement service monitoring

### Collection (TA0009)

#### T1005 - Data from Local System
- **Description**: Adversaries may search local system sources, such as file systems and configuration files, to find files of interest and sensitive data prior to exfiltration.
- **Campaign Usage**: Data collection through Velociraptor abuse
- **Indicators**: Unusual data collection activities
- **Detection**: Monitor for data collection patterns
- **Mitigation**: Implement data protection

#### T1113 - Screen Capture
- **Description**: Adversaries may attempt to take screen captures of the desktop to gather information over the course of an operation.
- **Campaign Usage**: Screen capture through DFIR tool capabilities
- **Indicators**: Screen capture activities
- **Detection**: Monitor for screen capture
- **Mitigation**: Implement screen protection

#### T1119 - Automated Collection
- **Description**: Adversaries may use automated techniques for collecting internal data.
- **Campaign Usage**: Automated data collection through Velociraptor
- **Indicators**: Automated collection activities
- **Detection**: Monitor for automated collection
- **Mitigation**: Implement automation monitoring

### Command and Control (TA0011)

#### T1071.001 - Application Layer Protocol: Web Protocols
- **Description**: Adversaries may communicate using application layer protocols associated with web traffic to avoid detection/network filtering by blending in with existing traffic.
- **Campaign Usage**: Web protocol communication for C2
- **Indicators**: Web protocol C2 communication
- **Detection**: Monitor for web protocol C2
- **Mitigation**: Implement web traffic monitoring

#### T1102.003 - Web Service: OneDrive
- **Description**: Adversaries may use OneDrive as an intermediary to support and hide C2 communications.
- **Campaign Usage**: OneDrive abuse for C2 operations
- **Indicators**: OneDrive C2 communication
- **Detection**: Monitor for OneDrive C2
- **Mitigation**: Implement OneDrive monitoring

#### T1104 - Multi-Stage Channels
- **Description**: Adversaries may create one or more redundant or alternative communication channels between the components of distributed malware.
- **Campaign Usage**: Multi-stage C2 communication
- **Indicators**: Multi-stage C2 patterns
- **Detection**: Monitor for multi-stage C2
- **Mitigation**: Implement C2 monitoring

### Exfiltration (TA0010)

#### T1041 - Exfiltration Over C2 Channel
- **Description**: Adversaries may steal data by exfiltrating it over an existing command and control channel.
- **Campaign Usage**: Data exfiltration over C2 channels
- **Indicators**: C2 channel exfiltration
- **Detection**: Monitor for C2 exfiltration
- **Mitigation**: Implement exfiltration monitoring

#### T1567.002 - Exfiltration Over Web Service: To Cloud Storage
- **Description**: Adversaries may exfiltrate data to cloud storage services rather than over their primary command and control channel.
- **Campaign Usage**: Cloud storage exfiltration
- **Indicators**: Cloud storage exfiltration
- **Detection**: Monitor for cloud exfiltration
- **Mitigation**: Implement cloud exfiltration monitoring

## Detection Strategies

### Network-Based Detection
- **Cloud Service Monitoring**: Monitor for unusual cloud service usage
- **API Call Analysis**: Analyze cloud service API calls
- **C2 Communication**: Detect encrypted C2 communication
- **Domain Analysis**: Monitor for suspicious domains

### Endpoint Detection
- **DFIR Tool Monitoring**: Monitor Velociraptor usage
- **PowerShell Analysis**: Analyze PowerShell execution
- **Process Monitoring**: Monitor for process injection
- **File System Monitoring**: Detect unusual file access

### Behavioral Detection
- **Tool Abuse Detection**: Detect abuse of legitimate tools
- **Cloud Service Abuse**: Identify unusual cloud usage
- **Data Collection Patterns**: Detect unusual data collection
- **Lateral Movement**: Identify lateral movement patterns

## Mitigation Strategies

### Technical Controls
- **DFIR Tool Security**: Implement proper security controls
- **Cloud Security**: Implement cloud security controls
- **Endpoint Protection**: Deploy advanced endpoint protection
- **Network Segmentation**: Implement network segmentation

### Administrative Controls
- **Access Management**: Implement proper access controls
- **Cloud Governance**: Implement cloud governance
- **Security Training**: Provide security training
- **Incident Response**: Develop incident response procedures

### Monitoring and Detection
- **Tool Monitoring**: Implement tool monitoring
- **Cloud Monitoring**: Deploy cloud monitoring
- **Behavioral Analytics**: Implement behavioral analysis
- **Threat Hunting**: Conduct proactive threat hunting

## Conclusion

The Velociraptor Ransomware Campaign demonstrates sophisticated abuse of legitimate DFIR tools and cloud infrastructure. The comprehensive MITRE ATT&CK mapping provides organizations with detailed information about the techniques used and appropriate detection and mitigation strategies.

Organizations should implement comprehensive security measures including proper tool governance, cloud security controls, advanced monitoring, and proactive threat hunting to defend against similar campaigns.

---

**Report Date**: October 6, 2025  
**Threat Level**: High  
**Confidence Level**: High  
**Source**: [Cisco Talos - Velociraptor leveraged in ransomware attacks](https://raw.githubusercontent.com/Cisco-Talos/IOCs/refs/heads/main/2025/10/velociraptor-leveraged-in-ransomware-attacks.json)  
**Last Updated**: October 6, 2025

# UAT-8099 Chinese Cybercrime Group Campaign - MITRE ATT&CK Mapping

## Overview

This document provides a comprehensive mapping of the UAT-8099 Chinese Cybercrime Group Campaign to the MITRE ATT&CK framework. The campaign demonstrates sophisticated abuse of IIS servers for SEO fraud and search engine manipulation.

## Campaign Summary

- **Campaign Name**: UAT-8099 Chinese Cybercrime Group Campaign
- **Date**: September 30, 2025
- **Source**: Cisco Talos Intelligence
- **Associated Threat Actor**: UAT-8099
- **Primary Objective**: SEO fraud and search engine manipulation
- **Threat Level**: High

## MITRE ATT&CK Technique Mapping

### Initial Access (TA0001)

#### T1078.004 - Valid Accounts: Cloud Accounts
- **Description**: Adversaries may obtain and abuse credentials of a cloud account to gain initial access to a cloud environment.
- **Campaign Usage**: Compromise of cloud accounts for IIS server access
- **Indicators**: 
  - Cloud account abuse
  - Unusual cloud service usage
  - IIS server access through cloud accounts
- **Detection**: Monitor for unusual cloud service usage patterns
- **Mitigation**: Implement cloud access controls and monitoring

#### T1584.003 - Virtual Private Server
- **Description**: Adversaries may compromise third-party Virtual Private Servers (VPSs) that can be used during targeting.
- **Campaign Usage**: Use of compromised VPS infrastructure for SEO fraud operations
- **Indicators**: 
  - VPS abuse for SEO fraud
  - Unusual VPS usage patterns
  - SEO fraud infrastructure
- **Detection**: Monitor for VPS abuse and SEO fraud activities
- **Mitigation**: Implement VPS monitoring and security controls

### Execution (TA0002)

#### T1059.001 - Command and Scripting Interpreter: PowerShell
- **Description**: Adversaries may abuse PowerShell commands and scripts for execution.
- **Campaign Usage**: PowerShell execution for IIS server exploitation and SEO fraud
- **Indicators**: 
  - PowerShell command execution
  - IIS server manipulation
  - SEO fraud script execution
- **Detection**: Monitor PowerShell execution and script content
- **Mitigation**: Implement PowerShell logging and script execution policies

#### T1053 - Scheduled Task/Job
- **Description**: Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code.
- **Campaign Usage**: Scheduled tasks for persistent SEO fraud operations
- **Indicators**: 
  - Unusual scheduled task creation
  - SEO fraud task scheduling
  - Persistent task execution
- **Detection**: Monitor scheduled task creation and execution
- **Mitigation**: Implement task scheduling controls

#### T1035 - Service Execution
- **Description**: Adversaries may execute a binary, command, or script via a method that interacts with Windows services.
- **Campaign Usage**: Service execution for IIS server exploitation
- **Indicators**: 
  - Service abuse for IIS exploitation
  - Unusual service execution
  - IIS server service manipulation
- **Detection**: Monitor for service execution abuse
- **Mitigation**: Implement service monitoring and controls

#### T1064 - Scripting
- **Description**: Adversaries may use scripts to aid in operations and perform multiple actions that would otherwise be manual.
- **Campaign Usage**: Scripting for automated SEO fraud operations
- **Indicators**: 
  - Automated SEO fraud scripts
  - Script-based IIS exploitation
  - Automated content manipulation
- **Detection**: Monitor for scripting activities
- **Mitigation**: Implement script monitoring and controls

#### T1569 - System Services
- **Description**: Adversaries may abuse system services or daemons to execute commands or programs.
- **Campaign Usage**: System service abuse for IIS server exploitation
- **Indicators**: 
  - System service abuse
  - IIS service manipulation
  - Service-based exploitation
- **Detection**: Monitor for system service abuse
- **Mitigation**: Implement system service monitoring

### Persistence (TA0003)

#### T1053 - Scheduled Task/Job
- **Description**: Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code.
- **Campaign Usage**: Scheduled tasks for persistent SEO fraud operations
- **Indicators**: 
  - Persistent scheduled tasks
  - SEO fraud task persistence
  - Long-term task execution
- **Detection**: Monitor scheduled task persistence
- **Mitigation**: Implement task scheduling governance

#### T1035 - Service Execution
- **Description**: Adversaries may execute a binary, command, or script via a method that interacts with Windows services.
- **Campaign Usage**: Service execution for persistent IIS server access
- **Indicators**: 
  - Persistent service execution
  - IIS service persistence
  - Long-term service abuse
- **Detection**: Monitor for persistent service execution
- **Mitigation**: Implement service persistence monitoring

#### T1569 - System Services
- **Description**: Adversaries may abuse system services or daemons to execute commands or programs.
- **Campaign Usage**: System service abuse for persistent access
- **Indicators**: 
  - Persistent system service abuse
  - Long-term service manipulation
  - Service-based persistence
- **Detection**: Monitor for persistent system service abuse
- **Mitigation**: Implement system service persistence monitoring

### Defense Evasion (TA0005)

#### T1027 - Obfuscated Files or Information
- **Description**: Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents.
- **Campaign Usage**: Obfuscation of SEO fraud tools and scripts
- **Indicators**: 
  - Obfuscated SEO fraud tools
  - Encrypted content manipulation scripts
  - Hidden SEO fraud activities
- **Detection**: Monitor for obfuscation techniques
- **Mitigation**: Implement file analysis and content inspection

#### T1140 - Deobfuscate/Decode Files or Information
- **Description**: Adversaries may use obfuscated files or information to hide artifacts of an intrusion from analysis.
- **Campaign Usage**: Deobfuscation of SEO fraud content and tools
- **Indicators**: 
  - Deobfuscation activities
  - SEO fraud content decoding
  - Hidden content manipulation
- **Detection**: Monitor for deobfuscation techniques
- **Mitigation**: Implement content analysis and monitoring

#### T1562.001 - Impair Defenses: Disable or Modify Tools
- **Description**: Adversaries may disable or modify security tools to avoid possible detection of their malware/tools and activities.
- **Campaign Usage**: Disabling security tools to avoid detection of SEO fraud activities
- **Indicators**: 
  - Security tool tampering
  - SEO fraud detection evasion
  - Defense disabling
- **Detection**: Monitor for security tool tampering
- **Mitigation**: Implement security tool protection

### Credential Access (TA0006)

#### T1003 - OS Credential Dumping
- **Description**: Adversaries may attempt to dump credentials to obtain account login and credential material.
- **Campaign Usage**: Credential dumping for IIS server access
- **Indicators**: 
  - Credential dumping activities
  - IIS server credential theft
  - Password hash extraction
- **Detection**: Monitor for credential dumping techniques
- **Mitigation**: Implement credential protection

#### T1555 - Credentials from Password Stores
- **Description**: Adversaries may search for common password storage locations to obtain user credentials.
- **Campaign Usage**: Access to password stores for IIS server credentials
- **Indicators**: 
  - Password store access
  - IIS credential theft
  - Password extraction
- **Detection**: Monitor for password store access
- **Mitigation**: Implement password store protection

#### T1056.001 - Input Capture: Keylogging
- **Description**: Adversaries may log user keystrokes to intercept credentials as the user types them.
- **Campaign Usage**: Keylogging for credential theft
- **Indicators**: 
  - Keylogging activities
  - Credential interception
  - Input capture
- **Detection**: Monitor for keylogging techniques
- **Mitigation**: Implement input protection

### Discovery (TA0007)

#### T1087.004 - Account Discovery: Cloud Account
- **Description**: Adversaries may attempt to get a listing of cloud accounts.
- **Campaign Usage**: Discovery of cloud accounts for IIS server access
- **Indicators**: 
  - Cloud account enumeration
  - IIS server account discovery
  - Cloud service access
- **Detection**: Monitor for cloud account discovery
- **Mitigation**: Implement cloud account monitoring

#### T1018 - Remote System Discovery
- **Description**: Adversaries may attempt to get a listing of other systems by IP address, hostname, or other logical identifier on a network.
- **Campaign Usage**: Network discovery for IIS server targeting
- **Indicators**: 
  - Network discovery activities
  - IIS server enumeration
  - System discovery
- **Detection**: Monitor for network discovery
- **Mitigation**: Implement network segmentation

#### T1046 - Network Service Scanning
- **Description**: Adversaries may attempt to get a listing of services running on remote hosts and local network infrastructure devices.
- **Campaign Usage**: Service scanning for IIS server vulnerabilities
- **Indicators**: 
  - Service scanning activities
  - IIS service enumeration
  - Vulnerability scanning
- **Detection**: Monitor for service scanning
- **Mitigation**: Implement service monitoring

### Collection (TA0009)

#### T1005 - Data from Local System
- **Description**: Adversaries may search local system sources to find files of interest and sensitive data prior to exfiltration.
- **Campaign Usage**: Data collection from compromised IIS servers
- **Indicators**: 
  - Unusual data collection activities
  - IIS server data access
  - Content analysis
- **Detection**: Monitor for data collection patterns
- **Mitigation**: Implement data protection

#### T1113 - Screen Capture
- **Description**: Adversaries may attempt to take screen captures of the desktop to gather information.
- **Campaign Usage**: Screen capture for intelligence gathering
- **Indicators**: 
  - Screen capture activities
  - Visual data collection
  - Screenshot capture
- **Detection**: Monitor for screen capture
- **Mitigation**: Implement screen protection

#### T1119 - Automated Collection
- **Description**: Adversaries may use automated techniques for collecting internal data.
- **Campaign Usage**: Automated data collection for SEO fraud intelligence
- **Indicators**: 
  - Automated collection activities
  - SEO fraud data gathering
  - Automated processes
- **Detection**: Monitor for automated collection
- **Mitigation**: Implement automation monitoring

### Command and Control (TA0011)

#### T1071.001 - Application Layer Protocol: Web Protocols
- **Description**: Adversaries may communicate using application layer protocols associated with web traffic to avoid detection.
- **Campaign Usage**: Web protocol communication for SEO fraud C2
- **Indicators**: 
  - Web protocol C2 communication
  - SEO fraud C2 traffic
  - HTTP/HTTPS C2
- **Detection**: Monitor for web protocol C2
- **Mitigation**: Implement web traffic monitoring

#### T1102.003 - Web Service: OneDrive
- **Description**: Adversaries may use OneDrive as an intermediary to support and hide C2 communications.
- **Campaign Usage**: OneDrive abuse for SEO fraud C2
- **Indicators**: 
  - OneDrive C2 communication
  - SEO fraud C2 through OneDrive
  - Cloud service C2
- **Detection**: Monitor for OneDrive C2
- **Mitigation**: Implement OneDrive monitoring

#### T1104 - Multi-Stage Channels
- **Description**: Adversaries may create one or more redundant or alternative communication channels between the components of distributed malware.
- **Campaign Usage**: Multi-stage C2 communication for SEO fraud operations
- **Indicators**: 
  - Multi-stage C2 patterns
  - SEO fraud C2 redundancy
  - Alternative channels
- **Detection**: Monitor for multi-stage C2
- **Mitigation**: Implement C2 monitoring

### Exfiltration (TA0010)

#### T1041 - Exfiltration Over C2 Channel
- **Description**: Adversaries may steal data by exfiltrating it over an existing command and control channel.
- **Campaign Usage**: Data exfiltration over C2 channels for SEO fraud
- **Indicators**: 
  - C2 channel exfiltration
  - SEO fraud data theft
  - Information exfiltration
- **Detection**: Monitor for C2 exfiltration
- **Mitigation**: Implement exfiltration monitoring

#### T1567.002 - Exfiltration Over Web Service: To Cloud Storage
- **Description**: Adversaries may exfiltrate data to cloud storage services rather than over their primary command and control channel.
- **Campaign Usage**: Cloud storage exfiltration for SEO fraud data
- **Indicators**: 
  - Cloud storage exfiltration
  - SEO fraud data to cloud
  - Web service exfiltration
- **Detection**: Monitor for cloud exfiltration
- **Mitigation**: Implement cloud exfiltration monitoring

## Detection Strategies

### Network-Based Detection
- **SEO Fraud Domains**: Monitor for connections to SEO fraud infrastructure
- **IIS Server Abuse**: Monitor for unusual IIS server activity
- **Search Engine Manipulation**: Monitor for search engine traffic patterns
- **Content Injection**: Monitor for content injection activities

### Endpoint Detection
- **IIS Server Monitoring**: Monitor for IIS server modifications
- **Content Analysis**: Analyze content for spam and manipulation
- **SEO Activities**: Monitor for SEO-related activities
- **Traffic Analysis**: Analyze traffic for unusual patterns

### Behavioral Detection
- **SEO Fraud**: Detect SEO fraud activities
- **Search Engine Gaming**: Detect manipulation of search engine algorithms
- **Content Spam**: Detect injection of spam content
- **Traffic Diversion**: Detect diversion of legitimate traffic

## Mitigation Strategies

### Technical Controls
- **IIS Security**: Implement comprehensive IIS security controls
- **Web Application Security**: Deploy web application firewalls
- **Content Security**: Implement content security policies
- **Search Engine Monitoring**: Monitor for search engine manipulation

### Administrative Controls
- **SEO Governance**: Implement SEO governance policies
- **Content Management**: Implement content management controls
- **Traffic Monitoring**: Monitor for unusual traffic patterns
- **Search Engine Policies**: Implement search engine usage policies

### Monitoring and Detection
- **SEO Monitoring**: Monitor for SEO fraud activities
- **Search Engine Analytics**: Analyze search engine traffic patterns
- **Content Analysis**: Analyze content for spam and manipulation
- **Traffic Analysis**: Analyze traffic for unusual patterns

## Conclusion

The UAT-8099 Chinese Cybercrime Group Campaign demonstrates sophisticated abuse of IIS servers for SEO fraud and search engine manipulation. The comprehensive MITRE ATT&CK mapping provides organizations with detailed information about the techniques used and appropriate detection and mitigation strategies.

Organizations should implement comprehensive security measures including IIS security controls, content monitoring, search engine analytics, and proactive threat hunting to defend against similar campaigns.

---

**Report Date**: September 30, 2025  
**Threat Level**: High  
**Confidence Level**: High  
**Source**: [Cisco Talos - UAT-8099: Chinese-speaking cybercrime group targets high-value IIS for SEO fraud](https://raw.githubusercontent.com/Cisco-Talos/IOCs/refs/heads/main/2025/09/uat-8099-chinese-speaking-cybercrime-group-seo-fraud.json)  
**Last Updated**: September 30, 2025

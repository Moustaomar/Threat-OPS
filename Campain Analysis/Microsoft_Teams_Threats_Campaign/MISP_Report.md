# MISP Report - Microsoft Teams Threats Campaign

## Executive Summary

This MISP report documents the Microsoft Teams Threats campaign, a comprehensive analysis of threat actors abusing Microsoft Teams capabilities for reconnaissance, initial access, persistence, and data exfiltration. The campaign covers various attack techniques used by threat actors to exploit Teams' core features including messaging, calls/meetings, and video-based screen sharing.

## Campaign Overview

- **Campaign Name**: Microsoft Teams Threats Campaign
- **Threat Actor**: Multiple threat actors abusing Microsoft Teams
- **Attribution**: Various (cybercriminals and state-sponsored actors)
- **Target**: Microsoft Teams users and organizations
- **Threat Level**: High
- **Date**: October 7, 2025

## Threat Intelligence Summary

### Primary Attack Vectors
- **Messaging (Chat) Abuse**: One-on-one phishing chats, impersonation attacks
- **Calls and Meetings Abuse**: Meeting hijacking, screen sharing exploitation
- **Video-based Screen Sharing Abuse**: Screen capture for intelligence gathering
- **File Upload Abuse**: Malicious file sharing and storage

### Key Indicators of Compromise (IOCs)

#### Attack Tools and Frameworks
- **ROADtools** - Microsoft Graph API exploitation framework
- **TeamFiltration** - Teams enumeration and exploitation toolkit
- **TeamsEnum** - Teams-specific reconnaissance tool
- **MSFT-Recon-RS** - Microsoft reconnaissance framework
- **GraphRunner** - Microsoft Graph API abuse tool
- **TeamsPhisher** - Teams phishing toolkit
- **convoC2** - Teams command and control framework
- **EvilSlackbot** - Malicious Teams bot

#### Known Campaigns
- **3AM Ransomware** - Teams vishing campaigns
- **DarkGate Malware** - Teams-based delivery
- **Atomic Stealer** - Fake Teams for Mac delivery
- **VEILDrive** - C2 via Microsoft services

#### Target Sectors
- **Government Entities** - National and local government organizations
- **Critical Infrastructure** - Power, water, transportation, and communication systems
- **Defense Contractors** - Military and defense industry companies
- **Financial Institutions** - Banks, investment firms, and financial services
- **Healthcare Organizations** - Hospitals, pharmaceutical companies, and medical research
- **Energy Sector** - Oil, gas, and renewable energy companies
- **Telecommunications** - Telecom providers and communication infrastructure
- **Technology Companies** - Software, hardware, and IT service providers

## Technical Analysis

### Attack Techniques

#### Reconnaissance
- **Directory Object Enumeration**: Teams and channel member enumeration
- **Tenant Analysis**: Tenant ID and domain enumeration
- **Federation Configuration**: External communication permissions analysis
- **Presence Exploitation**: User presence status exploitation

#### Initial Access
- **Phishing via Teams Chat**: One-on-one phishing chats
- **Malicious File Uploads**: Binary executable uploads
- **External User Impersonation**: Guest user account abuse
- **Anonymous Participant Exploitation**: Cross-tenant communication abuse

#### Persistence
- **Web Shell Deployment**: Malicious file storage in Teams chat files
- **Account Persistence**: External user account maintenance
- **Guest User Abuse**: Persistent access through guest accounts

#### Data Exfiltration
- **Screen Sharing Abuse**: Screen capture for intelligence gathering
- **File Exfiltration**: Malicious file sharing
- **External Communication**: Data theft through external channels

## MITRE ATT&CK Mapping

### Initial Access
- **T1566.001**: Spearphishing Attachment
- **T1566.003**: Spearphishing via Service
- **T1189**: Drive-by Compromise
- **T1078.004**: Valid Accounts: Cloud Accounts

### Execution
- **T1059.001**: Command and Scripting Interpreter: PowerShell
- **T1059.003**: Command and Scripting Interpreter: Windows Command Shell
- **T1204.002**: User Execution: Malicious File

### Persistence
- **T1078.004**: Valid Accounts: Cloud Accounts
- **T1505.003**: Server Software Component: Web Shell
- **T1543.003**: Create/Modify System Process: Windows Service

### Defense Evasion
- **T1078.004**: Valid Accounts: Cloud Accounts
- **T1562.001**: Impair Defenses: Disable or Modify Tools
- **T1027**: Obfuscated Files or Information

### Command and Control
- **T1071.001**: Application Layer Protocol: Web Protocols
- **T1071.004**: Application Layer Protocol: DNS
- **T1102.003**: Web Service: OneDrive

### Exfiltration
- **T1041**: Exfiltration Over C2 Channel
- **T1567.002**: Exfiltration Over Web Service: To Cloud Storage
- **T1048.003**: Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol

## Detection Recommendations

### Microsoft Defender XDR Queries
- **Teams External Communication Detection**: Monitor external thread communications
- **Suspicious File Upload Detection**: Track file uploads to Teams
- **Impersonation Detection**: Detect impersonation attempts
- **Guest User Monitoring**: Monitor guest user activities

### Microsoft Sentinel Queries
- **Teams Phishing Activity Detection**: Monitor for Teams phishing activities
- **File Upload and Access Tracking**: Track file uploads and access
- **External Communication Monitoring**: Monitor external user interactions
- **Guest User Abuse Detection**: Detect guest user abuse

## Mitigation Strategies

### Technical Controls
- **Microsoft Entra ID Protection**: Identity threat detection and protection
- **Microsoft Defender for Cloud Apps**: Cloud application security
- **Microsoft Defender for Office 365**: Email and collaboration security
- **Microsoft Defender for Endpoint**: Endpoint detection and response
- **Microsoft Defender for Identity**: Identity threat detection

### Administrative Controls
- **User Education**: Teams security training and awareness
- **Policy Implementation**: Guest user and external communication policies
- **Access Controls**: Strict access management
- **Monitoring**: Continuous security monitoring

### Configuration Recommendations
- **External Communication**: Disable external meetings and chat
- **Domain Restrictions**: Limit external communication to specified domains
- **Privacy Mode**: Enable Privacy mode for user presence
- **Guest User Restrictions**: Implement strict guest user policies
- **External Access Policies**: Configure external access controls

## MISP Event Details

### Event Information
- **Event ID**: Microsoft_Teams_Threats_Campaign
- **Date**: 2025-10-07
- **Threat Level**: High (1)
- **Published**: False
- **Attribute Count**: 20

### Key Attributes
- **Attack Tools**: 8 reconnaissance and exploitation tools
- **Known Campaigns**: 4 malware families and campaigns
- **Target Sectors**: 8 primary target sectors
- **Malware Families**: 3 malware families
- **Tools**: 4 Microsoft tools and services

### Tags Applied
- **Threat Actor**: Multiple threat actors
- **Malware**: DarkGate, Atomic Stealer, VEILDrive
- **Tools**: Microsoft Teams, Microsoft Graph API, Microsoft Entra ID
- **MITRE ATT&CK**: 20+ technique mappings

## Conclusion

Microsoft Teams represents a critical attack surface that requires comprehensive security measures. The extensive collaboration features that make Teams valuable for organizations also make it attractive to threat actors.

Organizations must implement a multi-layered defense strategy that includes technical controls, administrative controls, monitoring and detection, and incident response preparedness to defend against Teams-specific threats.

---

**Report Date**: October 7, 2025  
**Threat Level**: High  
**Confidence Level**: High  
**Source**: [Microsoft Security Blog - Disrupting threats targeting Microsoft Teams](https://www.microsoft.com/en-us/security/blog/2025/10/07/disrupting-threats-targeting-microsoft-teams/)  
**Last Updated**: October 7, 2025

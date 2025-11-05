# Microsoft Teams Threats Campaign - MITRE ATT&CK Mapping

## Overview

This document provides a comprehensive mapping of Microsoft Teams threats to the MITRE ATT&CK framework. The analysis covers various attack techniques used by threat actors to abuse Teams' core capabilities including messaging, calls/meetings, and video-based screen sharing.

## Campaign Summary

- **Campaign Name**: Microsoft Teams Threats Campaign
- **Date**: October 7, 2025
- **Source**: [Microsoft Security Blog - Disrupting threats targeting Microsoft Teams](https://www.microsoft.com/en-us/security/blog/2025/10/07/disrupting-threats-targeting-microsoft-teams/)
- **Threat Level**: High
- **Target Platform**: Microsoft Teams

## MITRE ATT&CK Technique Mapping

### 1. Initial Access (TA0001)

#### T1566.001 - Spearphishing Attachment
- **Description**: Attackers use malicious file attachments in Teams chats
- **Implementation**: Malicious documents, executables, or scripts shared via Teams
- **Detection**: Monitor for suspicious file uploads to Teams
- **Mitigation**: File scanning, user training, application control

#### T1566.003 - Spearphishing via Service
- **Description**: Phishing attacks conducted through Teams messaging
- **Implementation**: One-on-one phishing chats, impersonation attacks
- **Detection**: Monitor external thread communications, impersonation patterns
- **Mitigation**: External communication controls, user education

#### T1189 - Drive-by Compromise
- **Description**: Malicious content delivered through Teams links
- **Implementation**: Malicious URLs shared in Teams chats
- **Detection**: Monitor for suspicious URLs in Teams communications
- **Mitigation**: URL filtering, user training

#### T1078.004 - Valid Accounts: Cloud Accounts
- **Description**: Abuse of legitimate Teams accounts for access
- **Implementation**: Compromised user accounts, guest user abuse
- **Detection**: Monitor for unusual account activity
- **Mitigation**: Account monitoring, access controls

### 2. Execution (TA0002)

#### T1059.001 - Command and Scripting Interpreter: PowerShell
- **Description**: PowerShell execution through Teams-delivered payloads
- **Implementation**: Malicious PowerShell scripts shared via Teams
- **Detection**: Monitor PowerShell execution from Teams-related processes
- **Mitigation**: PowerShell logging, execution policy restrictions

#### T1059.003 - Command and Scripting Interpreter: Windows Command Shell
- **Description**: Command shell execution through Teams
- **Implementation**: Malicious batch files or command scripts
- **Detection**: Monitor command execution from Teams processes
- **Mitigation**: Command monitoring, application control

#### T1204.002 - User Execution: Malicious File
- **Description**: User execution of malicious files delivered via Teams
- **Implementation**: Executable files shared through Teams chats
- **Detection**: Monitor file execution from Teams downloads
- **Mitigation**: File scanning, user training

### 3. Persistence (TA0003)

#### T1078.004 - Valid Accounts: Cloud Accounts
- **Description**: Maintaining access through compromised Teams accounts
- **Implementation**: Persistent access via guest or external user accounts
- **Detection**: Monitor for persistent account access
- **Mitigation**: Account monitoring, access controls

#### T1505.003 - Server Software Component: Web Shell
- **Description**: Web shell deployment through Teams file sharing
- **Implementation**: Malicious files stored in Teams chat files
- **Detection**: Monitor for web shell uploads to Teams
- **Mitigation**: File scanning, web shell detection

#### T1543.003 - Create/Modify System Process: Windows Service
- **Description**: Service creation for persistence
- **Implementation**: Malicious services installed via Teams-delivered payloads
- **Detection**: Monitor for new service creation
- **Mitigation**: Service monitoring, application control

### 4. Privilege Escalation (TA0004)

#### T1078.004 - Valid Accounts: Cloud Accounts
- **Description**: Privilege escalation through account compromise
- **Implementation**: Escalation via compromised administrative accounts
- **Detection**: Monitor for privilege escalation attempts
- **Mitigation**: Privilege monitoring, access controls

#### T1068 - Exploitation for Privilege Escalation
- **Description**: Exploitation of vulnerabilities for privilege escalation
- **Implementation**: Exploitation of Teams or related system vulnerabilities
- **Detection**: Monitor for privilege escalation attempts
- **Mitigation**: Regular patching, privilege monitoring

### 5. Defense Evasion (TA0005)

#### T1078.004 - Valid Accounts: Cloud Accounts
- **Description**: Using legitimate accounts to evade detection
- **Implementation**: Abuse of legitimate Teams accounts
- **Detection**: Monitor for unusual account activity
- **Mitigation**: Account monitoring, behavioral analysis

#### T1562.001 - Impair Defenses: Disable or Modify Tools
- **Description**: Disabling security tools and logging
- **Implementation**: Disabling Teams security features
- **Detection**: Monitor for security tool modifications
- **Mitigation**: Security tool protection, monitoring

#### T1027 - Obfuscated Files or Information
- **Description**: File obfuscation to evade detection
- **Implementation**: Obfuscated malicious files shared via Teams
- **Detection**: Monitor for obfuscated files in Teams
- **Mitigation**: File analysis, behavioral detection

### 6. Credential Access (TA0006)

#### T1555 - Credentials from Password Stores
- **Description**: Credential extraction from password stores
- **Implementation**: Credential theft through Teams-based attacks
- **Detection**: Monitor for credential access attempts
- **Mitigation**: Credential protection, monitoring

#### T1056.001 - Input Capture: Keylogging
- **Description**: Keylogging for credential capture
- **Implementation**: Keyloggers delivered via Teams
- **Detection**: Monitor for keylogging activities
- **Mitigation**: Input monitoring, user training

#### T1552.001 - Unsecured Credentials: Credentials In Files
- **Description**: Credential extraction from files
- **Implementation**: Credential files shared via Teams
- **Detection**: Monitor for credential file access
- **Mitigation**: File monitoring, credential protection

### 7. Discovery (TA0007)

#### T1087.004 - Account Discovery: Cloud Account
- **Description**: Discovery of cloud accounts through Teams
- **Implementation**: Teams enumeration for account discovery
- **Detection**: Monitor for account enumeration activities
- **Mitigation**: Account monitoring, access controls

#### T1018 - Remote System Discovery
- **Description**: Discovery of remote systems
- **Implementation**: Network discovery through Teams
- **Detection**: Monitor for network discovery activities
- **Mitigation**: Network monitoring, access controls

#### T1046 - Network Service Scanning
- **Description**: Network service scanning
- **Implementation**: Network scanning through Teams infrastructure
- **Detection**: Monitor for network scanning activities
- **Mitigation**: Network monitoring, segmentation

### 8. Lateral Movement (TA0008)

#### T1078.004 - Valid Accounts: Cloud Accounts
- **Description**: Lateral movement using cloud accounts
- **Implementation**: Movement through Teams accounts
- **Detection**: Monitor for lateral movement activities
- **Mitigation**: Account monitoring, access controls

#### T1210 - Exploitation of Remote Services
- **Description**: Exploitation of remote services for lateral movement
- **Implementation**: Exploitation of Teams-related services
- **Detection**: Monitor for remote service exploitation
- **Mitigation**: Service hardening, monitoring

### 9. Collection (TA0009)

#### T1005 - Data from Local System
- **Description**: Collection of local system data
- **Implementation**: Data collection through Teams
- **Detection**: Monitor for data collection activities
- **Mitigation**: Data loss prevention, monitoring

#### T1113 - Screen Capture
- **Description**: Screen capture for intelligence gathering
- **Implementation**: Screen sharing abuse in Teams
- **Detection**: Monitor for screen capture activities
- **Mitigation**: Screen sharing controls, monitoring

#### T1114.003 - Email Collection: Email Forwarding Rules
- **Description**: Email collection through forwarding rules
- **Implementation**: Email collection via Teams integration
- **Detection**: Monitor for email forwarding activities
- **Mitigation**: Email monitoring, access controls

### 10. Command and Control (TA0011)

#### T1071.001 - Application Layer Protocol: Web Protocols
- **Description**: C2 communication over web protocols
- **Implementation**: C2 communication through Teams
- **Detection**: Monitor for C2 communication patterns
- **Mitigation**: Network monitoring, C2 detection

#### T1071.004 - Application Layer Protocol: DNS
- **Description**: DNS-based C2 communication
- **Implementation**: DNS tunneling through Teams
- **Detection**: Monitor for DNS-based C2
- **Mitigation**: DNS monitoring, filtering

#### T1102.003 - Web Service: OneDrive
- **Description**: C2 communication via OneDrive
- **Implementation**: OneDrive integration abuse for C2
- **Detection**: Monitor for OneDrive C2 activities
- **Mitigation**: OneDrive monitoring, access controls

### 11. Exfiltration (TA0010)

#### T1041 - Exfiltration Over C2 Channel
- **Description**: Data exfiltration over C2 channels
- **Implementation**: Data theft through Teams C2
- **Detection**: Monitor for data exfiltration activities
- **Mitigation**: Data loss prevention, network monitoring

#### T1567.002 - Exfiltration Over Web Service: To Cloud Storage
- **Description**: Data exfiltration to cloud storage
- **Implementation**: Data theft via Teams cloud storage
- **Detection**: Monitor for cloud storage exfiltration
- **Mitigation**: Cloud access controls, monitoring

#### T1048.003 - Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol
- **Description**: Data exfiltration over unencrypted protocols
- **Implementation**: Data theft through Teams unencrypted channels
- **Detection**: Monitor for unencrypted data exfiltration
- **Mitigation**: Encryption monitoring, data loss prevention

## Detection Strategies

### Microsoft Defender XDR Queries

#### Teams External Communication Detection
```kql
MessageEvents
| where Timestamp > ago(5d)
| where IsExternalThread == true
| where (RecipientDetails contains "help" and RecipientDetails contains "desk")
    or (RecipientDetails contains "it" and RecipientDetails contains "support")
    or (RecipientDetails contains "working" and RecipientDetails contains "home")
| project Timestamp, SenderDisplayName, SenderEmailAddress, RecipientDetails, IsOwnedThread, ThreadType
```

#### Suspicious File Upload Detection
```kql
let portableExecutable = pack_array("binary.exe", "portable.exe");
let timeAgo = ago(30d);
MessageEvents
| where Timestamp > timeAgo
| where IsExternalThread == true
| where (RecipientDetails contains "help" and RecipientDetails contains "desk")
    or (RecipientDetails contains "it" and RecipientDetails contains "support")
| summarize spamEvent = min(Timestamp) by SenderEmailAddress
| join kind=inner (
    DeviceProcessEvents
    | where Timestamp > timeAgo
    | where FileName in (portableExecutable)
) on $left.SenderEmailAddress == $right.InitiatingProcessAccountUpn
| where spamEvent < Timestamp
```

### Microsoft Sentinel Queries

#### Teams Phishing Activity Detection
```kql
let suspiciousUpns = DeviceProcessEvents
    | where DeviceId == "alertedMachine"
    | where isnotempty(InitiatingProcessAccountUpn)
    | project InitiatingProcessAccountUpn;
CloudAppEvents
| where Application == "Microsoft Teams"
| where ActionType == "ChatCreated"
| where isempty(AccountObjectId)
| where RawEventData.ParticipantInfo.HasForeignTenantUsers == true
| where RawEventData.CommunicationType == "OneonOne"
| where RawEventData.Members[0].DisplayName in ("Microsoft Security", "Help Desk", "Help Desk Team", "Help Desk IT", "Microsoft Security", "office")
| where AccountId has "@"
| extend TargetUPN = tolower(tostring(RawEventData.Members[1].UPN))
| where TargetUPN in (suspiciousUpns)
```

#### File Upload and Access Tracking
```kql
OfficeActivity
| where RecordType =~ "SharePointFileOperation"
| where Operation =~ "FileUploaded"
| where UserId != "app@sharepoint"
| where SourceRelativeUrl has "Microsoft Teams Chat Files"
| join kind= leftouter (
    OfficeActivity
    | where RecordType =~ "SharePointFileOperation"
    | where Operation =~ "FileDownloaded" or Operation =~ "FileAccessed"
    | where UserId != "app@sharepoint"
    | where SourceRelativeUrl has "Microsoft Teams Chat Files"
) on OfficeObjectId
| extend userBag = bag_pack(UserId1, ClientIP1)
| summarize make_set(UserId1, 10000), make_bag(userBag, 10000) by TimeGenerated, UserId, OfficeObjectId, SourceFileName
| extend NumberUsers = array_length(bag_keys(bag_userBag))
| project timestamp=TimeGenerated, UserId, FileLocation=OfficeObjectId, FileName=SourceFileName, AccessedBy=bag_userBag, NumberOfUsersAccessed=NumberUsers
```

## Mitigation Strategies

### Technical Controls
- **Microsoft Entra ID Protection**: Identity threat detection
- **Microsoft Defender for Cloud Apps**: Cloud application security
- **Microsoft Defender for Office 365**: Email and collaboration security
- **Microsoft Defender for Endpoint**: Endpoint detection and response
- **Microsoft Defender for Identity**: Identity threat detection

### Administrative Controls
- **User Education**: Teams security training
- **Policy Implementation**: Guest user and external communication policies
- **Access Controls**: Strict access management
- **Monitoring**: Continuous security monitoring

### Configuration Recommendations
- **External Communication**: Disable external meetings and chat
- **Domain Restrictions**: Limit external communication to specified domains
- **Privacy Mode**: Enable Privacy mode for user presence
- **Guest User Restrictions**: Implement strict guest user policies
- **External Access Policies**: Configure external access controls

## Key Takeaways

1. **Teams as Attack Vector**: Microsoft Teams represents a high-value target for threat actors
2. **External Communication Risk**: External users and guest accounts pose significant security risks
3. **File Sharing Vulnerabilities**: Teams file sharing capabilities can be exploited for malware delivery
4. **Impersonation Threats**: Social engineering through Teams impersonation is highly effective
5. **Reconnaissance Opportunities**: Teams environments provide rich reconnaissance opportunities

## References

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Microsoft Security Blog - Disrupting threats targeting Microsoft Teams](https://www.microsoft.com/en-us/security/blog/2025/10/07/disrupting-threats-targeting-microsoft-teams/)
- [Microsoft Teams Security Guide](https://docs.microsoft.com/en-us/microsoftteams/teams-security-guide)
- [Microsoft Defender for Cloud Apps](https://docs.microsoft.com/en-us/defender-cloud-apps/)
- [Microsoft Entra ID Protection](https://docs.microsoft.com/en-us/azure/active-directory/identity-protection/)

---

**Analysis Date**: October 7, 2025  
**Threat Level**: High  
**Confidence Level**: High  
**Last Updated**: October 7, 2025

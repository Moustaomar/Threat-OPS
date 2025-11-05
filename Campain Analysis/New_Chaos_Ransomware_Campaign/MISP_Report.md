# MISP Report - New Chaos Ransomware Campaign

## Executive Summary

This MISP report documents the New Chaos Ransomware Campaign, a Ransomware-as-a-Service (RaaS) operation targeting organizations globally. The campaign involves sophisticated ransomware deployment with data encryption capabilities and ransom demands, representing a significant threat to organizations across various sectors.

## Campaign Overview

- **Campaign Name**: New Chaos Ransomware Campaign
- **Threat Actor**: New Chaos Ransomware Group
- **Type**: Ransomware-as-a-Service (RaaS)
- **Target**: Organizations globally
- **Threat Level**: High
- **Date**: July 24, 2025

## Threat Intelligence Summary

### Primary Attack Vector
- **Delivery Method**: Multiple attack vectors including phishing, exploit kits, and RDP attacks
- **Payload**: Chaos ransomware samples with encryption capabilities
- **Objective**: Data encryption and ransom demands
- **Infrastructure**: Command and control servers for ransomware operations

### Key Indicators of Compromise (IOCs)

#### Command and Control Infrastructure
- **144.172.103.42** - Primary C2 server
- **45.61.134.36** - Secondary C2 server  
- **107.170.35.225** - Additional C2 server

#### Ransomware Samples
- **SHA256**: 7c4b465159e1c7dbbe67f0eeb3f58de1caba293999a49843a0818480f05be14e
- **SHA256**: 11cfea4100ba3731d859148d2011c7225d337db22797f7e111c0f2876e986490
- **SHA256**: 1d846592ffcc19ed03a34316520aa31369218a88afa4e17ac547686d0348aa5b

## Technical Analysis

### Infection Chain
1. **Initial Access**: Phishing, exploit kits, or RDP attacks
2. **Lateral Movement**: Network reconnaissance and privilege escalation
3. **Ransomware Deployment**: Execution of Chaos ransomware samples
4. **Data Encryption**: Encryption of user and system files
5. **Ransom Demand**: Creation of ransom notes and communication with victims
6. **C2 Communication**: Communication with command and control servers

### Ransomware Capabilities
- **File Encryption**: Encryption of various file types
- **System Modification**: Disabling system recovery options
- **Backup Deletion**: Removal of system backups
- **Ransom Notes**: Creation of ransom demand files
- **C2 Communication**: Communication with command servers

### Attack Techniques
- **Data Encryption**: T1486 - Data Encrypted for Impact
- **System Recovery Inhibition**: T1490 - Inhibit System Recovery
- **Data Destruction**: T1485 - Data Destruction
- **Credential Access**: T1003 - OS Credential Dumping
- **System Discovery**: T1082 - System Information Discovery

## MITRE ATT&CK Mapping

### Initial Access
- **T1566.001**: Spearphishing Attachment
- **T1190**: Exploit Public-Facing Application
- **T1078.001**: Valid Accounts: Default Accounts
- **T1078.002**: Valid Accounts: Domain Accounts

### Execution
- **T1059.001**: Command and Scripting Interpreter: PowerShell
- **T1059.003**: Command and Scripting Interpreter: Windows Command Shell
- **T1204.002**: User Execution: Malicious File

### Persistence
- **T1053.005**: Scheduled Task/Job: Scheduled Task
- **T1543.003**: Create or Modify System Process: Windows Service

### Defense Evasion
- **T1027**: Obfuscated Files or Information
- **T1562.001**: Impair Defenses: Disable or Modify Tools
- **T1490**: Inhibit System Recovery

### Credential Access
- **T1003.001**: OS Credential Dumping: LSASS Memory
- **T1555.003**: Credentials from Password Stores: Credentials from Web Browsers

### Discovery
- **T1083**: File and Directory Discovery
- **T1018**: Remote System Discovery
- **T1082**: System Information Discovery

### Collection
- **T1005**: Data from Local System
- **T1119**: Automated Collection

### Command and Control
- **T1071.001**: Application Layer Protocol: Web Protocols
- **T1102**: Web Service
- **T1104**: Multi-Stage Channels

### Impact
- **T1486**: Data Encrypted for Impact
- **T1490**: Inhibit System Recovery
- **T1485**: Data Destruction

## Detection Recommendations

### Network-Based Detection
- Monitor for connections to identified C2 servers
- Track ransomware communication patterns
- Detect file encryption network traffic
- Monitor for ransom note creation

### Endpoint Detection
- Monitor for rapid file encryption activities
- Track system recovery disabling attempts
- Detect backup deletion activities
- Monitor for ransom note file creation

### Behavioral Detection
- Detect rapid encryption of multiple files
- Monitor system recovery feature disabling
- Track backup deletion activities
- Detect ransom note creation patterns

## Mitigation Strategies

### Technical Controls
- **Endpoint Protection**: Advanced endpoint detection and response
- **Network Monitoring**: Network traffic analysis and monitoring
- **Backup Systems**: Regular and secure backup procedures
- **Patch Management**: Timely application of security patches

### Administrative Controls
- **User Training**: Security awareness training
- **Access Controls**: Principle of least privilege
- **Incident Response**: Comprehensive incident response procedures
- **Backup Procedures**: Regular backup and recovery testing

### Monitoring and Detection
- **Threat Hunting**: Proactive hunting for ransomware activities
- **IOC Monitoring**: Tracking known threat indicators
- **Behavioral Analytics**: Advanced behavioral analysis
- **Network Monitoring**: Comprehensive network monitoring

## MISP Event Details

### Event Information
- **Event ID**: New_Chaos_Ransomware_Campaign
- **Date**: 2025-07-24
- **Threat Level**: High (1)
- **Published**: False
- **Attribute Count**: 6

### Key Attributes
- **C2 Servers**: 3 IP addresses for command and control infrastructure
- **Ransomware Samples**: 3 SHA256 hashes of Chaos ransomware samples
- **Network Activity**: C2 communication indicators
- **Payload Delivery**: Ransomware sample indicators

### Tags Applied
- **Malware**: Chaos Ransomware, Ransomware
- **Tools**: Ransomware-as-a-Service
- **MITRE ATT&CK**: 15+ technique mappings
- **Threat Level**: High

## Conclusion

The New Chaos Ransomware Campaign represents a significant threat to organizations globally through its Ransomware-as-a-Service model. The campaign's sophisticated encryption capabilities, system recovery inhibition, and C2 infrastructure demonstrate the evolving nature of ransomware threats.

Organizations should implement comprehensive security measures including advanced endpoint protection, network monitoring, regular backups, and user training to defend against similar campaigns.

---

**Report Date**: July 24, 2025  
**Threat Level**: High  
**Confidence Level**: High  
**Source**: [Cisco Talos Intelligence - New Chaos Ransomware](https://blog.talosintelligence.com/new-chaos-ransomware/)  
**Last Updated**: July 24, 2025

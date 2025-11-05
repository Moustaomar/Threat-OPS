# MISP Report - Volexity GOVERSHELL Campaign

## Executive Summary

This MISP report documents the Volexity GOVERSHELL Campaign, a sophisticated backdoor malware operation targeting government and corporate organizations worldwide. The campaign leverages advanced WebSocket-based command and control infrastructure, multi-layered persistence mechanisms, and sophisticated phishing techniques to establish long-term access to compromised systems.

## Campaign Overview

- **Campaign Name**: Volexity GOVERSHELL Campaign
- **Threat Type**: Backdoor Malware Campaign
- **Target**: Government and corporate organizations
- **Primary Vector**: Phishing emails with malicious attachments
- **Threat Level**: Medium
- **Date**: October 13, 2025

## Threat Intelligence Summary

### Primary Attack Vector
- **Delivery Method**: Phishing emails with malicious attachments
- **Payload**: GOVERSHELL backdoor malware
- **C2 Communication**: WebSocket-based command and control
- **Target**: Government and corporate organizations worldwide

### Key Indicators of Compromise (IOCs)

#### C2 Infrastructure (10 IP addresses)
- **104.194.152.137** - Primary C2 infrastructure
- **104.194.152.152** - Secondary C2 infrastructure
- **185.144.28.68** - Regional C2 infrastructure
- **31.192.234.22** - Additional C2 infrastructure
- **45.141.139.222** - Backup C2 infrastructure
- **74.119.193.175** - Regional C2 infrastructure
- **80.85.156.234** - Primary C2 infrastructure
- **80.85.154.48** - Secondary C2 infrastructure
- **80.85.157.117** - Additional C2 infrastructure
- **82.118.16.173** - Regional C2 infrastructure

#### C2 Domains (6 domains)
- **azure-app.store** - Azure-based C2 domain
- **twmoc.info** - Primary C2 domain
- **windows-app.store** - Windows-based C2 domain
- **cdn-apple.info** - Apple-themed C2 domain
- **sliddeshare.online** - SlideShare-themed C2 domain
- **doccloude.info** - Document cloud-themed C2 domain

#### WebSocket C2 URLs (5 URLs)
- **wss://api.twmoc.info/ws** - Primary WebSocket C2
- **wss://onedrive.azure-app.store/ws** - Azure OneDrive-themed WebSocket
- **wss://outlook.windows-app.store/ws** - Outlook-themed WebSocket
- **www.twmoc.info** - HTTP C2 endpoint
- **https://app-site-association.cdn-apple.info:443/updates.rss** - Apple-themed C2 endpoint

#### GOVERSHELL Malware Samples (11 SHA-256 hashes)
- **2ffe1e4f4df34e1aca3b8a8e93eee34bfc4b7876cedd1a0b6ca5d63d89a26301**
- **4c041c7c0d5216422d5d22164f83762be1e70f39fb8a791d758a816cdf3779a9**
- **53af82811514992241e232e5c04e5258e506f9bc2361b5a5b718b4e4b5690040**
- **88782d26f05d82acd084861d6a4b9397d5738e951c722ec5afed8d0f6b07f95e**
- **998e314a8babf6db11145687be18dc3b8652a3dd4b36c115778b7ca5f240aae4**
- **a5ee55a78d420dbba6dec0b87ffd7ad6252628fd4130ed4b1531ede960706d2d**
- **ad5718f6810714bc6527cc86d71d34d8c556fe48706d18b5d14f0261eb27d942**
- **fbade9d8a040ed643b68e25e19cba9562d2bd3c51d38693fe4be72e01da39861**
- **7d7d75e4d524e32fc471ef2d36fd6f7972c05674a9f2bac909a07dfd3e19dd18**
- **0414217624404930137ec8f6a26aebd8a3605fe089dbfb9f5aaaa37a9e2bad2e**
- **126c3d21a1dae94df2b7a7d0b2f0213eeeec3557c21717e02ffaed690c4b1dbd**

#### Phishing Infrastructure URLs (23 URLs)

##### OneDrive Phishing URLs (4 URLs)
- **https://1drv.ms/u/c/F703BC98FAB44D61/ER_XG5FDkURHtsmna8vOQrIBRODKiQBKYJVKnI-kGKwX0A**
- **https://1drv.ms/u/c/F703BC98FAB44D61/ESz4UV9JeOhOp8kiWd0Ie10ByH7eUdSRlBy2NCiNeo2LYw**
- **https://1drv.ms/u/c/f9e3b332ce488781/Eap6_fxYFP5Eh1ZKDZaf8lMBjJNcfdba4MVcr4YfKj674w?e=fgNIj4**
- **https://1drv.ms/u/c/F703BC98FAB44D61/ERpeLpJlb7FAkbfyuffpFJYBZ-8u2MmQH6LW5xH86B4M8w**

##### Netlify Phishing Infrastructure (18 URLs)
- **https://aesthetic-donut-1af43s2.netlify.app/file/rar**
- **https://aesthetic-donut-1af43s2.netlify.app/file/zip**
- **https://animated-dango-0fa8c8.netlify.app/file/Taiwan%20Intro.zip**
- **https://aquamarine-choux-46cb43.netlify.app/file/rar**
- **https://aquamarine-choux-46cb43.netlify.app/file/zip**
- **https://aquamarine-choux-46cb43.netlify.app/index/file/[PDF]202507_Please_check_the_document.zip**
- **https://dainty-licorice-db2b1e.netlify.app/file/zip**
- **https://dulcet-mooncake-36558c.netlify.app/file/zip**
- **https://harmonious-malabi-a8ebfa.netlify.app/file/Taiwan%20Intro.rar**
- **https://hllowrodcanlhelipme.netlify.app/file/zip**
- **https://jazzy-biscotti-68241f.netlify.app/files/Intro-Doc.rar**
- **https://loveusa.netlify.app/file/rar**
- **https://pulicwordfiledownlos.netlify.app/file/rar**
- **https://spontaneous-selkie-d3346f.netlify.app/file/zip**
- **https://statuesque-unicorn-09420f.netlify.app/r**
- **https://subtle-klepon-d73b9b.netlify.app/file/rar**
- **https://subtle-klepon-d73b9b.netlify.app/file/zip**
- **https://vocal-crostata-86ebbf.netlify.app/files/zip**

##### Sync.com Phishing URL (1 URL)
- **https://ln5.sync.com/4.0/dl/100016f90#3d5wrb4z-hfb4iz3m-qmjzsqnq-39rn3vjv**

### Campaign Characteristics
- **Total IOCs**: 58 (10 IPs + 6 domains + 5 C2 URLs + 11 malware samples + 23 phishing URLs)
- **Geographic Scope**: Global targeting
- **Target Focus**: Government and corporate organizations
- **Attack Sophistication**: High
- **Persistence**: Long-term access capabilities

## Technical Analysis

### GOVERSHELL Backdoor Capabilities
The campaign utilizes sophisticated backdoor malware with advanced capabilities:

#### Core Functionality
- **Remote Access**: Full remote control of compromised systems
- **Command Execution**: Execution of arbitrary commands
- **File Operations**: File upload, download, and manipulation
- **Process Management**: Process creation, termination, and monitoring
- **Registry Operations**: Registry key creation, modification, and deletion
- **Service Management**: Windows service creation and management

#### Communication Protocols
- **WebSocket**: Real-time bidirectional communication
- **HTTP/HTTPS**: Standard web protocols for C2 communication
- **Custom Protocols**: Proprietary communication protocols
- **Encryption**: Encrypted communication channels

#### Persistence Mechanisms
- **Windows Services**: Service-based persistence
- **Scheduled Tasks**: Task-based persistence
- **Registry Run Keys**: Registry-based persistence
- **Startup Folders**: Folder-based persistence
- **DLL Hijacking**: DLL-based persistence

### C2 Infrastructure Analysis
The campaign employs a sophisticated multi-layered C2 infrastructure:

#### Infrastructure Components
- **Multiple IP Addresses**: 10 C2 IP addresses for resilience
- **Domain Infrastructure**: 6 C2 domains for redundancy
- **WebSocket Communication**: Real-time bidirectional communication
- **Protocol Diversity**: Multiple communication protocols
- **Geographic Distribution**: Global C2 infrastructure

#### Communication Methods
- **WebSocket**: Primary communication method
- **HTTP/HTTPS**: Standard web protocols
- **Custom Protocols**: Proprietary communication methods
- **Encrypted Channels**: Encrypted communication channels

### Phishing Infrastructure Analysis
The campaign extensively uses legitimate cloud services for payload delivery:

#### Cloud Service Abuse
- **OneDrive**: Microsoft OneDrive for file sharing
- **Netlify**: Netlify hosting for malicious file distribution
- **Sync.com**: Sync.com for file sharing
- **Cloud Services**: Abuse of various cloud services

#### Phishing Techniques
- **File Name Obfuscation**: Misleading file names and extensions
- **Cloud Service Abuse**: Use of legitimate cloud services
- **Domain Spoofing**: Sophisticated domain impersonation
- **Protocol Mimicking**: Mimicking legitimate protocols

## MITRE ATT&CK Mapping

### Initial Access
- **T1566.001**: Spearphishing Attachment
- **T1566.002**: Spearphishing Link
- **T1078.004**: Valid Accounts: Cloud Accounts

### Execution
- **T1059**: Command and Scripting Interpreter
- **T1059.001**: PowerShell
- **T1059.007**: JavaScript
- **T1204.002**: User Execution: Malicious File

### Persistence
- **T1543.003**: Create or Modify System Process: Windows Service
- **T1053.005**: Scheduled Task/Job: Scheduled Task
- **T1547.001**: Boot or Logon Autostart Execution: Registry Run Keys

### Command and Control
- **T1071**: Application Layer Protocol
- **T1071.001**: Web Protocols
- **T1102**: Web Service
- **T1102.001**: Dead Drop Resolver
- **T1102.002**: Bidirectional Communication
- **T1102.003**: OneDrive
- **T1104**: Multi-Stage Channels
- **T1219**: Remote Access Software

### Exfiltration
- **T1041**: Exfiltration Over C2 Channel
- **T1041.001**: HTTP Exfiltration
- **T1567**: Exfiltration Over Web Service
- **T1567.001**: Webmail Exfiltration
- **T1567.002**: Cloud Storage Exfiltration
- **T1048**: Exfiltration Over Alternative Protocol

## Detection Recommendations

### Network-Based Detection
- Monitor for connections to identified C2 infrastructure
- Detect WebSocket traffic to suspicious domains
- Monitor for unusual network communication patterns
- Track data exfiltration activities

### Endpoint Detection
- Monitor for backdoor installation and execution
- Detect process injection activities
- Track credential harvesting activities
- Monitor for data collection and exfiltration

### Behavioral Detection
- Detect backdoor behavioral patterns
- Monitor for credential dumping activities
- Track data collection and exfiltration
- Detect system abuse and lateral movement

## Mitigation Strategies

### Technical Controls
- **Email Security**: Advanced email filtering for malicious attachments
- **Web Security**: Web filtering and content inspection
- **Endpoint Protection**: EDR solutions with behavioral analysis
- **Network Security**: Firewall rules and network segmentation

### Administrative Controls
- **User Training**: Security awareness for phishing attacks
- **Access Controls**: Principle of least privilege
- **Network Segmentation**: Isolate critical systems
- **Incident Response**: Rapid response procedures

### Monitoring and Detection
- **SIEM Integration**: Centralized logging and monitoring
- **Threat Hunting**: Proactive threat hunting activities
- **IOC Monitoring**: Track known threat indicators
- **Behavioral Analytics**: Advanced behavioral analysis

## Impact Assessment

### Financial Impact
- **Data Theft**: Stealing sensitive corporate and government data
- **Intellectual Property Theft**: Theft of proprietary information
- **Financial Fraud**: Unauthorized financial transactions
- **Regulatory Fines**: Potential regulatory violations and penalties

### Operational Impact
- **System Compromise**: Complete control of compromised systems
- **Data Breach**: Large-scale data breaches
- **Business Disruption**: Operational disruption and downtime
- **Reputation Damage**: Loss of customer and partner trust

### Data Impact
- **Sensitive Information**: Personal and corporate data theft
- **Intellectual Property**: Proprietary information and trade secrets
- **Financial Data**: Banking and financial information
- **Government Data**: Classified and sensitive government information

## MISP Event Details

### Event Information
- **Event ID**: Volexity_GOVERSHELL_Campaign
- **Date**: 2025-10-13
- **Threat Level**: Medium (2)
- **Published**: False
- **Attribute Count**: 50

### Key Attributes
- **C2 Infrastructure**: 10 IP addresses for C2 communication
- **C2 Domains**: 6 domains for C2 infrastructure
- **WebSocket URLs**: 5 WebSocket C2 URLs
- **Malware Samples**: 11 GOVERSHELL SHA-256 hashes
- **Phishing URLs**: 23 phishing infrastructure URLs
- **Source URL**: 1 source URL for data attribution

### Tags Applied
- **Threat Type**: Backdoor, GOVERSHELL, Remote Access
- **Attack Vector**: Email, Web, Cloud Services
- **Target**: Government, Corporate, Critical Infrastructure
- **MITRE ATT&CK**: 20+ technique mappings

## Recommendations

### Immediate Actions
1. **Block C2 Infrastructure**: Block identified C2 IP addresses and domains
2. **Update Security Signatures**: Update email and web security signatures
3. **User Notification**: Notify users of phishing threats
4. **Incident Response**: Activate incident response procedures

### Long-term Measures
1. **Security Awareness**: Comprehensive user training programs
2. **Technical Controls**: Implement advanced security controls
3. **Monitoring**: Deploy comprehensive monitoring solutions
4. **Incident Response**: Develop and test incident response procedures

### Continuous Improvement
1. **Threat Intelligence**: Integrate threat intelligence feeds
2. **Security Testing**: Regular security assessments and testing
3. **Training Updates**: Continuous security awareness training
4. **Technology Updates**: Regular security technology updates

## Conclusion

The Volexity GOVERSHELL Campaign represents a significant and sophisticated threat to government and corporate organizations. The campaign's use of advanced WebSocket-based C2 infrastructure, multi-layered persistence mechanisms, and sophisticated phishing techniques demonstrates the advanced capabilities of modern cybercriminals.

### Key Takeaways
- **High Sophistication**: Advanced backdoor capabilities and C2 infrastructure
- **Multi-Vector Approach**: Email, web, and cloud service abuse
- **Persistent Threat**: Long-term access to compromised systems
- **Global Targeting**: Worldwide targeting of high-value organizations
- **Advanced Techniques**: WebSocket communication and cloud service abuse

### Final Recommendations
Organizations must implement comprehensive security measures including advanced email protection, web filtering, user training, and continuous monitoring to defend against sophisticated backdoor campaigns. The integration of threat intelligence, behavioral analytics, and rapid incident response capabilities is essential for effective defense.

---
**Report Date**: October 13, 2025  
**Threat Level**: Medium  
**Confidence Level**: High  
**Source**: [Volexity Threat Intelligence](https://github.com/volexity/threat-intel)  
**Last Updated**: October 13, 2025

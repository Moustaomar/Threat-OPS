# NXSMS/OPERA1ER/Common Raven Threat Actor Profile

## Executive Summary

**Threat Actor:** NXSMS/OPERA1ER/Common Raven  
**Aliases:** Common Raven, OPERA1ER, NXSMS  
**Threat Level:** HIGH  
**Geographic Focus:** West Africa (Senegal, Ivory Coast, Mali, Burkina Faso)  
**Primary Targets:** Financial Institutions, Government Entities, Healthcare Organizations  
**Motivation:** Financial Gain, Espionage  
**First Observed:** 2018  
**Active Status:** ACTIVE  

## Overview

NXSMS/OPERA1ER/Common Raven is a sophisticated Advanced Persistent Threat (APT) group that has been actively targeting financial institutions and government entities across West Africa since 2018. The group demonstrates advanced capabilities in social engineering, malware development, and infrastructure management, with a particular focus on banking and financial services organizations.

## Attribution & Background

### Geographic Origin
- **Primary Region:** West Africa
- **Target Countries:** Senegal, Ivory Coast, Mali, Burkina Faso, Ghana
- **Infrastructure:** Distributed across multiple countries including Seychelles, China, and various European locations

### Motivations
- **Primary:** Financial gain through banking fraud and theft
- **Secondary:** Corporate espionage and data exfiltration
- **Tertiary:** Political intelligence gathering

## Tactics, Techniques, and Procedures (TTPs)

### MITRE ATT&CK Framework Mapping

#### Initial Access (TA0001)
- **T1566 - Phishing**
  - Spearphishing Link (T1566.002)
  - Spearphishing Attachment (T1566.001)
- **T1204 - User Execution**
  - Malicious File (T1204.002)

#### Execution (TA0002)
- **T1059 - Command and Scripting Interpreter**
  - PowerShell (T1059.001) - Primary execution method
  - Windows Command Shell (T1059.003)
- **T1569 - System Services**
  - Service Execution (T1569.002)
- **T1053 - Scheduled Task/Job**
  - Scheduled Task (T1053.005)
- **T1047 - Windows Management Instrumentation**

#### Persistence (TA0003)
- **T1547 - Boot or Logon Autostart Execution**
  - Registry Run Keys (T1547.001)
  - Login Items (T1547.015)
- **T1037 - Boot or Logon Initialization Scripts**
  - Startup Items (T1037.005)
- **T1543 - Create or Modify System Process**
  - Windows Service (T1543.003)
- **T1574 - Hijack Execution Flow**
  - Services File Permissions Weakness (T1574.010)
- **T1112 - Modify Registry**

#### Privilege Escalation (TA0004)
- **T1548 - Abuse Elevation Control Mechanism**
  - Bypass User Account Control (T1548.002)
- **T1134 - Access Token Manipulation**
- **T1055 - Process Injection**
  - Process Hollowing (T1055.012)
- **T1068 - Exploitation for Privilege Escalation**

#### Defense Evasion (TA0005)
- **T1070 - Indicator Removal**
  - File Deletion (T1070.004)
- **T1550 - Use Alternate Authentication Material**
  - Pass the Hash (T1550.002)

#### Credential Access (TA0006)
- **T1003 - OS Credential Dumping**
  - Cached Domain Credentials (T1003.005)

#### Discovery (TA0007)
- **T1087 - Account Discovery**
- **T1083 - File and Directory Discovery**
- **T1046 - Network Service Discovery**
- **T1057 - Process Discovery**
- **T1018 - Remote System Discovery**
- **T1082 - System Information Discovery**
- **T1016 - System Network Configuration Discovery**

#### Lateral Movement (TA0008)
- **T1021 - Remote Services**
  - SMB/Windows Admin Shares (T1021.002)
  - Windows Remote Management (T1021.006)

#### Collection (TA0009)
- **T1005 - Data from Local System**
- **T1039 - Data from Network Shared Drive**
- **T1113 - Screen Capture**

#### Command and Control (TA0011)
- **T1071 - Application Layer Protocol**
  - Web Protocols (T1071.001)
- **T1132 - Data Encoding**
  - Standard Encoding (T1132.001)
- **T1568 - Dynamic Resolution**
  - Fast Flux DNS (T1568.001)
- **T1573 - Encrypted Channel**
- **T1105 - Ingress Tool Transfer**

#### Exfiltration (TA0010)
- **T1029 - Scheduled Transfer**
- **T1041 - Exfiltration Over C2 Channel**

#### Impact (TA0040)
- **T1565 - Data Manipulation**
  - Runtime Data Manipulation (T1565.003)
  - Stored Data Manipulation (T1565.001)
  - Transmitted Data Manipulation (T1565.002)

## Infrastructure & Tools

### Command and Control Infrastructure
- **Primary C2:** Multiple IP addresses across different ASNs
- **Communication Protocols:** HTTP/HTTPS, DNS
- **Infrastructure Providers:** Various hosting providers in Seychelles, China, and Europe
- **Domain Generation:** Dynamic DNS services and compromised domains

### Malware Families
- **Custom Backdoors:** Multi-protocol backdoors supporting DNS and HTTP channels
- **Cobalt Strike:** Commercial penetration testing framework
- **PowerShell Scripts:** Custom PowerShell-based tools for reconnaissance and data collection

### Tools and Utilities
- **PyPyKatz:** Credential dumping tool
- **SharpHostInfo:** Reconnaissance tool
- **masscan:** Network scanning utility
- **SharpAdidnsdump:** Active Directory enumeration tool
- **PsExec:** Lateral movement tool

## Target Analysis

### Primary Targets
1. **Financial Institutions**
   - Commercial banks
   - Credit unions
   - Financial services companies
   - Payment processors

2. **Government Entities**
   - Ministries and departments
   - Regulatory agencies
   - Public sector organizations

3. **Healthcare Organizations**
   - Hospitals and medical centers
   - Healthcare providers
   - Medical research institutions

### Geographic Focus
- **West Africa:** Senegal, Ivory Coast, Mali, Burkina Faso, Ghana
- **Secondary:** Other African countries with financial infrastructure

## Indicators of Compromise (IOCs)

### Network Indicators
- **IP Addresses:** Multiple C2 servers across different ASNs
- **Domains:** Banking impersonation domains, dynamic DNS services
- **URLs:** C2 endpoints with specific path patterns

### File Indicators
- **Malware Hashes:** SHA256, MD5, SHA1 hashes for various malware components
- **Filenames:** Specific naming conventions for malware and tools

### Behavioral Indicators
- **PowerShell Execution:** Unusual PowerShell activity
- **Network Scanning:** Port scanning activities
- **Credential Dumping:** LSASS memory access
- **Lateral Movement:** SMB and RDP connections

## Detection Recommendations

### Network Monitoring
- Monitor for connections to known C2 infrastructure
- Detect unusual PowerShell network activity
- Watch for banking domain impersonation
- Monitor for credential dumping activities

### Endpoint Detection
- PowerShell execution monitoring
- Process injection detection
- Registry modification monitoring
- File system monitoring for persistence mechanisms

### Behavioral Analysis
- User behavior analytics for unusual access patterns
- Network traffic analysis for C2 communication
- File system monitoring for data exfiltration

## Mitigation Strategies

### Technical Controls
- Implement application whitelisting
- Deploy endpoint detection and response (EDR) solutions
- Use network segmentation
- Implement multi-factor authentication
- Regular security awareness training

### Operational Controls
- Incident response planning
- Regular security assessments
- Threat hunting activities
- Information sharing with industry peers

## Intelligence Gaps

### Current Limitations
- Limited attribution to specific individuals or organizations
- Incomplete understanding of full infrastructure
- Limited visibility into target selection criteria
- Unknown relationships with other threat actors

### Research Priorities
- Infrastructure analysis and mapping
- Malware analysis and reverse engineering
- Attribution research
- Target analysis and victimology

## References

1. Unit 42 Research: "NXSMS/OPERA1ER/Common Raven: Advanced Persistent Threat targeting financial institutions and government entities in West Africa"
2. MITRE ATT&CK Framework
3. Industry threat intelligence reports
4. Law enforcement and government agency reports

---

**Last Updated:** January 2025  
**Classification:** TLP:AMBER  
**Distribution:** Internal Use Only

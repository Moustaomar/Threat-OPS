# APT27 (Emissary Panda) MISP Threat Intelligence Report

## Executive Summary

**Threat Actor**: APT27 (Emissary Panda, Iron Tiger, LuckyMouse)  
**Threat Level**: High  
**TLP**: Amber  
**Report Date**: January 15, 2025  
**Source**: [DeXpose Threat Intelligence](https://www.dexpose.io/threat-actor-profile-apt27/)

APT27 is a Chinese state-sponsored cyber-espionage group that has been active since at least 2010. The group has been linked to long-running campaigns against governments, critical industries, and organizations worldwide, typically seeking political, economic, strategic intelligence and occasionally financial objectives.

## Threat Actor Profile

### Primary Information
- **Primary Name**: APT27
- **Common Aliases**: Emissary Panda, Iron Tiger, LuckyMouse, BRONZE UNION, Threat Group-3390
- **Country of Origin**: China
- **Activity Period**: 2010 - Present
- **Motivation**: State-sponsored cyber-espionage with dual focus on intelligence collection and financial gain

### Target Sectors
- Government entities
- Defense and aerospace
- Telecommunications
- Energy
- Manufacturing
- High-tech and IT
- Research and education
- Business services
- Travel and automotive
- Electronics
- Information technology
- **Healthcare** (expanded operations since 2021)

### Geographic Targeting
- North America
- Southeast Asia
- Western and Eastern Asia
- Middle East
- Europe
- South America

## Malware and Tools

### Custom Malware
- **HyperBro**: In-memory backdoor/RAT for persistent access, command execution, and data exfiltration
- **SysUpdate**: Modular backdoor supporting Windows and Linux, used for persistence, command execution, file/process management, screenshot capture, and C2 communications

### Shared Tools
- **PlugX (Korplug, Sogu)**: Modular RAT with command execution, screen capture, keylogging, file operations, and process/service management capabilities
- **ZxShell**: Classic China-nexus RAT
- **gh0st RAT**: Remote access tool used by China-nexus cyberespionage groups
- **HTTPBrowser**: Remote access trojan (RAT)
- **ASPXSpy**: ASP.NET webshell (APT27 uses modified "ASPXTool" variant)
- **China Chopper**: Lightweight webshell for foothold and post-exploitation
- **Windows Credential Editor (WCE)**: Credential-dumping utility
- **Mimikatz**: Post-exploitation tool for credential extraction

## Recent Campaign Activity

### Healthcare Sector Targeting (2021)
- **Targets**: German pharmaceutical and technology companies, U.S. healthcare organizations
- **Method**: Exploitation of Zoho ManageEngine ADSelfService Plus vulnerability (CVE-2021-40539)
- **Objective**: Stealing trade secrets and intellectual property
- **Impact**: Compromised organizations across healthcare, defense, higher education, consulting, and IT industries

### Law Enforcement Actions
- U.S. Department of Justice charges against 12 Chinese contract hackers and law enforcement officers
- Global cyber-espionage operations targeting multiple industries
- Focus on economic espionage and intellectual property theft

## Indicators of Compromise (IOCs)

### Command and Control Infrastructure
- **C2 Server**: 185.12.45.134:443/ajax
- **Protocol**: HTTPS
- **Purpose**: HyperBro malware C2 communication

### File Hashes (SHA256)

#### Malicious Documents (Spear-phishing)
- `4fce3d38e0a308088cd75c2ef1bb5aa312e83447d63a82f62839d3609a283b02`
- `3e04eb55095ad6a45905564d91f2ab6500e07afcdf9d6c710d6166d4eef28185`
- `4123a19cda491f4d31a855e932b8b7afdcf3faf5b448f892da624c768205a289`

#### HyperBro Malware
- `04f48ed27a83a57a971e73072ac5c769709306f2714022770fb364fd575fd462`
- `e74056a729e004031b78007708bb98d759ff94b46866898c5a05d87013cd643c`
- `52072a8f99dacd5c293fccd051eab95516d8b880cd2bc5a7e0f4a30d008e22a7`

#### Web Shells
- `2feae7574a2cc4dea2bff4eceb92e3a77cf682c0a1e78ee70be931a251794b86` (stylecs.aspx)
- `d1ab0dff44508bac9005e95299704a887b0ffc42734a34b30ebf6d3916053dbe` (stylecss.aspx)
- `6b3f835acbd954af168184f57c9d8e6798898e9ee650bd543ea6f2e9d5cf6378` (test.aspx)
- `006569f0a7e501e58fe15a4323eedc08f9865239131b28dc5f95f750b4767b38` (error2.aspx)
- `0e823a5b64ee761b70315548d484b5b9c4b61968b5068f9a8687c612ddbfeb80` (OwaAuth web shell)

#### SysUpdate Malware
- `b39e2cf333b9f854bcdf993aa6c1f357d2a7042139e4c6ca47ed504090006a61` (Windows)
- `6d9031eb617096439bc8c8f7c32f4a11ffefc4326d99229fc78722873092e400` (Linux)
- `d950cc937f4df9ab0bad44513d23ea7ecdfae2b0de8ba351018de5fb5d7b1382` (Windows DLL)
- `123880edc91f7dc033a769d9523f783f7b426673ee95e9e33654cdfa95a6462c` (Windows payload)

#### Other Malware
- `af31c16dcd54ee11d425eb3a579ad0606a05b36c0605cc16007f3d3c84d8e291` (Pandora rootkit)
- `07f87f7b3313acd772f77d35d11fc12d3eb7ca1a2cd7e5cef810f9fb657694a0` (Trojanized Able Desktop)
- `c2dc17bdf16a609cdb5a93bf153011d67c6206f7608931b1ca1c1d316b5ad54f` (Korplug/PlugX)

### Filenames
- `stylecs.aspx`
- `stylecss.aspx`
- `test.aspx`
- `error2.aspx`

## MITRE ATT&CK Framework Mapping

### Initial Access
- **T1190**: Exploit Public-Facing Application
- **T1566.001**: Spearphishing Attachment
- **T1189**: Drive-by Compromise (watering hole)
- **T1133**: External Remote Services

### Execution
- **T1059.001**: Command & Scripting Interpreter: PowerShell
- **T1059.003**: Command & Scripting Interpreter: Windows Cmd
- **T1055.012**: Process Injection: Process Hollowing
- **T1047**: Windows Management Instrumentation
- **T1203**: Exploitation for Client Execution

### Persistence
- **T1505.003**: Server Software Component: Web Shell
- **T1543.003**: Create/Modify System Process: Windows Service
- **T1547.001**: Registry Run Keys/Startup Folder
- **T1053**: Scheduled Task/Job
- **T1112**: Modify Registry

### Privilege Escalation
- **T1068**: Exploitation for Privilege Escalation
- **T1548.002**: Bypass User Account Control

### Credential Access
- **T1003**: OS Credential Dumping
- **T1555**: Credentials from Password Stores
- **T1056.001**: Input Capture: Keylogging

### Collection
- **T1113**: Screen Capture

### Discovery
- **T1046**: Network Service Scanning
- **T1018**: Remote System Discovery
- **T1033**: Account Discovery
- **T1087**: Account Discovery: Local Account
- **T1016**: System Network Configuration Discovery
- **T1049**: System Network Connections Discovery
- **T1005**: Data from Local System

### Lateral Movement
- **T1210**: Exploitation of Remote Services
- **T1570**: Lateral Tool Transfer

### Command and Control
- **T1071.001**: Application Layer Protocol: Web Protocols

### Exfiltration
- **T1074.001**: Data Staged: Local
- **T1074.002**: Data Staged: Remote
- **T1560.001**: Archive Collected Data
- **T1567.002**: Exfiltration Over Web Service: To Cloud Storage (Dropbox)
- **T1041**: Exfiltration Over C2 Channel

### Defense Evasion
- **T1574.001**: DLL Side-Loading
- **T1027**: Obfuscated/Compressed Files & Info
- **T1070**: Indicator Removal
- **T1562.002**: Impair Defenses: Disable Windows Event Logging
- **T1140**: Deobfuscate/Decode Files or Information

## Detection Recommendations

### Network Monitoring
- Monitor for connections to known C2 infrastructure (185.12.45.134)
- Detect unusual outbound traffic patterns
- Monitor for data exfiltration to cloud storage services (Dropbox)
- Implement network segmentation to limit lateral movement

### Endpoint Detection
- Monitor for execution of known APT27 malware families (HyperBro, SysUpdate, PlugX)
- Detect DLL side-loading activities
- Monitor for credential dumping activities (Mimikatz, WCE)
- Track scheduled task creation and modification
- Monitor for web shell uploads and execution

### Email Security
- Implement advanced phishing detection
- Monitor for spear-phishing campaigns targeting specific individuals
- Analyze email attachments for malicious content
- Deploy email security gateways with advanced threat protection

### Web Application Security
- Monitor for web shell uploads and execution
- Implement application-layer monitoring for suspicious activities
- Regular vulnerability assessments of public-facing applications
- Monitor for exploitation of Zoho ManageEngine and similar applications

## Mitigation Strategies

### Technical Controls
- Implement multi-factor authentication across all systems
- Regular patching of public-facing applications, especially Zoho ManageEngine
- Network segmentation to limit lateral movement
- Endpoint detection and response (EDR) solutions
- Email security gateways with advanced threat protection
- Web application firewalls (WAF)

### Administrative Controls
- Security awareness training focusing on spear-phishing recognition
- Regular security assessments and penetration testing
- Incident response planning and testing
- Vendor risk management for third-party applications
- Regular backup and recovery testing

### Monitoring and Detection
- 24/7 security operations center (SOC) monitoring
- Threat hunting activities focused on APT27 TTPs
- Regular IOC updates and threat intelligence integration
- Behavioral analytics for detecting advanced persistent threats
- Regular security assessments and vulnerability management

## Critical Vulnerabilities Exploited

### Zoho ManageEngine ADSelfService Plus (CVE-2021-40539)
- **CVSS Score**: 9.8 (Critical)
- **Impact**: Remote code execution vulnerability
- **Exploitation**: Used in healthcare sector targeting campaigns
- **Affected Organizations**: Healthcare, defense, higher education, consulting, and IT industries
- **Recommendation**: Immediate patching and monitoring required

## MISP Event Details

### Event Information
- **Event ID**: [To be assigned by MISP instance]
- **Date**: 2025-01-15
- **Threat Level**: High (1)
- **TLP**: Amber
- **Attribute Count**: 30
- **Published**: False (for internal use)

### Attribute Categories
- **Network Activity**: 2 attributes (IP addresses, URLs)
- **Payload Delivery**: 25 attributes (SHA256 hashes, filenames)
- **Attribution**: 6 attributes (threat actor names and aliases)

### Tags Applied
- `tlp:amber`
- `type:OSINT`
- `misp:threat-level="high"`
- `misp-galaxy:threat-actor="APT27"`
- `misp-galaxy:country="China"`
- Malware-specific tags for HyperBro, SysUpdate, PlugX, Korplug, Pandora
- Tool-specific tags for Mimikatz, WCE, China Chopper, ASPXSpy
- MITRE ATT&CK technique tags

## References

1. [DeXpose APT27 Threat Actor Profile](https://www.dexpose.io/threat-actor-profile-apt27/)
2. [MITRE ATT&CK APT27](https://attack.mitre.org/groups/G0027/)
3. [FBI IC3 PSA on APT27](https://www.ic3.gov/PSA/2025/PSA250305)
4. [DOJ Charges Against Chinese Hackers](https://www.justice.gov/opa/pr/justice-department-charges-12-chinese-contract-hackers-and-law-enforcement-officers-global)
5. [HHS Sector Alert on APT27](https://www.hhs.gov/sites/default/files/chinese-cyberspionage-campaign-targets-multiple-industries.pdf)
6. [Trellix Research on Cyber Tools and Foreign Policy](https://www.trellix.com/blogs/research/cyber-tools-and-foreign-policy/)
7. [Google Cloud Security Insights on APT Groups](https://cloud.google.com/security/resources/insights/apt-groups)
8. [Scythe Threat Thursday on APT27](https://scythe.io/threat-thursday/apt27)
9. [HivePro Threat Advisory on APT27 HyperBro](https://hivepro.com/threat-advisory/apt27-group-uses-the-hyperbro-remote-access-trojan-to-inject-backdoors-into-victims-network/)
10. [Unit42 Research on Emissary Panda](https://unit42.paloaltonetworks.com/emissary-panda-attacks-middle-east-government-sharepoint-servers/)

---

**Report Classification**: TLP:AMBER  
**Distribution**: Internal use only  
**Last Updated**: January 15, 2025  
**Next Review**: February 15, 2025  
**Report Version**: 1.0

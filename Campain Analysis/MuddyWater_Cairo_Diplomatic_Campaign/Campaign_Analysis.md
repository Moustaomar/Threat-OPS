# MuddyWater Cairo-Centric Diplomatic Espionage Campaign Analysis

## Executive Summary

This analysis details a sophisticated espionage campaign attributed to MuddyWater (also known as MERCURY), an Iranian state-sponsored Advanced Persistent Threat (APT) group. The campaign specifically targets Egyptian diplomatic entities and other Middle Eastern government organizations through carefully crafted spear-phishing operations designed to appear as legitimate diplomatic communications.

## Campaign Overview

- **Threat Actor**: MuddyWater (MERCURY)
- **Attribution**: Iran's Ministry of Intelligence and Security (MOIS)
- **Campaign Name**: Cairo-Centric Diplomatic Espionage Campaign
- **Primary Targets**: Egyptian Ministry of Foreign Affairs, Middle Eastern diplomatic entities
- **Timeline**: Active as of August 2025
- **Classification**: TLP:AMBER

## Attack Vector Analysis

### Initial Access (T1566.001)
The campaign employs spear-phishing attachments as the primary initial access vector. The attackers craft emails that appear to originate from legitimate government sources, using themes such as:

- **Online seminars** hosted by Ministry of Foreign Affairs entities
- **Infrastructure project documentation** (dredging projects)
- **Official diplomatic communications**

### Payload Delivery
The attack chain follows this sequence:

1. **Spear-phishing Email** → Contains malicious Office document
2. **Malicious Document** → Executes VBA macro upon user interaction
3. **VBA Macro** → Downloads and executes secondary payload
4. **Custom Backdoor** (sysProcUpdate.exe) → Establishes persistence and C2 communication

## Technical Analysis

### Infrastructure
- **Primary Domain**: `screenai.online`
- **IP Address**: `159.198.36.115` ⚠️ **CRITICAL INTELLIGENCE**
- **C2 Endpoint**: `https://screenai.online/Home/`

### Infrastructure Analysis - MOIS Connection
**SIGNIFICANT FINDING**: The IP address `159.198.36.115` is associated with **HomeLand Justice** (Void Manticore), another Iranian state-sponsored threat actor affiliated with Iran's Ministry of Intelligence and Security (MOIS). This infrastructure sharing demonstrates:

1. **Coordinated Iranian Cyber Operations**: Multiple MOIS-affiliated groups sharing infrastructure
2. **Operational Efficiency**: Centralized infrastructure management across threat actors
3. **Strategic Coordination**: MuddyWater and HomeLand Justice operations may be centrally planned

The domain `screenai.online` is designed to masquerade as a legitimate AI-related service, a common tactic used by Iranian operators to blend malicious infrastructure with legitimate-appearing services.

### Malware Components

#### 1. VBA Macro (ThisDocument.cls)
- **Purpose**: Initial execution and payload staging
- **Techniques**: Obfuscation, anti-analysis, sandbox evasion
- **Multiple variants** identified with different hash values

#### 2. Custom Backdoor (sysProcUpdate.exe)
- **Purpose**: Persistence, reconnaissance, data exfiltration
- **Process Name**: Designed to appear as a legitimate Windows system process
- **Capabilities**: 
  - Command execution
  - File system access
  - Network communication
  - Process injection (T1055.002)

#### 3. Decoy Documents
The campaign uses multiple decoy documents themed around:
- **Egypt**: MFA seminars and infrastructure projects
- **Cyprus**: Ministry of Foreign Affairs communications
- **Oman**: Foreign Ministry official documents

## MITRE ATT&CK Mapping

### Tactics and Techniques Observed

| Tactic | Technique | ID | Description |
|--------|-----------|----|-----------| 
| **Initial Access** | Spearphishing Attachment | T1566.001 | Malicious Office documents |
| **Execution** | User Execution | T1204.002 | Macro-enabled documents |
| **Execution** | Visual Basic | T1059.005 | VBA macro execution |
| **Execution** | Windows Command Shell | T1059.003 | Command line operations |
| **Persistence** | Registry Run Keys | T1547.001 | Startup persistence |
| **Privilege Escalation** | Process Injection | T1055.002 | PE injection techniques |
| **Defense Evasion** | Deobfuscate/Decode Files | T1140 | Runtime deobfuscation |
| **Defense Evasion** | Obfuscated Files | T1027.016 | Junk code insertion |
| **Defense Evasion** | Virtualization/Sandbox Evasion | T1497 | Anti-analysis techniques |
| **Discovery** | Account Discovery | T1087.001 | Local account enumeration |
| **Discovery** | System Information Discovery | T1082 | System reconnaissance |
| **Discovery** | System Owner/User Discovery | T1033 | User enumeration |
| **Command and Control** | Web Protocols | T1071.001 | HTTPS communications |
| **Command and Control** | Ingress Tool Transfer | T1105 | Tool and payload delivery |
| **Exfiltration** | Exfiltration Over C2 Channel | T1041 | Data exfiltration |

## Geopolitical Context

This campaign aligns with Iran's strategic intelligence interests in the Middle East, particularly:

1. **Diplomatic Intelligence Gathering**: Targeting Egyptian foreign ministry to understand Egypt's regional diplomatic positions
2. **Regional Influence Operations**: Monitoring diplomatic communications between Middle Eastern nations
3. **Strategic Infrastructure Monitoring**: Interest in regional development projects and infrastructure initiatives

## Defensive Recommendations

### Immediate Actions
1. **Block IOCs**: Implement blocking rules for identified domains, IPs, and file hashes
2. **Email Security**: Enhance email filtering for Office documents from external sources
3. **User Awareness**: Conduct targeted training on diplomatic-themed phishing attempts

### Long-term Mitigations
1. **Macro Security**: Disable VBA macros by default organization-wide
2. **Application Allowlisting**: Implement strict controls on executable execution
3. **Network Monitoring**: Deploy enhanced monitoring for C2 communications
4. **Endpoint Detection**: Deploy behavioral analysis for process injection techniques

## Intelligence Gaps

1. **Additional Infrastructure**: Likely additional domains and IPs not yet identified
2. **Attribution Confidence**: Medium-high confidence based on TTPs and targeting
3. **Campaign Scope**: Potential additional targets beyond those identified
4. **Operational Timeline**: Full campaign duration and progression unclear

## Related Activity

This campaign shows similarities to previous MuddyWater operations:
- Use of government-themed decoy documents
- PowerShell-based execution chains
- Custom backdoor development
- Targeting of Middle Eastern government entities

## Analyst Assessment

- **Threat Level**: HIGH
- **Sophistication**: MEDIUM-HIGH
- **Attribution Confidence**: MEDIUM-HIGH
- **Campaign Status**: ACTIVE
- **Recommended Response**: IMMEDIATE ACTION REQUIRED

## Sources and References

- Network indicators extracted from campaign analysis
- File hash analysis from malware samples
- MITRE ATT&CK framework mapping
- Regional geopolitical context analysis

---

**Analysis Date**: August 9, 2025  
**Analyst**: CTI Expert  
**Classification**: TLP:AMBER  
**Distribution**: Authorized personnel only

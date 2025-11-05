# HomeLand Justice (Void Manticore) - Threat Actor Profile

## Executive Summary

HomeLand Justice is an Iranian state-sponsored cyber threat group affiliated with Iran's Ministry of Intelligence and Security (MOIS), widely considered a persona used by the broader threat actor known as **Void Manticore**. Active since at least 2008, this group conducts politically motivated cyber operations focused on espionage, data destruction, and influence campaigns.

## Threat Actor Details

- **Primary Name**: HomeLand Justice
- **Alternative Names**: Void Manticore, Karma (Israel-focused operations)
- **Attribution**: Iran's Ministry of Intelligence and Security (MOIS)
- **Active Since**: 2008
- **Classification**: State-sponsored APT

## Key Characteristics

### Operational Focus
- **Politically motivated cyber operations**
- **Espionage and intelligence gathering**
- **Data destruction and disruption**
- **Influence campaigns and psychological operations**

### Primary Targets
- **Albanian government and infrastructure** (anti-MEK operations)
- **Middle Eastern diplomatic entities**
- **Opposition groups** (particularly MEK - Mojahedin-e Khalq)
- **Regional government institutions**

## Notable Campaigns

### Albanian Government Operations
- **July 2022**: Disrupted Albanian e-government services
  - Objective: Cancel planned MEK conference
  - Impact: Significant service disruption
- **September 2022**: Targeted border systems
- **December 2023**: Attacked government institutions

### Geopolitical Context
The group's operations are closely tied to Iran's opposition to the **Mojahedin-e Khalq (MEK)** organization, which operates from Albanian territory. Their attacks often coincide with:
- Political events involving MEK
- International conferences
- Diplomatic tensions

## Symbolism and Branding

### Logo Analysis
HomeLand Justice's logo is strategically designed to counter the **PredatorySparrow** threat actor:
- **Design**: Eagle attacking a bird (representing PredatorySparrow)
- **Symbolism**: Bird confined in Star of David
- **Message**: "why should our taxes be spent on terrorists of Durres?"
- **Reference**: Durres is Albania's second-largest city, home to MEK

### PredatorySparrow Connection
- **Target**: Iranian fuel infrastructure (December 18, 2023)
- **Previous attacks**: Iranian steel factories
- **Relationship**: HomeLand Justice positions itself as counter to PredatorySparrow

## Regional Aliases and Operations

### HomeLand Justice (Albania Focus)
- Primary operations against Albanian targets
- Anti-MEK campaigns
- Government infrastructure disruption

### Karma (Israel Focus)
- Israel-targeted operations
- Regional geopolitical campaigns
- Coordinated with broader Iranian cyber strategy

## Tactics, Techniques, and Procedures (TTPs) - Comprehensive Analysis

### Initial Access
- **T1190: Exploit Public-Facing Application** - Web service exploitation across multiple ports
- **T1078: Valid Accounts** - Compromised credential usage for network infiltration

### Execution (Advanced Capabilities)
- **T1059.001: PowerShell** - Primary payload execution method
- **T1059.003: Windows Command Shell** - System command execution
- **T1059.004: Unix Shell** - Cross-platform capabilities
- **T1072: Software Deployment Tools** - Legitimate tool abuse
- **T1569: System Services** / **T1569.002: Service Execution** - Service manipulation

### Persistence (Multi-Vector Approach)
- **T1098: Account Manipulation** - User account modification
- **T1543: Create or Modify System Process** / **T1543.003: Windows Service** - Process/service manipulation
- **T1112: Modify Registry** - Registry-based persistence
- **T1505.003: Web Shell** - Server component persistence

### Privilege Escalation
- **T1134: Access Token Manipulation** - Token privilege escalation
- **T1055: Process Injection** - Code injection into legitimate processes
- **T1098: Account Manipulation** - Account privilege escalation

### Defense Evasion (Sophisticated Anti-Analysis)
- **T1134: Access Token Manipulation** - Token-based evasion
- **T1553.002: Code Signing** - Trust control subversion
- **T1140: Deobfuscate/Decode Files** - Runtime deobfuscation
- **T1562.001: Disable or Modify Tools** / **T1562: Impair Defenses** - Security tool disruption
- **T1070: Indicator Removal** / **T1070.004: File Deletion** / **T1070.006: Timestomp** - Evidence elimination
- **T1036: Masquerading** - Legitimate software impersonation
- **T1027: Obfuscated Files** - Code/data obfuscation
- **T1497: Virtualization/Sandbox Evasion** / **T1497.001: System Checks** - Analysis environment detection

### Credential Access
- **T1056: Input Capture** / **T1056.001: Keylogging** - User input interception
- **T1003.001: LSASS Memory** - OS credential dumping

### Discovery (Comprehensive Reconnaissance)
- **T1087: Account Discovery** - User account enumeration
- **T1083: File and Directory Discovery** - File system reconnaissance
- **T1046: Network Service Discovery** - Network service scanning
- **T1057: Process Discovery** - Running process enumeration
- **T1012: Query Registry** - Registry information gathering
- **T1018: Remote System Discovery** - Network system discovery
- **T1518: Software Discovery** - Installed software enumeration
- **T1082: System Information Discovery** - System configuration gathering
- **T1033: System Owner/User Discovery** - User/ownership information
- **T1007: System Service Discovery** - System service enumeration

### Lateral Movement (Multi-Protocol Capabilities)
- **T1570: Lateral Tool Transfer** - Tool deployment across systems
- **T1021.001: Remote Desktop Protocol** - RDP-based movement
- **T1021: Remote Services** - Remote service exploitation
- **T1021.002: SMB/Windows Admin Shares** - File share movement
- **T1021.006: Windows Remote Management** - WinRM movement
- **T1072: Software Deployment Tools** - Legitimate tool misuse

### Collection
- **T1056: Input Capture** / **T1056.001: Keylogging** - User data collection
- **T1113: Screen Capture** - Screen content collection

### Command and Control (Advanced Infrastructure)
- **T1105: Ingress Tool Transfer** - Tool/payload delivery
- **T1095: Non-Application Layer Protocol** - Custom protocol C2
- **T1572: Protocol Tunneling** - Protocol encapsulation
- **T1090: Proxy** - Proxy chain communication

### Exfiltration
- **T1048.003: Exfiltration Over Unencrypted Non-C2 Protocol** - Alternative exfiltration channels

### Impact (Destructive Capabilities)
- **T1485: Data Destruction** - Data deletion/corruption
- **T1486: Data Encrypted for Impact** - Ransomware/encryption attacks
- **T1561: Disk Wipe** / **T1561.001: Disk Content Wipe** / **T1561.002: Disk Structure Wipe** - Comprehensive disk destruction
- **T1490: Inhibit System Recovery** - Recovery mechanism disruption
- **T1489: Service Stop** - Critical service termination

## Infrastructure Connections

### Known Infrastructure
- **IP Address**: `159.198.36.115` (linked to MuddyWater Cairo campaign)
- **Domain**: `screenai.online` (shared with MuddyWater operations)

This infrastructure sharing demonstrates the interconnected nature of Iranian cyber operations and the coordination between different MOIS-affiliated groups.

## Intelligence Assessment

### Threat Level: **HIGH**
- State-sponsored capabilities
- Proven operational success
- Active targeting of regional allies

### Sophistication: **MEDIUM-HIGH**
- Custom malware development
- Coordinated multi-vector campaigns
- Strategic geopolitical alignment

### Geographic Scope: **REGIONAL**
- Primary focus: Middle East and Balkans
- Secondary: Counter-opposition operations globally

## Defensive Recommendations

### Immediate Actions
1. **Monitor known infrastructure** (159.198.36.115, screenai.online)
2. **Enhanced email security** for government entities
3. **Threat hunting** for HomeLand Justice TTPs

### Strategic Mitigations
1. **Diplomatic entity hardening** in MEK-related regions
2. **Cross-border intelligence sharing** (Albania, regional partners)
3. **Counter-influence operations** awareness

## Related Threat Activity

### Connected Operations
- **MuddyWater**: Shared infrastructure and targeting
- **Iranian Cyber Operations**: Broader MOIS coordination
- **Anti-MEK Campaigns**: Multi-actor collaboration

### Timeline Correlation
- MuddyWater diplomatic campaigns align with HomeLand Justice operations
- Coordinated timing suggests centralized planning
- Infrastructure reuse indicates operational efficiency

## Intelligence Gaps

1. **Full infrastructure mapping** of Void Manticore
2. **Command and control structure** within MOIS
3. **Operational planning cycles** and triggers
4. **Technical capabilities evolution**

---

**Analysis Date**: September 8, 2025  
**Analyst**: CTI Expert  
**Classification**: TLP:AMBER  
**Source**: Open Source Intelligence, Infrastructure Analysis

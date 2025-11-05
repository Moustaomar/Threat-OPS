# Nimbus Manticore Threat Actor Profile

## Executive Summary

**Nimbus Manticore** is a sophisticated Iranian-linked Advanced Persistent Threat (APT) group that has been active since at least 2022. The group demonstrates advanced operational security, innovative attack techniques, and a focus on strategic intelligence gathering aligned with Islamic Revolutionary Guard Corps (IRGC) priorities.

## Threat Actor Information

### Primary Designations
- **Nimbus Manticore** (CheckPoint Research)
- **UNC1549** (Mandiant)
- **Smoke Sandstorm** (Microsoft)
- **Iranian Dream Job** (Previous campaign designation)

### Attribution
- **Country of Origin**: Iran
- **Affiliation**: Islamic Revolutionary Guard Corps (IRGC)
- **Motivation**: Strategic intelligence gathering, espionage
- **Sophistication Level**: Nation-state
- **Confidence Level**: High

## Historical Context

### Timeline
- **First Observed**: June 2022 (Minibike backdoor)
- **Recent Activity**: September 2025 (MiniJunk campaign)
- **Status**: Active
- **Evolution**: Significant advancement in stealth and evasion capabilities

### Campaign Evolution
1. **2022**: Initial Minibike backdoor deployment
2. **2023-2024**: Steady evolution of tools and techniques
3. **2025**: Introduction of MiniJunk and MiniBrowse, multi-stage DLL side-loading

## Target Profile

### Geographic Focus
- **Primary**: Western Europe (Portugal, Denmark, Sweden)
- **Secondary**: Middle East (Egypt, Israel, UAE, Azerbaijan)
- **Tertiary**: Asia (Pakistan)

### Sector Targeting
- **Defense Manufacturing**: Strategic weapons and military equipment
- **Telecommunications**: Critical infrastructure and communications
- **Aerospace/Aviation**: Commercial and military aviation
- **Healthcare**: Medical technology and research
- **Technology**: Cloud services and software development

### Target Selection Criteria
- Organizations aligned with IRGC strategic priorities
- High-value intelligence targets
- Critical infrastructure sectors
- Government and military contractors

## Attack Methodology

### Initial Access
- **Primary Vector**: Spear-phishing campaigns
- **Social Engineering**: HR recruitment impersonation
- **Infrastructure**: Fake career portals
- **Customization**: Unique URLs and credentials per target

### Persistence Mechanisms
- **Scheduled Tasks**: Windows Task Scheduler
- **Registry Modifications**: Run keys and system configuration
- **File System**: Malicious executables in application directories
- **Process Injection**: DLL side-loading techniques

### Command and Control
- **Infrastructure**: Azure and Cloudflare hosting
- **Resilience**: Multiple hardcoded C2 servers
- **Concealment**: IP address obfuscation
- **Redundancy**: Backup infrastructure

## Malware Arsenal

### MiniJunk Backdoor
- **Type**: Advanced backdoor
- **Evolution**: From original "Minibike" backdoor
- **Capabilities**:
  - Remote command execution
  - Data exfiltration
  - System reconnaissance
  - Persistence mechanisms
- **Stealth Features**:
  - Heavy obfuscation
  - Code signing
  - Binary size inflation
  - Junk code insertion

### MiniBrowse Stealer
- **Type**: Browser credential stealer
- **Targets**:
  - Saved passwords
  - Browser history
  - Session cookies
  - Form data
- **Stealth**: Similar obfuscation techniques as MiniJunk

### Technical Characteristics
- **Obfuscation**: Compiler-level obfuscation
- **Code Signing**: Valid digital signatures
- **Analysis Resistance**: "Irreversible" static analysis
- **Modular Architecture**: Redundant C2 infrastructure

## Tactics, Techniques, and Procedures (TTPs)

### MITRE ATT&CK Framework
- **T1574.002**: DLL Side-Loading
- **T1566.002**: Spearphishing Link
- **T1053.005**: Scheduled Task
- **T1055**: Process Injection
- **T1027**: Obfuscated Files or Information
- **T1078**: Valid Accounts
- **T1071.001**: Web Protocols
- **T1105**: Ingress Tool Transfer
- **T1583.001**: Acquire Infrastructure - Domains
- **T1584.001**: Compromise Infrastructure - Domains

### Attack Chain
1. **Reconnaissance**: Target research and profiling
2. **Weaponization**: Malware development and testing
3. **Delivery**: Spear-phishing with malicious attachments
4. **Exploitation**: Multi-stage DLL side-loading
5. **Installation**: Persistence mechanisms
6. **Command and Control**: C2 communication
7. **Actions on Objectives**: Data exfiltration

## Infrastructure Analysis

### Domain Infrastructure
- **Career Portals**: Impersonation of legitimate companies
- **Azure Hosting**: Legitimate cloud infrastructure
- **Cloudflare Protection**: IP address concealment
- **Dynamic DNS**: Infrastructure flexibility

### C2 Infrastructure
- **Primary**: Azure-based infrastructure
- **Secondary**: Cloudflare-protected domains
- **Backup**: Multiple hardcoded servers
- **Resilience**: Redundant communication channels

### Domain Naming Conventions
- **Career-themed**: boeing-careers.com, airbus.global-careers.com
- **Medical-themed**: healthbodymonitoring.azurewebsites.net
- **Generic**: cloudaskingquestions.azurewebsites.net

## Operational Security (OPSEC)

### Stealth Techniques
- **DLL Side-loading**: Unusual DLL loading from alternate paths
- **Process Hollowing**: Legitimate process execution
- **Code Obfuscation**: Heavy, compiler-level obfuscation
- **Binary Bloating**: Size inflation to evade detection

### Infrastructure Security
- **IP Concealment**: Cloudflare protection
- **Domain Fronting**: Traffic obfuscation
- **Legitimate Hosting**: Azure and legitimate cloud services
- **Dynamic Infrastructure**: Rapid infrastructure changes

## Intelligence Gaps

### Technical Gaps
- Complete malware sample analysis
- Full C2 infrastructure mapping
- Detailed TTP documentation
- Attribution evidence

### Operational Gaps
- Campaign timeline reconstruction
- Target selection criteria
- Data exfiltration methods
- Long-term objectives

## Detection Recommendations

### Network Monitoring
- Monitor for connections to career-themed domains
- Watch for Azure infrastructure communication
- Track DLL side-loading behaviors
- Monitor for scheduled task creation

### Endpoint Detection
- **EDR Rules**: DLL side-loading detection
- **Process Monitoring**: Unusual process execution chains
- **File System**: Monitor for persistence mechanisms
- **Registry**: Track system configuration changes

### Email Security
- **Phishing Detection**: HR-themed spear-phishing campaigns
- **URL Analysis**: Career portal domain monitoring
- **Attachment Scanning**: Malicious archive detection

## Mitigation Strategies

### Immediate Actions
1. **Block Known IOCs**: Implement network blocks for identified domains and IPs
2. **Email Filtering**: Enhance spear-phishing detection
3. **Endpoint Protection**: Deploy DLL side-loading detection
4. **User Training**: Educate on HR-themed phishing campaigns

### Long-term Defenses
1. **Zero Trust Architecture**: Implement strict access controls
2. **Behavioral Analytics**: Deploy AI-based threat detection
3. **Threat Hunting**: Proactive search for similar TTPs
4. **Incident Response**: Prepare for APT-level intrusions

## Threat Assessment

### Risk Level
- **Overall Risk**: HIGH
- **Sophistication**: Nation-state level
- **Persistence**: Long-term threat
- **Impact**: Strategic intelligence gathering

### Key Concerns
- Advanced stealth techniques
- Sophisticated social engineering
- Resilient infrastructure
- Strategic targeting

## Conclusion

Nimbus Manticore represents a significant and evolving threat to organizations in targeted sectors. The group's advanced capabilities, sophisticated attack techniques, and strategic focus make them a high-priority threat requiring comprehensive defense strategies.

Organizations should implement multi-layered defenses, including advanced threat detection, user education, and incident response capabilities to defend against this sophisticated threat actor.

---

**Sources:**
- CheckPoint Research: "Nimbus Manticore Deploys New Malware Targeting Europe" (September 2025)
- Mandiant: "Minibike Backdoor Analysis" (June 2022)
- Microsoft: "Smoke Sandstorm Campaign Analysis"

**Last Updated**: October 2025
**Classification**: TLP:AMBER

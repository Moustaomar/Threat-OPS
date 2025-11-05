# Nimbus Manticore APT Campaign Analysis

## Executive Summary

**Nimbus Manticore** (also known as UNC1549, Smoke Sandstorm, and "Iranian Dream Job" operations) is a sophisticated Iranian-linked Advanced Persistent Threat (APT) group that has recently launched a new malware campaign targeting Western Europe and the Middle East. The campaign demonstrates advanced operational security, multi-stage DLL side-loading techniques, and the deployment of evolved malware tools including **MiniJunk** backdoor and **MiniBrowse** stealer.

## Campaign Overview

### Timeline
- **First Observed**: Early 2025
- **Active Period**: Ongoing
- **Latest Activity**: September 2025

### Target Geography
- **Primary Targets**: Western Europe
  - Portugal
  - Denmark  
  - Sweden
- **Secondary Targets**: Middle East & Asia
  - Egypt
  - Israel
  - United Arab Emirates
  - Azerbaijan
  - Pakistan

### Target Sectors
- Defense manufacturing
- Telecommunications
- Aerospace/aviation
- Organizations aligned with IRGC strategic priorities

## Threat Actor Profile

### Aliases
- **Nimbus Manticore** (CheckPoint designation)
- **UNC1549** (Mandiant designation)
- **Smoke Sandstorm** (Microsoft designation)
- **Iranian Dream Job** (Previous campaign name)

### Attribution
- **Country of Origin**: Iran
- **Affiliation**: Islamic Revolutionary Guard Corps (IRGC)
- **Motivation**: Strategic intelligence gathering, espionage
- **Sophistication Level**: Nation-state

### Historical Context
Nimbus Manticore has been active since at least 2022, with their **Minibike** backdoor (also known as **SlugResin**) first reported by Mandiant in June 2022. The group has demonstrated consistent evolution of their tools and techniques, showing significant advancement in stealth and evasion capabilities.

## Attack Methodology

### Initial Access
1. **Spear-Phishing Campaign**
   - Fake HR recruiter messages
   - Impersonation of legitimate aerospace, defense, and telecommunications companies
   - Custom URLs and credentials for each target
   - High-quality pretexting with local context

2. **Fake Career Portals**
   - React-based infrastructure
   - Impersonated brands: Boeing, Airbus, Rheinmetall, flydubai
   - Career-themed domain naming conventions
   - Cloudflare protection for IP concealment
   - Pre-shared credentials for controlled access

### Malware Delivery
- **Archive Format**: ZIP files masquerading as legitimate hiring software
- **Example**: `Survey.zip` containing malicious executables
- **Social Engineering**: Files appear as legitimate hiring process software

### Infection Chain

#### Multi-Stage DLL Side-Loading
The campaign employs a sophisticated **multi-stage sideloading** technique:

1. **User Execution**
   - Victim runs `Setup.exe` from malicious archive
   - Legitimate Windows executable that side-loads `userenv.dll`

2. **Malware Setup**
   - `Setup.exe` starts `SenseSampleUploader.exe` (Windows Defender component)
   - `SenseSampleUploader.exe` side-loads `xmllite.dll` (malware loader)

3. **Persistence**
   - Loader copies `Setup.exe` as `MigAutoPlay.exe` to `%AppData%\Local\Microsoft\MigAutoPlay\`
   - Copies malicious `userenv.dll` to working directory
   - Creates scheduled task for persistence

#### DLL Side-Loading Mechanism
- **userenv.dll**: Checks executing PE module name to determine infection stage
- **Stage Detection**: If not running from `MigAutoPlay.exe`, loads the Loader DLL
- **Process Override**: Uses previously undocumented low-level APIs to modify process execution parameters
- **DLL Search Order**: Overrides normal DLL search order to load malicious DLLs from alternate paths

## Malware Arsenal

### MiniJunk Backdoor
- **Evolution**: Advanced version of the original "Minibike" backdoor
- **Capabilities**: 
  - Remote command execution
  - Data exfiltration
  - Persistence mechanisms
  - C2 communication
- **Stealth Features**:
  - Heavy obfuscation
  - Compiler-level tricks
  - Code signing with valid certificates
  - Binary size inflation
  - Junk code insertion

### MiniBrowse Stealer
- **Purpose**: Browser credential and data theft
- **Targets**: 
  - Saved passwords
  - Browser history
  - Session cookies
  - Form data
- **Stealth**: Similar obfuscation techniques as MiniJunk

### Technical Characteristics
- **Obfuscation**: Heavy, compiler-level obfuscation
- **Code Signing**: Valid digital signatures
- **Binary Bloating**: Size inflation to evade detection
- **Analysis Resistance**: Samples designed to be "irreversible" for static analysis
- **Modular Architecture**: Redundant C2 servers for resilience

## Infrastructure Analysis

### Command and Control (C2)
- **Resilience**: Multiple hardcoded C2 servers
- **Cloud Services**: Extensive use of Azure and Cloudflare
- **Redundancy**: Backup C2 infrastructure
- **Concealment**: IP address obfuscation through cloud services

### Domain Infrastructure
The campaign uses two distinct infrastructure clusters:

#### Primary Campaign Domains
- **Career-themed domains**:
  - `boeing-careers.com`
  - `rheinmetallcareer.org`
  - `airbus.global-careers.com`
  - `flydubaicareers.ae.org`
- **Generic career domains**:
  - `global-careers.com`
  - `careers-hub.org`
  - `careersworld.org`

#### Azure Infrastructure
- **Medical/Healthcare themed**:
  - `healthbodymonitoring.azurewebsites.net`
  - `medical-deepresearch.azurewebsites.net`
  - `patient-azureportal.azurewebsites.net`
- **Cloud services**:
  - `cloudaskingquestions.azurewebsites.net`
  - `smartapptools.azurewebsites.net`

### Infrastructure Resilience
- **Cloudflare Protection**: IP address concealment
- **Azure Hosting**: Legitimate cloud infrastructure
- **Domain Fronting**: Traffic obfuscation techniques
- **Dynamic DNS**: Dynamic infrastructure updates

## Technical Indicators

### File Hashes
*Note: Specific hashes would be extracted from malware samples and included in IOC lists*

### Network Indicators
- **Domains**: 100+ malicious domains across multiple TLDs
- **IP Addresses**: Azure-hosted infrastructure
- **URLs**: Career portal and malware delivery URLs

### Behavioral Indicators
- **DLL Side-loading**: Unusual DLL loading from alternate paths
- **Process Hollowing**: Legitimate process execution with malicious payloads
- **Scheduled Tasks**: Persistence through Windows Task Scheduler
- **Registry Modifications**: System configuration changes

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

## Conclusion

The Nimbus Manticore campaign represents a significant escalation in Iranian APT capabilities, demonstrating:

1. **Advanced Stealth**: Multi-stage DLL side-loading and heavy obfuscation
2. **Operational Security**: Sophisticated infrastructure and targeting
3. **Technical Innovation**: Previously undocumented techniques
4. **Strategic Focus**: Clear alignment with IRGC priorities

Organizations in targeted sectors should implement comprehensive detection and response capabilities to defend against this sophisticated threat actor.

---

**Sources:**
- CheckPoint Research: "Nimbus Manticore Deploys New Malware Targeting Europe" (September 2025)
- Mandiant: "Minibike Backdoor Analysis" (June 2022)
- Microsoft: "Smoke Sandstorm Campaign Analysis"

**Last Updated**: October 2025
**Classification**: TLP:AMBER

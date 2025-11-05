# HoldingHands Asia Expansion Campaign - Comprehensive Threat Analysis

## Executive Summary

FortiGuard Labs has identified a sophisticated multi-stage malware campaign leveraging HoldingHands and Winos 4.0 malware that has expanded across Asia throughout 2024-2025. The campaign, attributed to an unidentified threat actor, initially targeted users in China before systematically expanding to Taiwan, Japan, and most recently Malaysia. The operation demonstrates advanced evasion techniques, infrastructure reuse patterns, and evolving delivery mechanisms that connect seemingly isolated attacks into a coordinated regional campaign.

**Source**: Fortinet FortiGuard Labs Threat Research  
**Reference**: https://www.fortinet.com/blog/threat-research/tracking-malware-and-attack-expansion-a-hacker-groups-journey-across-asia  
**Publication Date**: October 17, 2025  
**Campaign Timeline**: March 2024 - October 2025

## Threat Overview

### Campaign Characteristics
- **Primary Malware Families**: Winos 4.0, HoldingHands
- **Targeted Regions**: China, Taiwan, Japan, Malaysia
- **Attack Vector**: Phishing emails with malicious PDF and Excel attachments
- **Severity Level**: High
- **Affected Platforms**: Microsoft Windows
- **Impact**: Information theft, persistent system access, credential harvesting

### Key Findings
1. **Geographic Expansion**: Systematic targeting across Asia with infrastructure connections
2. **Infrastructure Reuse**: Shared Tencent Cloud account IDs and domain patterns
3. **Evolving Tactics**: Transition from cloud storage links to custom domains
4. **Advanced Evasion**: Multi-stage execution, anti-VM, privilege escalation, Task Scheduler abuse
5. **Social Engineering**: Impersonation of government documents from Ministries of Finance and other agencies

## Timeline of Campaign Evolution

### March 2024 - China Operations
- Initial attacks targeting China using Excel documents
- Delivery via Tencent Cloud storage links
- Distribution of Winos 4.0 malware

### January 2025 - Taiwan Expansion
- Winos 4.0 attacks observed targeting users in Taiwan
- Use of phishing PDFs mimicking Ministry of Finance documents
- Tencent Cloud Account IDs: 1321729461, 1329400280 identified

### February 2025 - Malware Family Shift
- Transition from Winos 4.0 to HoldingHands malware
- Expansion of operations across multiple countries
- Introduction of custom domain delivery (domains with "tw" pattern)

### March 2025 - Japan Targeting
- Japanese-language phishing pages deployed
- Continued use of Taiwan-related domains (twsww[.]xin/download[.]html)
- Shared C2 infrastructure (156[.]251[.]17[.]9)

### October 2025 - Malaysia Operations
- Latest campaign phase targeting Malaysia
- Advanced multi-stage execution via Task Scheduler
- Domain twczb[.]com linked to previous Taiwan infrastructure

## Technical Analysis

### Initial Access - Phishing Campaign

#### Delivery Mechanisms
1. **PDF Attachments**
   - Masquerade as official government documents
   - Embedded malicious links (Tencent Cloud and custom domains)
   - Multiple decoy links to avoid detection
   - Social engineering themes: tax regulations, purchase orders, ministry communications

2. **Excel Documents**
   - Observed in China-focused attacks (March 2024)
   - Macro-enabled documents with malicious payloads

3. **Word Documents**
   - Detected in Japan-focused attacks
   - Links to download pages hosting HoldingHands variants

4. **HTML Attachments**
   - Redirect to download pages
   - Contains links to deceptive images and malware delivery

#### Infrastructure Patterns
- **Tencent Cloud Abuse**: Account IDs 1321729461 and 1329400280 used across multiple campaigns
- **Domain Naming Convention**: Use of "tw" (Taiwan abbreviation) in second-level domains
- **Download Pages**: JavaScript-based dynamic link fetching from JSON data
- **Code Reuse**: Identical scripts across multiple webpages for different attacks

### Multi-Stage Execution Chain

#### Stage 1: Initial Loader (dokan2.dll)
- **Functionality**: Shellcode loader for sw.dat
- **Technique**: DLL side-loading via legitimate Dokany control program
- **File**: Dokumen audit cukai dan sampel bahan.exe (social engineering lure)
- **Evasion**: Masquerades as legitimate Dokany library

#### Stage 2: Environment Setup (sw.dat)
- **Anti-VM Detection**: Checks physically installed RAM
- **Privilege Escalation**: Impersonates TrustedInstaller service thread for highest privilege
- **Persistence**: Creates necessary files for subsequent stages
- **Anti-Analysis**: Multiple checks for analysis environments

#### Stage 3: Persistence Mechanism (TimeBrokerClient.dll)
- **Trigger**: Windows Task Scheduler service exploitation
- **Process Validation**: Calculates ASCII sum of process name (must equal 0x47A for svchost.exe)
- **Dynamic API Resolution**: VirtualAlloc RVA stored in svchost.ini
- **File Dependencies**: 
  - svchost.ini (contains VirtualAlloc RVA)
  - msvchost.dat (encrypted shellcode data)
- **Decryption Key**: Process name (svchost.exe) used as decryption key
- **Evasion**: Filenames generated dynamically from loading process name

#### Stage 4: Shellcode Execution (msvchost.dat)
- **Command Line Validation**: Checks for specific svchost.exe command line
  ```
  C:\windows\system32\svchost.exe -k netsvcs -p -s Schedule
  ```
- **Anti-AV Checks**: Repeats anti-virus process detection
- **Session Management**: 
  - Retrieves terminal sessions via WTSEnumerateSessions
  - Searches for active user sessions
  - Duplicates user access tokens for impersonation
  - Launches taskhostw.exe with user context
- **Payload Injection**: Injects HoldingHands payload into taskhostw.exe
- **Monitoring**: Checks every 5 seconds for taskhostw.exe; reinjects if terminated

### HoldingHands Payload

#### Core Capabilities
- **Information Stealing**: Exfiltrates sensitive data
- **Remote Access**: Provides backdoor access to compromised systems
- **Command and Control**: Communicates with attacker infrastructure
- **Persistence**: Maintains long-term access

#### Recent Updates (2025 Variant)
1. **Dynamic C2 Updates**: New command (0x15) to update C2 IP address via registry
   - **Registry Key**: HKEY_CURRENT_USER\SOFTWARE\HHClient
   - **Value Name**: AdrrStrChar
   - **Value**: {IP address}
   - **Benefit**: Infrastructure changes without malware redeployment

2. **Command Changes**: Termination command changed from 0x15 to 0x17

#### Configuration Storage
- **Registry Key**: HKEY_CURRENT_USER\SOFTWARE\HHClient
- **Persistent**: Survives reboots

### Task Scheduler Abuse

#### Persistence Mechanism
- **Target Service**: Task Scheduler (Schedule service)
- **Trigger Method**: Service restart mechanism
- **Recovery Setting**: Configured to restart 1 minute after failure
- **Execution Flow**:
  1. Task Scheduler service fails or is restarted
  2. svchost.exe executes to restart service
  3. Malicious TimeBrokerClient.dll loaded
  4. Shellcode chain initiated
- **Detection Challenge**: No direct process launch required

### Anti-Analysis Techniques

1. **Anti-VM Detection**
   - Physical RAM checks
   - Environment fingerprinting

2. **Process Validation**
   - ASCII sum calculations
   - Command line verification
   - Process name checks

3. **Anti-AV**
   - Security product process detection
   - Multiple validation stages

4. **Code Obfuscation**
   - Dynamic filename generation
   - Process name as decryption key
   - Encrypted shellcode stages

5. **Legitimate Signatures**
   - Digital signatures on malicious executables
   - Debug paths: D:\Workspace\HoldingHands-develop\HoldingHands-develop\Door\x64\Release\BackDoor.pdb

6. **Infrastructure Obscurity**
   - JSON-based dynamic link fetching
   - Prevents direct webpage-to-download link association

## Attribution and Victimology

### Threat Actor Profile
- **Attribution**: Unidentified hacker group
- **Sophistication Level**: High
- **Operational Security**: Strong (infrastructure reuse patterns, evolving tactics)
- **Targeting**: Regional focus on Asia-Pacific region

### Targeting Patterns
1. **Geographic Progression**
   - China (March 2024) → Taiwan (January 2025) → Japan (March 2025) → Malaysia (October 2025)
   - Systematic expansion across Southeast and East Asia

2. **Sector Focus**
   - Government entities (Ministry of Finance impersonation)
   - Tax and financial document themes
   - Business sectors (purchase orders)

3. **Language Localization**
   - Chinese, Traditional Chinese, Japanese, Malay language lures
   - Region-appropriate social engineering

## Indicators of Compromise (IOCs)

### Domains
```
zxp0010w.vip
gjqygs.cn
zcqiyess.vip
jpjpz1.cc
jppjp.vip
jpjpz1.top
twczb.com (Malaysia campaign)
twsww.xin (Japan campaign)
twswzz.xin (Taiwan campaign)
```

### IP Addresses
```
206.238.199.22
206.238.221.244
154.91.64.45
156.251.17.12
206.238.221.182
38.60.203.110
```

### File Hashes (SHA256)
```
c138ff7d0b46a657c3a327f4eb266866957b4117c0507507ba81aaeb42cdefa9
03e1cdca2a9e08efa8448e20b50dc63fdbea0e850de25c3a8e04b03e743b983d
2b1719108ec52e5dea20169a225b7d383ad450195a5e6274315c79874f448caa
dc45981ff705b641434ff959de5f8d4c12341eaeda42d278bd4e46628df94ac5
0db506d018413268e441a34e6e134c9f5a33ceea338fc323d231de966401bb2c
031c916b599e17d8cfa13089bddafc2436be8522f0c9e479c7d76ba3010bbd18
c6095912671a201dad86d101e4fe619319cc22b10b4e8d74c3cd655b2175364c
804dc39c1f928964a5c02d129da72c836accf19b8f6d8dc69fc853ce5f65b4f3
1c4bc67ae4af505f58bd11399d45e196fc17cc5dd32ad1d8e6836832d59df6e6
fb9c9ed91fc70f862876bd77314d3b2275069ca7c4db045e5972e726a3e8e04c
8d25da6459c427ad658ff400e1184084db1789a7abff9b70ca85cf57f4320283
```

### Malicious Files
```
dokan2.dll (shellcode loader)
sw.dat (environment setup)
TimeBrokerClient.dll (persistence mechanism)
svchost.ini (contains VirtualAlloc RVA)
msvchost.dat (encrypted shellcode)
system.dat (HoldingHands payload)
Dokumen audit cukai dan sampel bahan.exe (social engineering lure)
```

### Registry Keys
```
HKEY_CURRENT_USER\SOFTWARE\HHClient (configuration)
HKEY_CURRENT_USER\SOFTWARE\HHClient\AdrrStrChar (C2 IP address)
```

### Tencent Cloud Infrastructure
```
Account IDs: 1321729461, 1329400280
```

## Detection and Mitigation

### Detection Strategies

#### Network-Based Detection
1. Monitor for connections to identified malicious domains and IP addresses
2. Detect Tencent Cloud storage abuse patterns
3. Identify unusual DNS queries to domains with "tw" patterns
4. Monitor for C2 communication patterns

#### Host-Based Detection
1. **File System Monitoring**
   - Monitor for suspicious DLL side-loading (dokan2.dll)
   - Detect creation of .dat files in system directories
   - Alert on svchost.ini creation outside standard locations

2. **Registry Monitoring**
   - Monitor HKEY_CURRENT_USER\SOFTWARE\HHClient registry modifications
   - Alert on AdrrStrChar value changes

3. **Process Monitoring**
   - Detect unusual svchost.exe spawning taskhostw.exe
   - Monitor for Task Scheduler service restarts
   - Alert on TimeBrokerClient.dll loading by svchost.exe

4. **Behavioral Detection**
   - Token manipulation and impersonation attempts
   - WTSEnumerateSessions API calls from unusual processes
   - Privilege escalation via TrustedInstaller impersonation

#### Email Security
1. Scan for phishing emails with PDF/Excel/Word attachments
2. Analyze embedded links in documents
3. Detect government document impersonation
4. Identify Tencent Cloud links in attachments

### Fortinet Protection

#### Available Protections
- **FortiGuard Antivirus Signatures**:
  - XML/Agent.EFA9!tr
  - W64/ShellcodeRunner.ARG!tr
  - W64/Agent.BDN!tr

- **FortiGate**: Real-time threat detection and blocking
- **FortiMail**: Phishing email detection ("virus detected")
- **FortiClient**: Endpoint protection
- **FortiEDR**: Advanced endpoint detection and response
- **FortiSandbox**: Real-time anti-phishing, embedded in FortiMail and web filtering

#### Content Security
- **FortiGuard CDR**: Content Disarm and Reconstruction for malicious macros
- **IP Reputation Service**: Proactive blocking of malicious source IPs
- **Anti-Botnet Security**: Blocks C2 communications

### Mitigation Recommendations

#### Immediate Actions
1. **Block IOCs**: Implement blocking for all identified domains, IPs, and file hashes
2. **Email Filtering**: Enhance filtering for government document impersonation
3. **Endpoint Scanning**: Search for identified malicious files across environment
4. **Registry Auditing**: Check for HHClient registry keys on Windows systems

#### Short-Term Measures
1. **User Awareness Training**: Educate users on phishing tactics (Fortinet NSE FCF training)
2. **Attachment Scanning**: Implement strict scanning for PDF/Excel/Word attachments
3. **Cloud Storage Monitoring**: Monitor and control access to cloud storage platforms
4. **Task Scheduler Auditing**: Review scheduled tasks for anomalies

#### Long-Term Strategy
1. **Defense in Depth**: Implement layered security controls
2. **Threat Intelligence**: Subscribe to threat intelligence feeds for Asia-focused campaigns
3. **Incident Response**: Develop playbooks for multi-stage malware incidents
4. **Zero Trust**: Implement zero-trust architecture principles
5. **Application Whitelisting**: Control execution of unauthorized applications
6. **Privilege Management**: Limit user and application privileges

## Threat Intelligence Insights

### Campaign Connections
The threat actor demonstrates sophisticated operational planning through:
1. **Infrastructure Reuse**: Same Tencent Cloud accounts across multiple campaigns
2. **Code Reuse**: Identical JavaScript download page code
3. **Domain Patterns**: Consistent naming conventions (tw-prefix domains)
4. **C2 Sharing**: Same IP addresses used across different geographic campaigns
5. **Development Artifacts**: Debug paths reveal "HoldingHands-develop" project structure

### Evolution Indicators
- **March 2024 to January 2025**: Basic Winos 4.0 distribution
- **February 2025**: Transition to HoldingHands with enhanced capabilities
- **March-October 2025**: Advanced multi-stage execution and Task Scheduler abuse
- **Dynamic C2 Updates**: Recent addition shows ongoing development

### Future Predictions
1. **Geographic Expansion**: Likely to target additional Asia-Pacific countries
2. **Malware Evolution**: Continued development of HoldingHands capabilities
3. **Evasion Enhancement**: Further anti-analysis and anti-detection improvements
4. **Infrastructure Rotation**: Expected changes in domains and IPs (enabled by dynamic C2 update feature)

## Conclusion

The HoldingHands Asia Expansion Campaign represents a significant and evolving threat to organizations across the Asia-Pacific region. The threat actor demonstrates high sophistication through:

- Advanced multi-stage malware delivery and execution
- Systematic geographic expansion with localized social engineering
- Strong operational security with infrastructure reuse patterns
- Continuous malware development and capability enhancement
- Effective evasion techniques against security products

Organizations in the region should prioritize implementing the detection and mitigation strategies outlined in this analysis. The campaign's ongoing nature and expanding geographic footprint indicate that the threat actor remains active and capable.

**Immediate Priority Actions:**
1. Implement all provided IOCs in security controls
2. Enhance email security and user awareness
3. Deploy endpoint detection for Task Scheduler abuse
4. Monitor for registry modifications in HHClient keys
5. Review and harden Windows Task Scheduler configurations

## References

- Fortinet FortiGuard Labs: "Tracking Malware and Attack Expansion: A Hacker Group's Journey across Asia" (October 17, 2025)
  https://www.fortinet.com/blog/threat-research/tracking-malware-and-attack-expansion-a-hacker-groups-journey-across-asia

## Appendix

### Attack Flow Diagram Summary

```
[Phishing Email] 
    → [PDF/Excel/Word with Malicious Link]
        → [Download Page (JavaScript-based)]
            → [ZIP Archive Download]
                → [EXE with Legitimate Signature]
                    → [dokan2.dll Side-Loading]
                        → [sw.dat Execution]
                            → [TimeBrokerClient.dll via Task Scheduler]
                                → [msvchost.dat Shellcode]
                                    → [HoldingHands Payload in taskhostw.exe]
                                        → [C2 Communication]
                                            → [Data Exfiltration]
```

### Debug Path Artifacts
```
D:\Workspace\HoldingHands-develop\HoldingHands-develop\Door\x64\Release\BackDoor.pdb
```

### Command Line Indicators
```
C:\windows\system32\svchost.exe -k netsvcs -p -s Schedule
```

### API Calls of Interest
- VirtualAlloc (dynamic resolution via svchost.ini)
- WTSEnumerateSessions (session enumeration)
- CreateProcessAsUserW (user context execution)
- GetModuleHandleA (module base retrieval)

---

**Document Classification**: TLP:WHITE  
**Analysis Date**: October 18, 2025  
**Analyst**: ThreatOps-for-MISP  
**Version**: 1.0


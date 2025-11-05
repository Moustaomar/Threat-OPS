# Malvertising Certificate Abuse Campaign - Comprehensive Threat Analysis

## Executive Summary

On September 25, 2025, Conscia's Managed Detection and Response (MDR) team investigated a sophisticated malvertising campaign that attempted to compromise an enterprise endpoint through a fake Microsoft Teams installer. This campaign represents a significant evolution in threat actor tactics, combining **SEO poisoning, certificate abuse, and living-off-the-land techniques** to bypass traditional security controls.

The attack was successfully prevented by Microsoft Defender's Attack Surface Reduction (ASR) rules, which blocked suspicious outbound connections before the malware could establish command and control communication. This incident highlights both the sophistication of modern malvertising campaigns and the critical importance of behavioral-based endpoint protection.

## Campaign Overview

### Attack Vector
- **Primary Method**: Malvertising with SEO poisoning
- **Payload**: Fake Microsoft Teams installer (MSTeamsSetup.exe)
- **Infrastructure**: Cloudflare CDN hosting with short-lived certificates
- **Malware Family**: Oyster Backdoor (Broomstick/CleanUpLoader)

### Timeline of Events
| **Time**     | **Event**                                         | **Significance**                                            |
| ------------ | ------------------------------------------------- | ----------------------------------------------------------- |
| **13:42:28** | Navigation to www.bing.com                        | Search initiated                                            |
| **13:42:39** | Redirection to teams-install.icu                  | **11 seconds after search – indicating automated redirect** |
| **13:42:55** | HTTPS connection established to malicious domain  | Payload download initiated                                  |
| **14:20:21** | cleanmgr.exe creates DismHost.exe in Temp folders | Suspicious living-off-the-land activity                     |
| **14:39:00** | MSTeamsSetup.exe execution attempted              | Signed malware execution                                    |
| **14:39:15** | **ASR blocks C2 connection attempt**              | **Attack prevented – Alert triggered**                      |

## Technical Analysis

### Stage 1: Malvertising Vector

The campaign employed a sophisticated redirect chain:
**Bing Search → team.frywow.com → teams-install.icu**

#### Deception Techniques
1. **SEO Poisoning/Malvertising**: Malicious sites positioned in search results for Teams-related queries
2. **Domain Spoofing**: The domain "teams-install.icu" crafted to appear as a legitimate Microsoft property
3. **Infrastructure Masquerading**: All malicious domains hosted on Cloudflare (IP ranges: 104.21.x.x, 172.67.x.x), leveraging the CDN's reputation

#### Infrastructure Details
- **Primary Domain**: teams-install.icu
- **IP Addresses**: 172.67.154.95, 104.21.72.190
- **Hosting**: Cloudflare CDN
- **SSL Certificate**: Google Trust Services (WE1)
- **Certificate Validity**: September 24-26, 2025 (2 days only)
- **Domain Age**: Newly registered (typical of malicious campaigns)

### Stage 2: Certificate Abuse

The most sophisticated aspect of this campaign was the abuse of legitimate code-signing services:

#### MSTeamsSetup.exe Analysis
- **Digital Signature**: Valid and trusted
- **Signer**: "KUTTANADAN CREATIONS INC."
- **Certificate Chain**: Microsoft ID Verified CS EOC CA 01
- **Certificate Lifespan**: 2 days (September 24-26, 2025)
- **SHA256**: bd6ad2e1b62b2d0994adf322011f2a3afbb14f097efa3cbe741bc4c963e48889

#### Certificate Abuse Pattern
This represents an emerging threat pattern where actors:
- Obtain legitimate short-lived certificates to bypass signature-based security controls
- Minimize the window for certificate revocation
- Automate the signing process for multiple campaigns
- Exploit trust in signed executables

#### Related Certificate Signers
Research identified similar certificates being used in related campaigns:
- "Shanxi Yanghua HOME Furnishings Ltd"
- "Shanghai Ruikang Decoration Co"

### Stage 3: Malware Execution

#### Oyster Backdoor Capabilities
Based on threat intelligence correlation, this malware appears to be a variant of the Oyster backdoor, which includes:
- **Persistence Mechanisms**: Registry modifications, scheduled tasks
- **Data Collection**: File system enumeration, credential harvesting
- **Command Execution**: Remote command execution capabilities
- **Data Exfiltration**: C2 communication for data theft

#### Living-off-the-Land Activity
The campaign demonstrated sophisticated living-off-the-land techniques:
- **cleanmgr.exe**: Legitimate Windows utility used to create suspicious files
- **DismHost.exe**: Created in temporary folders for potential DLL side-loading
- **Process Hollowing**: Likely used for code injection

## Prevention Success

### Microsoft Defender ASR Intervention
**Successfully blocked C2 communication with:**
- nickbush24.com (primary C2)

### Prevented Activities
- Establishment of persistent backdoor access
- Potential data exfiltration
- Deployment of additional payloads
- Possible ransomware deployment

## Threat Intelligence

### Campaign Characteristics
- **Speed**: Modern malvertising can compromise users in under 15 seconds from search to infection
- **Stealth**: Certificate abuse bypasses traditional signature-based detection
- **Persistence**: Short-lived certificates minimize detection window
- **Scale**: Infrastructure suggests broader operation across multiple campaigns

### Attribution
While specific threat actor attribution is not available, the campaign characteristics suggest:
- **Sophisticated Operations**: Professional-grade infrastructure and techniques
- **Resource Availability**: Access to legitimate code-signing services
- **Technical Expertise**: Advanced living-off-the-land techniques
- **Financial Motivation**: Likely profit-driven rather than state-sponsored

## MITRE ATT&CK Framework Mapping

### Initial Access
- **T1566.001**: Spearphishing Attachment (fake Teams installer)
- **T1189**: Drive-by Compromise (malvertising redirect)

### Execution
- **T1059.001**: Command and Scripting Interpreter: PowerShell
- **T1055.012**: Process Injection: Process Hollowing

### Persistence
- **T1543.003**: Create/Modify System Process: Windows Service
- **T1547.001**: Registry Run Keys/Startup Folder
- **T1053**: Scheduled Task/Job

### Defense Evasion
- **T1027**: Obfuscated Files or Information
- **T1562.001**: Impair Defenses: Disable or Modify Tools
- **T1574.001**: DLL Side-Loading

### Command and Control
- **T1071.001**: Application Layer Protocol: Web Protocols

### Collection
- **T1003**: OS Credential Dumping
- **T1113**: Screen Capture

## Detection Recommendations

### Critical Detection Points

#### Certificate Anomaly Detection
- Alert on executables signed with certificates valid for ≤ 7 days
- Monitor for first-seen signers, especially for software installers
- Track certificates issued by "Microsoft ID Verified CS EOC CA 01"

#### Network-Based Detection
- Flag rapid redirects from search engines to newly registered domains
- Alert on downloads from domains with .icu TLDs
- Monitor connections to Cloudflare IPs immediately after search engine queries

#### Endpoint Detection
- Monitor for execution of cleanmgr.exe creating files in temp directories
- Alert on MSTeamsSetup.exe execution attempts
- Track certificate validation failures for short-lived certificates

### Microsoft XDR Hunting Queries

```kql
// Search for files signed by known malicious signers
DeviceFileCertificateInfo
| where Timestamp > ago(30d)
| where Signer has_any ("KUTTANADAN CREATIONS INC.", "Shanxi Yanghua HOME Furnishings Ltd", 
                       "Shanghai Ruikang Decoration Co")
| join kind=inner (DeviceFileEvents) on SHA1
| project Timestamp, DeviceName, FileName, FolderPath, Signer, SHA256, InitiatingProcessFileName
| sort by Timestamp desc

// Detect connections to known malicious domains
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any ("teams-install.icu", "nickbush24.com", "team.frywow.com")
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteUrl, 
          InitiatingProcessCommandLine
| sort by Timestamp desc

// Detect certificate abuse patterns
DeviceFileCertificateInfo
| where Timestamp > ago(30d)
| where CertificateNotAfter - CertificateNotBefore <= 7d
| where Signer contains "CREATIONS" or Signer contains "Furnishings" or Signer contains "Decoration"
| project Timestamp, DeviceName, FileName, Signer, CertificateNotBefore, CertificateNotAfter
| sort by Timestamp desc
```

## Mitigation Strategies

### Technical Controls
- **ASR Rules**: Ensure Microsoft Defender ASR rules are properly configured
- **Certificate Monitoring**: Implement certificate anomaly detection
- **Network Segmentation**: Isolate critical systems from internet access
- **Application Whitelisting**: Implement application control policies

### Administrative Controls
- **User Education**: Train users to recognize malvertising threats
- **Search Engine Security**: Use secure search practices
- **Software Installation**: Implement approval processes for software installation
- **Regular Updates**: Maintain current security patches

### Monitoring and Detection
- **Behavioral Analytics**: Implement user and entity behavior analytics (UEBA)
- **Threat Hunting**: Regular hunting for certificate abuse patterns
- **IOC Monitoring**: Continuous monitoring of campaign indicators
- **Incident Response**: Prepare response procedures for malvertising incidents

## Key Lessons Learned

1. **Living-off-the-Land Evolution**: Attackers continue finding creative ways to abuse legitimate Windows utilities
2. **ASR Rules Save the Day**: A properly configured Attack Surface Reduction policy can stop sophisticated attacks that bypass traditional antivirus
3. **Certificate Trust Is Not Absolute**: Short-lived certificates are being weaponized to evade security controls
4. **Speed of Attack**: Modern malvertising can compromise users in under 15 seconds from search to infection
5. **Infrastructure Abuse**: Legitimate services (Cloudflare, Google Trust Services) can be weaponized by threat actors

## Future Threat Landscape

### Emerging Trends
- **Certificate Abuse**: Increasing use of legitimate certificates for malicious purposes
- **CDN Weaponization**: Abuse of content delivery networks for hosting malicious content
- **Automated Campaigns**: Faster, more automated malvertising operations
- **Living-off-the-Land**: Continued abuse of legitimate system utilities

### Defensive Recommendations
- **Zero Trust Architecture**: Implement comprehensive zero trust security model
- **Behavioral Detection**: Focus on behavioral rather than signature-based detection
- **Certificate Intelligence**: Develop capabilities to detect certificate abuse patterns
- **User Training**: Continuous education on evolving threat landscape

## Conclusion

This malvertising campaign represents a significant evolution in threat actor tactics, demonstrating the weaponization of legitimate infrastructure and services. The successful prevention through Microsoft Defender ASR rules highlights the importance of behavioral-based endpoint protection in defending against sophisticated attacks.

Organizations must adapt their security strategies to address these evolving threats, focusing on:
- Behavioral detection over signature-based protection
- Certificate intelligence and anomaly detection
- User education and awareness
- Comprehensive incident response capabilities

The rapid evolution of these techniques—from SEO poisoning to certificate abuse to living-off-the-land tactics—demonstrates that security teams must continuously adapt their detection and prevention strategies to stay ahead of sophisticated threat actors.

---

**Analysis Date**: September 26, 2025  
**Threat Level**: High  
**Confidence Level**: High  
**Source**: [Conscia Blog - From SEO Poisoning to Malware Deployment: Malvertising campaign uncovered](https://conscia.com/blog/from-seo-poisoning-to-malware-deployment-malvertising-campaign-uncovered/)  
**Last Updated**: September 26, 2025

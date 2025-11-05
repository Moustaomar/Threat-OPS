# MISP Report - Malvertising Certificate Abuse Campaign

## Executive Summary

This MISP report documents the Malvertising Certificate Abuse campaign, a sophisticated malvertising operation that leverages SEO poisoning and certificate abuse to deliver fake Microsoft Teams installers. The campaign represents a significant evolution in threat actor tactics, combining malvertising with short-lived certificates to bypass traditional security controls.

## Campaign Overview

- **Campaign Name**: Malvertising Certificate Abuse Campaign
- **Threat Actor**: Unknown (sophisticated malvertising operation)
- **Attribution**: Unknown
- **Target**: Enterprise endpoints
- **Threat Level**: High
- **Date**: September 26, 2025

## Threat Intelligence Summary

### Primary Attack Vector
- **Delivery Method**: Malvertising with SEO poisoning
- **Payload**: Fake Microsoft Teams installer (MSTeamsSetup.exe)
- **Infrastructure**: Cloudflare CDN hosting with short-lived certificates
- **Malware Family**: Oyster Backdoor (Broomstick/CleanUpLoader)

### Key Indicators of Compromise (IOCs)

#### Network Indicators
- **teams-install.icu** - Malicious payload delivery site
- **team.frywow.com** - Redirect/gate infrastructure
- **witherspoon-law.com** - Redirect/gate infrastructure
- **nickbush24.com** - C2 Server
- **172.67.154.95** - teams-install.icu IP (Cloudflare CDN)
- **104.21.72.190** - teams-install.icu IP (Cloudflare CDN)

#### File Indicators
- **MSTeamsSetup.exe** - Malicious executable
- **SHA256**: bd6ad2e1b62b2d0994adf322011f2a3afbb14f097efa3cbe741bc4c963e48889

#### Certificate Information
- **Signer**: KUTTANADAN CREATIONS INC.
- **Certificate Chain**: Microsoft ID Verified CS EOC CA 01
- **Certificate Validity**: September 24-26, 2025 (2 days only)
- **Certificate Authority**: Google Trust Services (WE1)

#### Related Certificate Signers
- **KUTTANADAN CREATIONS INC.**
- **Shanxi Yanghua HOME Furnishings Ltd**
- **Shanghai Ruikang Decoration Co**

## Technical Analysis

### Attack Timeline
- **13:42:28** - Navigation to www.bing.com
- **13:42:39** - Redirection to teams-install.icu (11 seconds after search)
- **13:42:55** - HTTPS connection established to malicious domain
- **14:20:21** - cleanmgr.exe creates DismHost.exe in Temp folders
- **14:39:00** - MSTeamsSetup.exe execution attempted
- **14:39:15** - ASR blocks C2 connection attempt

### Malvertising Vector
- **Bing Search → team.frywow.com → teams-install.icu**
- **SEO Poisoning**: Malicious sites positioned in search results
- **Domain Spoofing**: Domain crafted to appear as legitimate Microsoft property
- **Infrastructure Masquerading**: All domains hosted on Cloudflare CDN

### Certificate Abuse Pattern
- **Short-lived Certificates**: 2-3 day validity periods
- **Legitimate Signing**: Valid and trusted digital signatures
- **Automated Signing**: Process for multiple campaigns
- **Trust Exploitation**: Bypassing signature-based security controls

### Prevention Success
- **Microsoft Defender ASR**: Successfully blocked C2 communication
- **Prevented Activities**: Backdoor access, data exfiltration, additional payloads
- **Key Lesson**: Behavioral-based protection effective against certificate abuse

## MITRE ATT&CK Mapping

### Initial Access
- **T1566.001**: Spearphishing Attachment
- **T1189**: Drive-by Compromise

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

### Exfiltration
- **T1041**: Exfiltration Over C2 Channel
- **T1567.002**: Exfiltration Over Web Service: To Cloud Storage

## Detection Recommendations

### Certificate Anomaly Detection
- Alert on executables signed with certificates valid for ≤ 7 days
- Monitor for first-seen signers, especially for software installers
- Track certificates issued by "Microsoft ID Verified CS EOC CA 01"

### Network-Based Detection
- Flag rapid redirects from search engines to newly registered domains
- Alert on downloads from domains with .icu TLDs
- Monitor connections to Cloudflare IPs immediately after search engine queries

### Endpoint Detection
- Monitor for execution of cleanmgr.exe creating files in temp directories
- Alert on MSTeamsSetup.exe execution attempts
- Track certificate validation failures for short-lived certificates

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

## MISP Event Details

### Event Information
- **Event ID**: Malvertising_Certificate_Abuse_Campaign
- **Date**: 2025-09-26
- **Threat Level**: High (1)
- **Published**: False
- **Attribute Count**: 15

### Key Attributes
- **Network Indicators**: 4 domains, 2 IP addresses, 3 URLs
- **File Indicators**: 1 executable, 1 SHA256 hash
- **Certificate Information**: 4 certificate-related attributes
- **Infrastructure**: 1 hosting provider, 1 CDN

### Tags Applied
- **Malware**: Oyster, Broomstick, CleanUpLoader
- **Tools**: Microsoft Teams, Cloudflare, Google Trust Services
- **MITRE ATT&CK**: 6 technique mappings

## Conclusion

The Malvertising Certificate Abuse campaign represents a significant evolution in threat actor tactics, demonstrating the weaponization of legitimate infrastructure and services. The successful prevention through Microsoft Defender ASR rules highlights the importance of behavioral-based endpoint protection.

Organizations must adapt their security strategies to address these evolving threats, focusing on behavioral detection over signature-based protection, certificate intelligence, user education, and comprehensive incident response capabilities.

---

**Report Date**: September 26, 2025  
**Threat Level**: High  
**Confidence Level**: High  
**Source**: [Conscia Blog - From SEO Poisoning to Malware Deployment: Malvertising campaign uncovered](https://conscia.com/blog/from-seo-poisoning-to-malware-deployment-malvertising-campaign-uncovered/)  
**Last Updated**: September 26, 2025

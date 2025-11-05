# APT35 Phishing Campaign - MISP Event Summary

## Event Overview
- **Event ID**: APT35-Phishing-2025-001
- **Date**: 2025-09-26
- **Threat Level**: High (1)
- **Analysis Status**: Complete (2)
- **Attribute Count**: 87
- **TLP**: Amber

## Executive Summary

This MISP event contains comprehensive intelligence on APT35's sophisticated phishing infrastructure targeting video conferencing platforms. The event includes 87 attributes covering infrastructure, domains, URLs, and technical indicators, providing SOC teams and threat hunters with actionable intelligence for detection and response.

## Key Intelligence Highlights

### 🎯 **Threat Actor**: APT35 (Mint Sandstorm/Charming Kitten/Educated Manticore)
- **Affiliation**: Islamic Revolutionary Guard Corps (IRGC)
- **Country**: Iran
- **Activity**: Since 2015, active through 2025
- **Objectives**: Espionage, surveillance, credential harvesting

### 🌐 **Infrastructure Analysis**
- **Primary Servers**: 2 IP addresses across 2 ASNs
- **Domain Count**: 65+ phishing domains
- **TLD Focus**: Primarily .online domains
- **Pattern**: viliam.*.online subdomain structure
- **Impersonation**: Google Meet, video conferencing platforms

### 🎯 **Targeting Intelligence**
- **Geographic**: Sweden, Israel, US, Middle East, Europe
- **Sectors**: Government, military, media, academic, international organizations
- **Victims**: High-value individuals, decision makers, technical personnel

## Attribute Breakdown

### Network Infrastructure (4 attributes)
- **IP Addresses**: 2 (79.132.131.184, 84.200.193.20)
- **ASNs**: 2 (39378 SERVINGA, 214036 Ultahost)
- **Confidence**: High for all infrastructure indicators

### Domain Intelligence (65+ attributes)
- **Phishing Domains**: 65+ domains with .online TLD
- **Subdomain Pattern**: viliam.*.online structure
- **Impersonation Targets**: Google Meet, video conferencing services
- **Confidence**: High for all domain indicators

### URL Intelligence (9 attributes)
- **Landing Pages**: 4 phishing landing pages
- **Invitation URLs**: 5 URLs with invitation parameters
- **Geographic Attribution**: Sweden, Israel submission sources
- **Timeline**: July-September 2025 activity

### Technical Indicators (9 attributes)
- **SSDeep Hashes**: 2 for hunting queries
- **Pattern Recognition**: 4 text patterns for detection
- **User Agent**: Common browser patterns
- **HTTP Methods**: GET requests for infrastructure

## MITRE ATT&CK Mapping

### Initial Access
- **T1566.002**: Spearphishing Link
- **T1189**: Drive-by Compromise
- **T1204**: User Execution

### Infrastructure
- **T1583.001**: Acquire Infrastructure - Domains
- **T1584.001**: Compromise Infrastructure - Domains
- **T1071.001**: Web Protocols

### Persistence & Evasion
- **T1059.007**: JavaScript
- **T1566**: Phishing

## Operational Value

### 🛡️ **Detection Capabilities**
- **SIEM Rules**: Ready-to-use detection rules
- **Hunting Queries**: SilentPush and VirusTotal queries
- **YARA Rules**: Pattern-based detection
- **Network Monitoring**: Infrastructure communication detection

### 🔍 **Threat Hunting**
- **Infrastructure Hunting**: ASN and IP-based searches
- **Domain Hunting**: Pattern-based domain discovery
- **Behavioral Hunting**: User agent and URL pattern analysis
- **Timeline Analysis**: Campaign evolution tracking

### 📊 **Intelligence Sharing**
- **TLP:Amber**: Appropriate for trusted partner sharing
- **Structured Data**: MISP-compatible format
- **Rich Context**: Detailed comments and source attribution
- **Confidence Scoring**: Risk-based prioritization

## Hunting Queries

### SilentPush (High Confidence)
```
datasource = ["webscan"] AND html_body_ssdeep = "*Ve1LTG7faKjubGga" AND html_body_ssdeep = "6:q9hqIY0gYkC/fAbplGMuzT6palUvN*"
```

### VirusTotal
```
entity:domain domain:viliam.*
entity:url url:online/?invitation
```

### SIEM Rules
```yaml
# APT35 Phishing Domain Detection
- name: APT35 Phishing Domain Access
  condition: |
    domain matches /.*\.online$/ AND
    (subdomain contains "viliam" OR subdomain contains "meet") AND
    url contains "invitation"
  severity: high
  tags: [apt35, phishing, video-conferencing]
```

## Recommended Actions

### Immediate (0-24 hours)
1. **Block Infrastructure**: Add all IPs and domains to blocklists
2. **Monitor Traffic**: Watch for communications to APT35 infrastructure
3. **User Awareness**: Alert users to video conferencing phishing tactics
4. **Credential Reset**: Reset credentials if compromise suspected

### Short-term (1-7 days)
1. **Threat Hunting**: Search for additional APT35 infrastructure
2. **Incident Response**: Develop APT35-specific response procedures
3. **Intelligence Sharing**: Share with trusted partners
4. **Security Controls**: Implement advanced phishing protection

### Long-term (1-4 weeks)
1. **Continuous Monitoring**: Ongoing infrastructure tracking
2. **Campaign Analysis**: Monitor campaign evolution
3. **Intelligence Requirements**: Develop APT35-specific intelligence needs
4. **Training**: User awareness and security team training

## Confidence Assessment

### High Confidence (90-100%)
- Infrastructure IPs and ASNs
- Confirmed phishing domains
- Behavioral patterns
- Attribution to APT35

### Medium Confidence (70-89%)
- Source contacts
- Technical indicators
- Geographic attribution
- Timeline analysis

### Low Confidence (50-69%)
- Future campaign predictions
- Victim impact assessment
- Attribution to specific individuals
- Campaign end dates

## Intelligence Gaps

### Known Gaps
- **Victim Impact**: Limited information on successful compromises
- **Campaign Scope**: Unknown total number of targets
- **Malware**: No malware samples identified
- **C2 Infrastructure**: Limited C2 communication analysis

### Intelligence Requirements
- **Victim Notification**: Identify and notify potential victims
- **Campaign Tracking**: Monitor for new infrastructure
- **Behavioral Analysis**: Understand targeting patterns
- **Impact Assessment**: Evaluate campaign effectiveness

## Contact Information

**Threat Intelligence Team**
- **Email**: threatintel@organization.com
- **TLP**: Amber
- **Last Updated**: 2025-09-26
- **Next Review**: 2025-10-26

---

*This MISP event is classified as TLP:Amber and should be shared only with trusted partners and stakeholders. For questions or additional intelligence, contact the Threat Intelligence Team.*

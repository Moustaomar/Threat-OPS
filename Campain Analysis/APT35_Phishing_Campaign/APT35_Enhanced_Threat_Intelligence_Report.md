# APT35 (Mint Sandstorm/Charming Kitten/Educated Manticore): Enhanced Threat Intelligence Report

## Executive Summary

**APT35** (also known as **Mint Sandstorm**, **Charming Kitten**, **Educated Manticore**) is an Iranian state-sponsored advanced persistent threat (APT) group affiliated with the Islamic Revolutionary Guard Corps (IRGC). This report details their sophisticated phishing infrastructure targeting video conferencing platforms, with a focus on impersonating legitimate services to harvest credentials and conduct espionage operations.

### Key Intelligence Points
- **Threat Actor**: APT35 (Iranian state-sponsored)
- **Campaign**: Video Conferencing Phishing Infrastructure
- **Targets**: Government, military, media, academic, and international organizations
- **Geographic Focus**: US, Middle East, Europe
- **TTPs**: Social engineering, domain impersonation, credential harvesting
- **Infrastructure**: 65+ domains across 2 ASNs, active since July 2025

---

## Threat Actor Profile

### APT35 (Mint Sandstorm/Charming Kitten/Educated Manticore)
- **Affiliation**: Islamic Revolutionary Guard Corps (IRGC)
- **Country**: Iran
- **Activity Period**: Since 2015, active through 2025
- **Primary Objectives**: Espionage, surveillance, credential harvesting
- **Target Sectors**: Government, military, media, academic, international organizations

### Historical Context
APT35 has been active since at least 2015, conducting long-term espionage and surveillance operations. The group is known for:
- Sophisticated social engineering campaigns
- Multi-stage phishing operations
- Infrastructure persistence and adaptation
- Targeting high-value individuals and organizations

---

## Campaign Analysis

### Campaign Overview
**Campaign Name**: APT35 Video Conferencing Phishing Campaign 2025
**Start Date**: July 2025
**Status**: Active
**Infrastructure**: 2 primary servers, 65+ domains

### Tactics, Techniques, and Procedures (TTPs)

#### Initial Access
- **T1566.002 - Spearphishing Link**: Targeted phishing emails with malicious links
- **T1189 - Drive-by Compromise**: Malicious websites designed to harvest credentials
- **T1204 - User Execution**: Social engineering to trick users into visiting malicious sites

#### Infrastructure
- **T1583.001 - Acquire Infrastructure - Domains**: Registration of lookalike domains
- **T1584.001 - Compromise Infrastructure - Domains**: Use of legitimate-looking domains
- **T1071.001 - Web Protocols**: HTTP/HTTPS communication for credential harvesting

#### Persistence & Evasion
- **T1059.007 - JavaScript**: Client-side execution for credential harvesting
- **T1566 - Phishing**: Continuous social engineering operations

### Infrastructure Analysis

#### Primary Servers
1. **79.132.131.184** (AS 39378 SERVINGA)
   - Hosts 49 domains with .online TLD
   - Active since July 20, 2025
   - Geographic distribution: Sweden, Israel

2. **84.200.193.20** (AS 214036 Ultahost, Inc.)
   - Limited domain hosting (2-12 days)
   - Single active domain: rohand63.xyz

#### Domain Patterns
- **TLD Focus**: Primarily .online domains
- **Subdomain Pattern**: viliam.*.online
- **Impersonation Targets**: Google Meet, video conferencing platforms
- **Naming Convention**: Legitimate-looking service names

### Targeting Analysis

#### Geographic Targeting
- **Primary**: Sweden, Israel
- **Secondary**: US, Middle East, Europe
- **Method**: Country-specific domain registration and hosting

#### Sector Targeting
- Government organizations
- Military entities
- Media companies
- Academic institutions
- International organizations

#### Victimology
- High-value individuals
- Decision makers
- Technical personnel
- International contacts

---

## Technical Indicators

### Infrastructure Indicators
- **IP Addresses**: 79.132.131.184, 84.200.193.20
- **ASNs**: 39378 (SERVINGA), 214036 (Ultahost)
- **Domain Pattern**: *.online TLD with viliam subdomains
- **Impersonation**: Google Meet, video conferencing services

### Behavioral Indicators
- **Landing Page**: Four colored dots loading animation
- **JavaScript Requirement**: "You need to enable JavaScript to run this app"
- **URL Parameters**: invitation-based tracking parameters
- **User Agent**: Standard browser patterns

### Hunting Queries

#### SilentPush Query (High Confidence)
```
datasource = ["webscan"] AND html_body_ssdeep = "*Ve1LTG7faKjubGga" AND html_body_ssdeep = "6:q9hqIY0gYkC/fAbplGMuzT6palUvN*"
```

#### VirusTotal Queries
```
entity:domain domain:viliam.*
entity:url url:online/?invitation
```

#### YARA Rules
```yara
rule APT35_Phishing_Infrastructure {
    meta:
        description = "Detects APT35 phishing infrastructure patterns"
        author = "Threat Intelligence Team"
        date = "2025-09-26"
    
    strings:
        $s1 = "You need to enable JavaScript to run this app."
        $s2 = "blue ball red ball yellow ball green ball"
        $s3 = "viliam"
        $s4 = "invitation"
    
    condition:
        2 of them
}
```

---

## Detection and Mitigation

### Detection Rules

#### SIEM Rules
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

#### Network Detection
```yaml
# APT35 Infrastructure Communication
- name: APT35 Infrastructure Communication
  condition: |
    destination_ip in [79.132.131.184, 84.200.193.20] OR
    destination_domain matches /.*\.online$/ AND
    user_agent contains "Mozilla"
  severity: medium
  tags: [apt35, infrastructure]
```

### Mitigation Strategies

#### Technical Controls
1. **DNS Filtering**: Block .online domains with viliam subdomains
2. **Web Proxy**: Filter requests to known APT35 infrastructure
3. **Email Security**: Enhanced phishing detection for video conferencing links
4. **User Training**: Awareness of video conferencing phishing tactics

#### Operational Controls
1. **Threat Hunting**: Regular searches for APT35 infrastructure
2. **Incident Response**: Procedures for credential compromise
3. **Intelligence Sharing**: TLP:Amber sharing with trusted partners
4. **Continuous Monitoring**: Ongoing infrastructure tracking

---

## Operational Recommendations

### Immediate Actions
1. **Block Infrastructure**: Add all identified IPs and domains to blocklists
2. **Monitor Communications**: Watch for traffic to APT35 infrastructure
3. **User Awareness**: Train users on video conferencing phishing tactics
4. **Credential Reset**: Reset credentials if compromise suspected

### Long-term Strategies
1. **Threat Hunting**: Regular searches for new APT35 infrastructure
2. **Intelligence Sharing**: Participate in threat intelligence sharing
3. **Security Controls**: Implement advanced phishing protection
4. **Incident Response**: Develop APT35-specific response procedures

### Intelligence Requirements
1. **Infrastructure Monitoring**: Track new domain registrations
2. **Behavioral Analysis**: Monitor for APT35 TTPs
3. **Victim Notification**: Alert potential targets
4. **Campaign Tracking**: Monitor campaign evolution

---

## Attribution and Confidence

### Attribution Confidence: High
- **Infrastructure**: Consistent with known APT35 patterns
- **TTPs**: Align with historical APT35 operations
- **Geographic**: Matches APT35 targeting patterns
- **Timeline**: Consistent with APT35 activity cycles

### Intelligence Confidence
- **Infrastructure IOCs**: High confidence
- **Behavioral Patterns**: High confidence
- **Attribution**: High confidence
- **TTPs**: High confidence

---

## References and Sources

### Primary Sources
- Stormshield Customer Security Lab: "APT35 plays the same music again"
- SilentPush Platform: Infrastructure hunting queries
- VirusTotal: Domain and URL analysis
- URLScan.io: Landing page analysis

### Additional Intelligence
- MITRE ATT&CK Framework
- MISP Threat Intelligence Platform
- Open Source Intelligence (OSINT)
- Commercial Threat Intelligence Feeds

---

## Contact Information

**Threat Intelligence Team**
- Email: threatintel@organization.com
- TLP: Amber
- Last Updated: 2025-09-26
- Next Review: 2025-10-26

---

*This report is classified as TLP:Amber and should be shared only with trusted partners and stakeholders.*

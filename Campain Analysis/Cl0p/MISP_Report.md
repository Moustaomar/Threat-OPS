# Cl0p Ransomware Group - Complete Final Threat Intelligence (2019-2025) - All IOCs

## Event Summary
- **Event ID**: 6124556
- **Date**: 2025-10-14
- **Last Update**: 2025-10-14 09:56:01
- **Threat Level**: High (1)
- **Published**: No
- **Attribute Count**: 616
- **Analysis Level**: Complete
- **Distribution**: TLP:Amber

## Threat Actor Profile
- **Name**: Cl0p (Clop)
- **Type**: Ransomware-as-a-Service (RaaS)
- **First Observed**: 2019
- **Active**: Yes
- **Target Industries**: Healthcare, Education, Government, Finance, Technology
- **Geographic Focus**: Global
- **Attack Vectors**: Phishing, Exploit Kits, RDP Brute Force, Zero-day Exploits
- **Primary TTPs**: Data Exfiltration, Double Extortion, Ransomware Deployment

## Campaign Overview
This comprehensive threat intelligence report covers the complete Cl0p ransomware group activity from 2019 to 2025, including:
- **616 Indicators of Compromise (IOCs)**
- **Network Infrastructure**: 178 IP addresses, 28 domains, 3 URLs
- **Malware Samples**: 145 SHA256, 129 MD5, 129 SHA1 hashes
- **Associated Malware**: LEMURLOOT, Truebot, AdFind
- **Data Leak Sites**: Multiple Tor onion services
- **Phishing Infrastructure**: Sophisticated domain spoofing campaigns

## Indicator Categories

### Network Infrastructure (209 indicators)
- **URLs**: 3 (Data leak sites, payload delivery)
- **Domains**: 28 (Phishing domains, onion services)
- **IP Addresses**: 178 (C2 servers, infrastructure)

### Malware Artifacts (407 indicators)
- **SHA256 Hashes**: 145 (Primary malware samples)
- **MD5 Hashes**: 129 (Legacy hash support)
- **SHA1 Hashes**: 129 (Legacy hash support)
- **Filenames**: 4 (Specific malware files)

## Associated Malware Families
- **Cl0p Ransomware**: Primary payload
- **LEMURLOOT**: Data exfiltration tool
- **Truebot**: Initial access loader
- **AdFind**: Active Directory reconnaissance tool

## MITRE ATT&CK Framework Mapping
This campaign demonstrates techniques across multiple ATT&CK tactics:

### Initial Access
- **T1078**: Valid Accounts
- **T1190**: Exploit Public-Facing Application
- **T1566**: Phishing

### Execution
- **T1059**: Command and Scripting Interpreter
- **T1204**: User Execution
- **T1047**: Windows Management Instrumentation

### Persistence
- **T1543**: Create or Modify System Process
- **T1547**: Boot or Logon Autostart Execution
- **T1053**: Scheduled Task/Job

### Defense Evasion
- **T1546**: Event Triggered Execution
- **T1574**: Hijack Execution Flow

### Credential Access
- **T1003**: OS Credential Dumping

### Discovery
- **T1057**: Process Discovery
- **T1083**: File and Directory Discovery

### Lateral Movement
- **T1021**: Remote Services

### Collection
- **T1074**: Data Staged
- **T1213**: Data from Information Repositories
- **T1114**: Email Collection

### Command and Control
- **T1071**: Application Layer Protocol
- **T1105**: Ingress Tool Transfer

### Exfiltration
- **T1041**: Exfiltration Over C2 Channel

### Impact
- **T1486**: Data Encrypted for Impact
- **T1490**: Inhibit System Recovery

## Detection Recommendations

### Network Monitoring
- Monitor for connections to identified C2 IP addresses and domains
- Implement DNS sinkholing for identified malicious domains
- Monitor for Tor traffic patterns matching data leak site access
- Set up alerts for suspicious domain registrations (typosquatting patterns)

### Endpoint Detection
- Deploy YARA rules for Cl0p ransomware signatures
- Monitor for execution of identified malware hashes
- Implement behavioral detection for file encryption activities
- Monitor for PowerShell execution with suspicious parameters

### Email Security
- Implement advanced phishing detection for identified patterns
- Monitor for suspicious attachment types and macros
- Deploy URL reputation filtering for identified domains

## YARA Rules
```yara
rule Cl0p_Ransomware {
    meta:
        description = "Detects Cl0p ransomware samples"
        author = "ThreatOps Team"
        date = "2025-10-14"
        reference = "https://github.com/ThreatOps-for-MISP"
    
    strings:
        $s1 = "Cl0p" ascii
        $s2 = "clop" ascii
        $s3 = "CL0P" ascii
        $s4 = ".clop" ascii
        $s5 = "clop@tutanota.com" ascii
    
    condition:
        2 of them
}
```

## Sigma Rules
- Monitor for PowerShell execution with suspicious parameters
- Detect file encryption activities
- Monitor for network connections to C2 infrastructure
- Alert on suspicious domain registrations

## IOCs Summary

### High-Confidence Indicators
- **Data Leak Sites**: 3 Tor onion services
- **Primary C2 Infrastructure**: 178 IP addresses
- **Phishing Domains**: 28 domains with typosquatting patterns
- **Malware Samples**: 145 SHA256 hashes with high confidence

### Medium-Confidence Indicators
- **Legacy Hash Support**: 129 MD5 and 129 SHA1 hashes
- **Associated Tools**: AdFind, PowerShell scripts
- **File Artifacts**: 4 specific malware filenames

## Threat Intelligence Feeds
This event correlates with multiple threat intelligence sources:
- MalwareBazaar samples (2021-2025)
- ThreatFox IOCs (2022-2025)
- OSINT security advisories
- CTM360 observables
- Oracle security alerts

## Recommended Actions
1. **Immediate**: Block all identified IP addresses and domains
2. **Short-term**: Deploy YARA rules and Sigma detection rules
3. **Long-term**: Implement behavioral detection for ransomware activities
4. **Ongoing**: Monitor for new Cl0p infrastructure and TTPs

## Technical Details

### File Structure
- **MISP Event JSON**: `Cl0p_Complete_Final_MISP_Event.json` (616 attributes)
- **IOC Text File**: `Cl0p_Updated_IOCs.txt` (Organized by category)
- **Original IOCs**: `All IOCs.txt` (Source data)

### MISP Event Details
- **Event UUID**: Auto-generated by MISP
- **Attribute Count**: 616 total indicators
- **Distribution**: TLP:Amber
- **Threat Level**: High (1)
- **Analysis Level**: Complete
- **Date**: 2025-10-14

### Data Quality
- **High Confidence**: 209 network indicators (IPs, domains, URLs)
- **Medium Confidence**: 407 malware artifacts (hashes, filenames)
- **Source Verification**: Multiple threat intelligence feeds
- **Last Updated**: 2025-10-14 09:56:01

### MISP Integration
This event is fully compatible with MISP instances and includes:
- Proper attribute categorization
- MITRE ATT&CK technique mapping
- Galaxy tag associations
- Correlation with other threat intelligence events
- Export-ready JSON format

## Contact Information
- **Analyst**: ThreatOps Team
- **Organization**: ThreatOps-for-MISP
- **Email**: Contact through GitHub repository
- **Repository**: https://github.com/ThreatOps-for-MISP

## Tags
  - @[tag](tlp:amber)
  - @[tag](type:OSINT)
  - @[tag](misp:threat-level="high")
  - @[tag](misp-galaxy:threat-actor="Cl0p")
  - @[tag](misp-galaxy:malware="Cl0p Ransomware")
  - @[tag](misp-galaxy:malware="LEMURLOOT")
  - @[tag](misp-galaxy:malware="Truebot")
  - @[tag](misp-galaxy:tool="AdFind")
  - @[tag](misp-galaxy:tool="PowerShell")
#### Galaxies
  - *Name*: Attack Pattern
  - *Description*: ATT&CK Tactic
    - @[tag](misp-galaxy:mitre-attack-pattern="Valid Accounts - T1078")
    - @[tag](misp-galaxy:mitre-attack-pattern="Domain Accounts - T1078.002")
    - @[tag](misp-galaxy:mitre-attack-pattern="Local Accounts - T1078.003")
    - @[tag](misp-galaxy:mitre-attack-pattern="Exploit Public-Facing Application - T1190")
    - @[tag](misp-galaxy:mitre-attack-pattern="Phishing - T1566")
    - @[tag](misp-galaxy:mitre-attack-pattern="Spearphishing Attachment - T1566.001")
    - @[tag](misp-galaxy:mitre-attack-pattern="Spearphishing Link - T1566.002")
    - @[tag](misp-galaxy:mitre-attack-pattern="Command and Scripting Interpreter - T1059")
    - @[tag](misp-galaxy:mitre-attack-pattern="PowerShell - T1059.001")
    - @[tag](misp-galaxy:mitre-attack-pattern="Windows Command Shell - T1059.003")
    - @[tag](misp-galaxy:mitre-attack-pattern="Unix Shell - T1059.004")
    - @[tag](misp-galaxy:mitre-attack-pattern="Visual Basic - T1059.005")
    - @[tag](misp-galaxy:mitre-attack-pattern="JavaScript - T1059.007")
    - @[tag](misp-galaxy:mitre-attack-pattern="User Execution - T1204")
    - @[tag](misp-galaxy:mitre-attack-pattern="Malicious Link - T1204.001")
    - @[tag](misp-galaxy:mitre-attack-pattern="Malicious File - T1204.002")
    - @[tag](misp-galaxy:mitre-attack-pattern="Windows Management Instrumentation - T1047")
    - @[tag](misp-galaxy:mitre-attack-pattern="Native API - T1106")
    - @[tag](misp-galaxy:mitre-attack-pattern="Shared Modules - T1129")
    - @[tag](misp-galaxy:mitre-attack-pattern="Create or Modify System Process - T1543")
    - @[tag](misp-galaxy:mitre-attack-pattern="Windows Service - T1543.003")
    - @[tag](misp-galaxy:mitre-attack-pattern="Boot or Logon Autostart Execution - T1547")
    - @[tag](misp-galaxy:mitre-attack-pattern="Registry Run Keys / Startup Folder - T1547.001")
    - @[tag](misp-galaxy:mitre-attack-pattern="Scheduled Task/Job - T1053")
    - @[tag](misp-galaxy:mitre-attack-pattern="Scheduled Task - T1053.005")
    - @[tag](misp-galaxy:mitre-attack-pattern="Create Account - T1136")
    - @[tag](misp-galaxy:mitre-attack-pattern="Local Account - T1136.001")
    - @[tag](misp-galaxy:mitre-attack-pattern="Server Software Component - T1505")
    - @[tag](misp-galaxy:mitre-attack-pattern="Web Shell - T1505.003")
    - @[tag](misp-galaxy:mitre-attack-pattern="Event Triggered Execution - T1546")
    - @[tag](misp-galaxy:mitre-attack-pattern="Unix Shell Configuration Modification - T1546.004")
    - @[tag](misp-galaxy:mitre-attack-pattern="Application Shimming - T1546.011")
    - @[tag](misp-galaxy:mitre-attack-pattern="Hijack Execution Flow - T1574")
    - @[tag](misp-galaxy:mitre-attack-pattern="OS Credential Dumping - T1003")
    - @[tag](misp-galaxy:mitre-attack-pattern="LSASS Memory - T1003.001")
    - @[tag](misp-galaxy:mitre-attack-pattern="Process Discovery - T1057")
    - @[tag](misp-galaxy:mitre-attack-pattern="File and Directory Discovery - T1083")
    - @[tag](misp-galaxy:mitre-attack-pattern="Remote Services - T1021")
    - @[tag](misp-galaxy:mitre-attack-pattern="SMB/Windows Admin Shares - T1021.002")
    - @[tag](misp-galaxy:mitre-attack-pattern="Data Staged - T1074")
    - @[tag](misp-galaxy:mitre-attack-pattern="Data from Information Repositories - T1213")
    - @[tag](misp-galaxy:mitre-attack-pattern="Email Collection - T1114")
    - @[tag](misp-galaxy:mitre-attack-pattern="Application Layer Protocol - T1071")
    - @[tag](misp-galaxy:mitre-attack-pattern="Web Protocols - T1071.001")
    - @[tag](misp-galaxy:mitre-attack-pattern="Ingress Tool Transfer - T1105")
    - @[tag](misp-galaxy:mitre-attack-pattern="Exfiltration Over C2 Channel - T1041")
    - @[tag](misp-galaxy:mitre-attack-pattern="Data Encrypted for Impact - T1486")
    - @[tag](misp-galaxy:mitre-attack-pattern="Inhibit System Recovery - T1490")
  - *Name*: Ransomware
  - *Description*: Ransomware galaxy based on https://docs.google.com/spreadsheets/d/1TWS238xacAto-fLKh1n5uTsdijWdCEsGIM0Y0Hvmc5g/pubhtml
    - @[tag](misp-galaxy:ransomware="Clop")
#### Correlations
  - Oracle CVE-2025-61882: Cl0p & Scattered LAPSUS$ Hunters exploitation campaign (Oracle EBS RCE, data theft attacks)
  - Cl0p Ransomware Group - Comprehensive Threat Intelligence (2019-2025)
  - MalwareBazaar malware samples for 2025-10-09
  - OSINT - Oracle Security Alert Advisory - CVE-2025-61882
  - CTM360 Observables - 2025-10-06 (5 indicators)
  - Cl0p Ransomware Group: Complete IOC Collection (2019-2025) - All Infrastructure, Domains, Hashes, and TTPs
  - Cl0p Ransomware Group: 2019-2025 activity and infrastructure (LEMURLOOT, Truebot, data leak sites, zero-day exploits)
  - ThreatFox IOCs for 2025-08-11
  - ThreatFox IOCs for 2025-04-15
  - MalwareBazaar malware samples for 2025-03-16
  - ThreatFox IOCs for 2025-02-10
  - OSINT - Threat Advisory: Oh No Cleo! Cleo Software Actively Being Exploited in the Wild
  - ThreatFox IOCs for 2024-09-01
  - ThreatFox IOCs for 2024-07-03
  - ThreatFox IOCs for 2024-04-26
  - ThreatFox IOCs for 2024-04-25
  - ThreatFox IOCs for 2024-04-02
  - ThreatFox IOCs for 2024-03-05
  - MalwareBazaar malware samples for 2024-01-27
  - ThreatFox IOCs for 2023-12-27
  - MalwareBazaar malware samples for 2023-11-14
  - MalwareBazaar malware samples for 2023-06-06
  - MalwareBazaar malware samples for 2023-05-24
  - ThreatFox IOCs for 2023-05-23
  - ThreatFox IOCs for 2023-05-20
  - MalwareBazaar malware samples for 2023-04-16
  - ThreatFox IOCs for 2023-04-13
  - ThreatFox IOCs for 2023-03-23
  - MalwareBazaar malware samples for 2023-02-09
  - MalwareBazaar malware samples for 2022-10-13
  - Scraper: Talos Website
  - ThreatFox IOCs for 2022-06-23
  - MalwareBazaar malware samples for 2022-04-12
  - MalwareBazaar malware samples for 2022-03-25
  - MalwareBazaar malware samples for 2021-04-27
  - SectorJ04 Groupâ€™s Increased Activity in 2019
  - OSINT - Kernel Mode Malicious Loader
### Objects
### Attributes
  - @[attribute](e4f77e9a-ace7-4017-afbd-3fa2f4cdc09a)
  - @[attribute](62d0de49-8947-44bf-9000-63876cfaa00f)
  - @[attribute](8366b66e-c00b-4e46-afb2-d630a058d2b0)
  - @[attribute](3c4063cc-3cd0-42ec-b0b1-e910d24cc592)
  - @[attribute](238e3870-a2ee-4374-9e17-46332f01d1c4)
  - @[attribute](a860fec8-a0b5-465f-bbc1-f900c9fa5ad9)
  - @[attribute](cd180738-761c-43f7-8bec-fce630c8b2c1)
  - @[attribute](4953baaa-feef-4ebc-a4bb-598506a78974)
  - @[attribute](f10b0e53-3781-4982-b34b-a340047a15d9)
  - @[attribute](bae79209-e58e-4ba6-87fe-fcda03994cf2)
  - @[attribute](6af6abef-d498-4b0d-bedb-04f60baa0ab5)
  - @[attribute](fa9e1740-24a1-4bff-8715-701442891523)
  - @[attribute](4484a354-6db3-4403-b16a-8cb65639df97)
  - @[attribute](7dedea05-afc4-4a17-9746-5fd75a221347)
  - @[attribute](2fede9f9-d201-4cae-bb4e-af7bd923b9b7)
  - @[attribute](11964f2a-7bea-4d42-bf1c-6208966d76ca)
  - @[attribute](182ca04a-ad85-4300-afff-1e124f801dce)
  - @[attribute](95d0e72b-9961-4894-8aba-d855463b41aa)
  - @[attribute](9ad49a38-5c9b-4277-93ff-dc7d04ab205e)
  - @[attribute](302dd23b-a1b2-4760-a4dc-d4e66f524554)
  - @[attribute](5d779cac-9370-488d-9d96-8f55d5dceb4b)
  - @[attribute](2845b046-cee4-4a70-9f65-606d2993f574)
  - @[attribute](bd04bab6-578e-4c49-8bd2-c559e39b0797)
  - @[attribute](7e9e0b09-38f8-4d45-8c3c-278597f5073f)
  - @[attribute](4fe7eccd-ff7b-4396-aab5-5be458c234bd)
  - @[attribute](bd002566-1439-4a59-9d4d-2d44a3f14e79)
  - @[attribute](7d47d1df-6130-4d58-9650-b36594d70c58)
  - @[attribute](b84f302a-b398-42d6-9830-3e0d67f2f4a9)
  - @[attribute](abac0aa8-6e87-4d14-a94f-8e45468623cb)
  - @[attribute](89107dda-3920-4c7c-9612-9caf1ef05a08)
  - @[attribute](8a57a957-58e2-42b1-a102-5d2430d8fc9b)
  - @[attribute](2e43b8da-4fc3-400e-8ef1-2f486ea8771b)
  - @[attribute](55059cca-1ac8-4a3f-88e7-b73e916a5a40)
  - @[attribute](39b6c58f-b151-495d-9af1-426c20f239b0)
  - @[attribute](4802282e-8e97-4e5e-969a-4dba4e596ee2)
  - @[attribute](a25a297f-3264-4ebc-ac9d-3f1f4f08d32a)
  - @[attribute](4939abd5-685b-4f58-b1d3-9ff6c4f619d2)
  - @[attribute](e4b66b18-15e4-4dd7-81e3-b41faa718aca)
  - @[attribute](1e11f4ff-0543-4681-b8fc-ef8806f6f3a8)
  - @[attribute](bf1df59b-202e-4168-9fc7-dc19e5bf684d)
  - @[attribute](96fe73db-0823-470e-a01f-ba7e0a5f8dda)
  - @[attribute](05e4d49e-3890-42fc-a35a-980ae8b1dd55)
  - @[attribute](bb138b29-acfa-45e3-a1f6-e2f6c8146010)
  - @[attribute](ffac6f4f-01fa-4007-b8e9-4954ea572b46)
  - @[attribute](e6556864-3093-4b11-ac2d-a7fe711d0246)
  - @[attribute](9fac7aad-af92-4810-8b56-78053faf232b)
  - @[attribute](e2c212ed-0b4c-4930-9387-0bc4997bbeb4)
  - @[attribute](893826d5-4558-43b3-a22f-eb348828f55b)
  - @[attribute](9ed4d2f8-e013-4285-992d-a4c744f10aee)
  - @[attribute](9b5a6560-ef74-44b4-8012-c228761f15fb)
  - @[attribute](f2a37e44-3b7c-4fc0-b4d9-bc4a7c0bf648)
  - @[attribute](ed723052-16cf-4be8-9439-8c854599b4ff)
  - @[attribute](42725807-3801-4ef3-ab26-4bef3b47b0e3)
  - @[attribute](36672a02-a543-4e75-b428-ab4be3751faa)
  - @[attribute](74bf37a1-7c5a-4447-b323-b87050478a80)
  - @[attribute](9167caf5-f8ef-461a-a6aa-f4ae5d670fdf)
  - @[attribute](2f12a755-6389-4364-b937-c8aae0875985)
  - @[attribute](f2a588ed-5206-4cab-84be-514c13f54088)
  - @[attribute](ac4aa267-ee6e-4433-86bd-79150ba82b38)
  - @[attribute](febee0d6-dff2-4a86-a13d-5d3fe8ef012f)
  - @[attribute](e7c9a8ab-8d84-42b8-aab6-d79472b3f09a)
  - @[attribute](96ad3337-8b53-4403-8421-28c5471bdcd2)
  - @[attribute](14efec4f-eb95-447c-be44-69c4f14e5d75)
  - @[attribute](f5833b64-193e-4604-b70b-61a7f67fb69c)
  - @[attribute](66b44309-9013-453c-877a-02f30f04eb8f)
  - @[attribute](f3b0630f-3151-4431-a99d-16c0eb525d63)
  - @[attribute](d7ef679f-ba22-4c8e-a6f7-44cd9f227ba6)
  - @[attribute](ee532102-f48e-48da-b713-f35e6343cd51)
  - @[attribute](c68ff883-cfeb-4977-be63-2929fc7083e8)
  - @[attribute](5a3c6bb5-5551-43a1-9bfd-76b267f4a5d3)
  - @[attribute](61ecbfdc-5598-4a0a-babf-4d08dc42c6ef)
  - @[attribute](444c2b3c-ccd8-4bec-8e59-e95039d35fe0)
  - @[attribute](0ca1453d-c40c-4ae7-8ba9-1a07fa9df25c)
  - @[attribute](b9873f0f-0a1f-400e-b54c-c087288d427b)
  - @[attribute](058fd998-ebdf-4093-a97a-a473a5fbb2b6)
  - @[attribute](70e4d6d1-fbe1-4e12-927d-710258dde848)
  - @[attribute](02ece387-6d09-4599-a276-12e269839ab0)
  - @[attribute](9c2c8983-7116-448c-8c30-aad1967458ec)
  - @[attribute](2b23e7cc-88a4-4b56-8d4a-fa94082780f0)
  - @[attribute](2b4a8bd8-c9c2-4fa8-bb1e-1c1c31f00926)
  - @[attribute](2fb4b1d5-c8eb-4fa2-91dd-5ab373719780)
  - @[attribute](fe8b0195-2a2e-467d-b930-f01a8c147450)
  - @[attribute](55df12d8-e911-4848-b90c-238cffe4b58e)
  - @[attribute](a5b07ce0-5f7d-4cf3-b486-edbda808d92a)
  - @[attribute](3e891034-eeb3-4a1f-a185-275dd9999304)
  - @[attribute](d8ed2d97-6e5c-4b05-a2ee-493acdf49b27)
  - @[attribute](cb103aeb-ae8c-46db-9865-9737bf604343)
  - @[attribute](e287a10c-f350-4e0f-8e09-a571f4d22724)
  - @[attribute](c370d83c-a3fe-467a-8960-48a600f963e1)
  - @[attribute](5f6cb226-1c41-4e5d-bf20-f66142bab48f)
  - @[attribute](f664e8a2-6b62-4325-9df1-47b67ddcf4e6)
  - @[attribute](55c49020-1a8c-4755-aedd-018eb9c0bc73)
  - @[attribute](f6160fc6-6c52-43df-a0d8-b4934880ef93)
  - @[attribute](9279a97c-1373-4698-805b-9d1714f4b10a)
  - @[attribute](724ffdf5-6ae3-403c-bc67-acbe11f6e5af)
  - @[attribute](93934f64-b92a-4e88-84de-6b737eeb29e9)
  - @[attribute](9e2d5a40-c275-445d-aa9b-93b4b9cea94c)
  - @[attribute](15b4a9b0-1fda-409d-af90-ae8352a8a190)
  - @[attribute](d98e8c91-b5ca-4e55-a203-8cc8667e91f2)
  - @[attribute](045b5289-3b77-4913-ac3a-048ca5a5f2b2)
  - @[attribute](0346e483-1704-42e9-9299-c456d67b16f9)
  - @[attribute](d6801745-4e07-490f-975c-e9e347c5c4c5)
  - @[attribute](14c541cd-575e-4549-8d81-78c843d5af5e)
  - @[attribute](f9dc8826-daec-45ee-a677-ee2095e82935)
  - @[attribute](fb098b57-44d2-4f60-bfa4-410df577b9d5)
  - @[attribute](2e9fd7c3-0bfa-4d2e-a646-b03ca4ec1306)
  - @[attribute](487d89b5-955b-4efc-b3da-e68492f9f909)
  - @[attribute](8dd12526-6baa-4bb8-8e86-11cf40274e12)
  - @[attribute](c3969743-9491-420f-811e-802534911038)
  - @[attribute](2a5a26fa-a84b-42c0-beaf-99d75c239f1b)
  - @[attribute](0d47d3a2-2364-45e0-8c6e-66f303c10ff9)
  - @[attribute](fa7d5d89-9ae9-4051-ac52-88bd1d5bec7d)
  - @[attribute](331bc992-4366-42cc-99ea-98d962e184d7)
  - @[attribute](7358c476-5d3c-446b-a618-97e59b9b32fc)
  - @[attribute](34817865-8eee-45fa-b7fc-9eeeb444e940)
  - @[attribute](9605684a-1cf6-4582-81b5-1c095fced03e)
  - @[attribute](9c927e65-fb63-4554-9f07-03676b869c76)
  - @[attribute](9dfee104-5962-480f-9c0d-0626e97d3bbb)
  - @[attribute](49f95dfc-1fba-4070-b8fc-20f76b909e16)
  - @[attribute](2ed88c51-6522-4b3d-8569-dd0d7a8a10c8)
  - @[attribute](c5563ac4-48d1-45ca-a717-bc103b90fcc2)
  - @[attribute](c96ffd05-e5b2-4f35-9cff-d47c6d006762)
  - @[attribute](dec0621b-4f23-4eba-ab7c-4d7847c07407)
  - @[attribute](f4ac916d-f941-457b-a323-63d2b13a4a38)
  - @[attribute](c7ea86d5-be25-445b-b3ce-43298e7b3888)
  - @[attribute](ce5be1a8-ff03-4143-9a7a-b3ea2f47723f)
  - @[attribute](e46ff27e-6a7a-4d29-93de-b0a43367a8fe)
  - @[attribute](718fd13e-5adb-4f5d-ae83-1aa1fc7e8b82)
  - @[attribute](dc4ff896-64c1-4b33-8a68-48279c834c66)
  - @[attribute](a97c59bf-d474-4940-8442-5560ce47dc4f)
  - @[attribute](0f27a91d-246b-45c7-8a50-1b8fc1edf9f9)
  - @[attribute](f38f0981-c391-4def-a178-81497c5a8bfe)
  - @[attribute](455145cd-c402-425a-98d1-cc949739fe37)
  - @[attribute](ea7f6958-5428-4e85-9033-abff052d614c)
  - @[attribute](04c25d46-4b5c-41fc-94c8-f4fc8e086467)
  - @[attribute](29fb7543-33ee-46c8-9981-b721b2bf12ab)
  - @[attribute](6f9bb20e-e08f-4672-be1f-0e90b814cbba)
  - @[attribute](52352cb5-0ac7-4eee-862c-98d6e9de1086)
  - @[attribute](4cd5beb0-5a2f-4f58-a51e-25c01fab6e4a)
  - @[attribute](ff7979e8-91a0-4288-a344-939803c8c122)
  - @[attribute](81556ddd-2d47-431a-8bf7-ba8b4ad24511)
  - @[attribute](5ac2fdc4-5817-459b-8e32-af84044c59e8)
  - @[attribute](91ec1eb6-2b01-4256-9e6a-a8a69d3c4c20)
  - @[attribute](9e59b936-56af-4235-b4ce-e1f6cfd50b0b)
  - @[attribute](143d5676-a8d8-4952-8492-be8583f33e92)
  - @[attribute](6cc23b71-bd18-4a4b-b937-de7dcbca14a9)
  - @[attribute](e6bcdb9f-cb7a-432e-bf44-3ad783bbddcb)
  - @[attribute](97a8a165-73a5-4dc6-bf59-9db4de07fc95)
  - @[attribute](505a8a5a-cc8c-49e4-b283-aeab20419ded)
  - @[attribute](75e28544-1950-4646-a1cc-e79b16e3318c)
  - @[attribute](5d70b2f3-c506-4f5e-8c52-ae6c47a299ab)
  - @[attribute](fc84eeff-34e2-4d92-b7a1-d3ebcc62c3e1)
  - @[attribute](9e0de83a-e0f8-4be4-bd19-842f832f4519)
  - @[attribute](41d78400-89bb-440c-8ba6-a6eb89288a19)
  - @[attribute](e696e9b8-bc7a-4377-a6ac-fbd8634e1e4b)
  - @[attribute](e4893565-dc81-45de-aa06-480731ebd4b3)
  - @[attribute](07807e0d-0f14-4260-9966-d9a50ca84f21)
  - @[attribute](71094594-f3ef-486b-b742-cce64e368510)
  - @[attribute](29464b14-1dbf-4f49-901e-403f30689aa9)
  - @[attribute](0381e937-6fc7-440f-8667-3bdc795d467f)
  - @[attribute](bad6002d-28ef-4e05-ab39-b73fae26953c)
  - @[attribute](40fcba9e-5b72-4bb4-909b-5fc7e2aafc51)
  - @[attribute](ec2c85d6-b94b-4992-ba75-45ecb3a65251)
  - @[attribute](21c6510d-6649-4718-8c51-24f70d5aedb1)
  - @[attribute](6e3e7199-6891-4ce4-945b-da6968381e92)
  - @[attribute](02737ed9-38c5-42e6-82d8-001f78c72c37)
  - @[attribute](fdc04b0a-823f-4d8f-b129-662a6466237d)
  - @[attribute](8cecee1c-ffdb-4541-a81b-e514b4bb978d)
  - @[attribute](cd22fd91-5066-4c8f-9bd0-50e70b9455bf)
  - @[attribute](f8f04f91-313e-4cd0-8a31-da9815fd1bb3)
  - @[attribute](c35ad863-d29e-4183-996a-729fd9a69ee6)
  - @[attribute](c1a6484c-35e2-4ecc-820c-2c2ebe767a15)
  - @[attribute](4985f396-c602-4ce1-93e2-cfaee5f1c726)
  - @[attribute](c064912d-de0a-4aaa-bd9f-025b2fd9dbf6)
  - @[attribute](bb9700a2-9df3-4ae5-89cc-cbdbcfaf0bc7)
  - @[attribute](cf21ed85-e365-4109-9692-41fb26b5c7b3)
  - @[attribute](d5d9d7fe-c959-43e9-89ca-13f2e6e41553)
  - @[attribute](2c4f46be-d7f1-4217-be5a-d6c371ca2334)
  - @[attribute](77312017-c275-436c-b215-2f4d4991424a)
  - @[attribute](d013e449-e973-4d56-8842-1fa9548462ab)
  - @[attribute](08748589-5b2e-4670-9b37-cbf78e6314e4)
  - @[attribute](971db440-c545-48c7-b726-cabba957503d)
  - @[attribute](6a5878b7-66d8-409e-9d2e-d96f047a6da3)
  - @[attribute](fd13fc6c-01e6-4f30-8c45-6f5eac84d803)
  - @[attribute](5bdc5800-8309-4806-97a5-6a4cec30e4e9)
  - @[attribute](7c22e832-1187-4d31-a25e-1b0efc75f268)
  - @[attribute](5aa9a120-f6b9-49aa-8a54-448a13ece3c1)
  - @[attribute](515c65a9-9076-4fee-9801-69c56312a413)
  - @[attribute](db6dd491-83a7-4917-a20b-244484b3d19c)
  - @[attribute](ff449953-7576-4c13-96bf-dfd9f5d77aec)
  - @[attribute](40e9d88d-7a46-4c88-8dac-5064157cc3ed)
  - @[attribute](0d39d994-6dec-42ea-b0cb-27c361ca9b8f)
  - @[attribute](3e0a2cdc-7782-4774-b784-1bf0dd007f9d)
  - @[attribute](d04e9aa4-2b8e-4b1c-a7ce-e9d2e7fb4897)
  - @[attribute](dad23f44-1483-44d8-9971-f672dbfcfa96)
  - @[attribute](c98cb5f3-c916-43ce-9f63-eae7bcde14ea)
  - @[attribute](9ac9ed54-75b3-4419-b0e6-4a04abcd3899)
  - @[attribute](ce8fcc2c-3da0-4f3f-823c-9dcb6e97e95a)
  - @[attribute](e27e2415-1d74-45a2-9e75-ad3bd3d1d305)
  - @[attribute](404996d6-ea77-4d7f-836f-d3ff819d7a68)
  - @[attribute](b8a7608a-9b18-4ada-b7b2-ea9b3e17ac56)
  - @[attribute](3962b321-70b6-415e-b3af-36c267aa2648)
  - @[attribute](6d83967d-f879-48aa-b4eb-50375801733d)
  - @[attribute](da14b845-01a6-4383-8be4-b6ca76a74a54)
  - @[attribute](427b4ac2-80d4-402a-ab6f-6ad85f75aba1)
  - @[attribute](5da8eac5-d9a1-40ab-a655-003b1a8cd8c6)
  - @[attribute](16c79b2c-299a-4d20-9410-893350a31b7d)
  - @[attribute](629b9caa-4d11-463d-a063-a9b2464883db)
  - @[attribute](86040b94-9f2f-4fff-8f26-d776dd0131c4)
  - @[attribute](375d4f2f-14f2-40f3-8161-42ee16a7d1db)
  - @[attribute](81da77dd-6f06-4a89-9127-6e4aee1ca285)
  - @[attribute](d9d6d649-ec27-41b6-a88c-991a1442bb56)
  - @[attribute](86a9474f-6e7b-449f-9af9-c3edcdfc9560)
  - @[attribute](4024ff4f-6c33-4544-a5ee-0bfc4c007c33)
  - @[attribute](b96f8f8a-0ea3-474d-9c57-1f4b0f8fb774)
  - @[attribute](5fdcf25f-4a14-42ff-b540-57bfef8cdfc2)
  - @[attribute](cf0abffa-97a4-4ff6-8a65-fc730f0ccfe3)
  - @[attribute](5d568c30-cafe-4cac-9b03-94ee3f790aa6)
  - @[attribute](355b3e1b-73c6-42d6-b957-1da44326b511)
  - @[attribute](2525e524-70c6-4db6-806b-75d3ba997268)
  - @[attribute](c8a23e60-1dcd-49c6-ad68-9704b3953739)
  - @[attribute](dfe22183-4b67-4cae-9999-73565d51655b)
  - @[attribute](a14fe0a6-926c-4cf5-9f04-224755c60fde)
  - @[attribute](f3afb5c4-d557-466f-a7bb-32f0218fd732)
  - @[attribute](8b3dfa3c-97b4-4ba3-b62e-bd7745c54db5)
  - @[attribute](d237f16c-0ff0-49e9-86f4-8066e8e1b022)
  - @[attribute](9127017b-20c2-4cb7-8526-4c3dc4113e19)
  - @[attribute](6afbbdbc-6006-4f17-825c-883b62cdcb8e)
  - @[attribute](e183401f-97c6-4311-ab08-a08579e419d6)
  - @[attribute](e6ca45ad-0de3-401b-8bda-dad239d0365c)
  - @[attribute](1e1a0c8b-a5a0-426d-be2d-3cccf95419dd)
  - @[attribute](fc990177-2667-4e71-8ca2-ce5e05891491)
  - @[attribute](e553d35d-fb71-4845-ac09-4a578259c749)
  - @[attribute](5e1c2029-0de5-4ec3-bf3c-07f4dbc7916b)
  - @[attribute](6fef4e1e-1c07-48ea-93c6-d6b144218131)
  - @[attribute](f413ab6f-590b-4f22-83a5-01492a20c248)
  - @[attribute](2525dd31-e756-4316-9b4b-eb562f0aef66)
  - @[attribute](3b17587a-3f16-4300-a87c-287e67c52d02)
  - @[attribute](e5e41c33-9c40-4eec-a0d9-20f67f4156c8)
  - @[attribute](1cd17751-a52e-46b2-8555-4694ef69fc11)
  - @[attribute](ebfe6095-5112-44a9-ae32-bfe635030ad7)
  - @[attribute](2dec2b83-eb72-4075-9c9b-fa31b511b725)
  - @[attribute](53a39cb2-f000-4d0c-bbae-7533a7de4c1b)
  - @[attribute](a3790e5c-53a1-4221-917f-ca11f4783ac7)
  - @[attribute](eb6a8a70-ec09-4561-9ce4-89d98e8e4b54)
  - @[attribute](919142eb-f6f6-44a4-a118-d3c26f6f8976)
  - @[attribute](d50ca4f0-1a42-4d06-b028-d19b35a338da)
  - @[attribute](1a123edb-b1bf-4eda-846a-ce0ecda06cc6)
  - @[attribute](395180b8-a408-4d8e-9068-560f2160dbdd)
  - @[attribute](55ce3cee-4511-42cd-907b-5b65c02d9fa4)
  - @[attribute](7412f775-f02b-4a30-9758-2ad43e89ddf2)
  - @[attribute](9e91f524-a169-429a-a8ac-30aa41deb413)
  - @[attribute](7f057583-1850-4c5f-b6b6-47b4b3dd3da9)
  - @[attribute](d466fa76-b407-43dd-a45b-686efcc09809)
  - @[attribute](14d5caba-7acb-4c22-af88-0083bfc3e138)
  - @[attribute](0c6cbc59-bf88-412f-b347-df4bd53b4ec9)
  - @[attribute](791017bc-87f0-4533-b5e4-01254bd5ce1c)
  - @[attribute](83d41a28-f89c-4a51-aff7-375c41cfb30f)
  - @[attribute](99d154ca-33b6-4398-a412-445a55129215)
  - @[attribute](a8a304bf-7fb7-4d14-99e5-e76eb4fd0ec6)
  - @[attribute](18c93f59-d065-4b70-977c-d1b9fbaf09d1)
  - @[attribute](fe788cdd-6096-4de9-960f-3ceef4a507b2)
  - @[attribute](62e08e6e-72c9-41be-a5b7-86a75fc4dff0)
  - @[attribute](bdbadc90-f849-4db6-89e6-e70e6df177c2)
  - @[attribute](16f3b84e-3a9f-4826-a415-821412fe0cfc)
  - @[attribute](3c8a2711-7cc6-4d83-8a69-629316c0e377)
  - @[attribute](fe46ac3f-0bf5-4b59-8adb-d74446e2aed0)
  - @[attribute](4ad1848e-6f19-4e6a-896f-7c74d02bbab1)
  - @[attribute](4c262f13-d2d2-4315-8d90-e5f2eda79b70)
  - @[attribute](f3e7670a-ff5c-4505-b55e-16e8d92356eb)
  - @[attribute](424d9f80-c384-4394-b467-f460ff042c5f)
  - @[attribute](43a315ec-01d3-4666-b90f-315be0637fc8)
  - @[attribute](7cc3916d-7b9d-48d8-a303-ffbf9428b239)
  - @[attribute](752d5096-d440-41a3-8e6a-203b01ad2a29)
  - @[attribute](dde72ae0-7dec-45e2-be7c-7784e05c28f3)
  - @[attribute](b8b6c032-1e10-4847-a9ad-cd3a65e98b5c)
  - @[attribute](cfff62c1-06df-48c0-9028-513756796c83)
  - @[attribute](2786f273-082b-4ca1-a270-a2fee79c4d49)
  - @[attribute](f983f1a3-fe31-4a9e-9387-be384103b507)
  - @[attribute](b053a404-50ed-4399-89a8-98903b4c4b77)
  - @[attribute](438b41b8-d238-44c1-b5de-ddd79ad12767)
  - @[attribute](f72b41e6-c2a8-4e0b-8cb5-ffdba2943ed1)
  - @[attribute](408d6739-56b2-4b30-adae-b7824caf65eb)
  - @[attribute](b550b386-faad-4538-887c-d36ff472f475)
  - @[attribute](60d97aea-9e45-4433-89db-b7b415c1804f)
  - @[attribute](2bc03838-5f33-48ba-b86c-66aec44c9f01)
  - @[attribute](012275f3-9e2a-4ba9-9120-8dcb787b0ea0)
  - @[attribute](ff2f6d4e-6ad5-492f-8fdb-c58a8a484397)
  - @[attribute](132ce71d-8c35-4704-b8ba-cbec4bf5888d)
  - @[attribute](751e062c-60a4-4fa6-9717-5640b5b50a38)
  - @[attribute](0f213118-6656-427b-bd8c-aefd12692281)
  - @[attribute](efaa1dbc-57dc-4cbd-b504-098df1da2f67)
  - @[attribute](882561e4-566c-49b8-a575-62f9dc49b320)
  - @[attribute](c328d9de-378d-4670-b8c6-eb6ef4b9b567)
  - @[attribute](3d651acd-ebc0-4da3-b1fe-7fcbab76079d)
  - @[attribute](90259833-52c2-4419-a745-9ba381e7351b)
  - @[attribute](aa578ea8-0f09-40f1-b7f3-183c4a238a8b)
  - @[attribute](d5b6e0a8-629a-4b3b-9c3c-8c75f59feaa6)
  - @[attribute](1d1993dd-fc13-439c-bd65-2c52710ae2de)
  - @[attribute](996bd0da-fca3-4392-8ce9-fb6bfe501620)
  - @[attribute](94a585b8-13f6-41cf-b6e9-2d24005f706b)
  - @[attribute](9974c9a6-929c-4d59-8a77-7bfd6ec4b013)
  - @[attribute](b0dff48c-777c-4dbf-bf59-cd7dd379de82)
  - @[attribute](2c9b0fe1-48c6-42f9-a758-fadd3b6b8add)
  - @[attribute](9b91ad60-882f-4703-9639-9c81f5f8648a)
  - @[attribute](d8835860-b91d-4216-98a1-c99e16b8906d)
  - @[attribute](48f66a4e-617b-42a5-a72d-af280c477c11)
  - @[attribute](1345c984-600c-43e6-b01d-b3ca6c0c8277)
  - @[attribute](aaeeb3ea-66d1-4095-b77b-eb6bfce74f4d)
  - @[attribute](b0676832-f8dc-4ada-b94d-adec88719887)
  - @[attribute](fc92b81f-f430-453d-a3b5-0bc29368a9d1)
  - @[attribute](cf5235f8-3706-4622-8bb5-901ed15e1bb6)
  - @[attribute](7b247dd8-6a0d-4bf5-b612-b4ac3e72ddd7)
  - @[attribute](ca4404f2-33a2-4c1e-97bd-ac6704500918)
  - @[attribute](205b35c3-817c-426d-bb62-eb3a061a4b31)
  - @[attribute](936c8864-5999-4915-a5c2-0673fa513694)
  - @[attribute](f6714275-5cb5-4617-a380-c29159915b39)
  - @[attribute](d2052d6a-9700-4fdb-ac75-1509b76fdc52)
  - @[attribute](1ac67347-0de6-4fed-99d7-0fbb2e867e45)
  - @[attribute](54875ad7-d33e-4844-94e4-fa171007b179)
  - @[attribute](274c45b4-7c15-4045-b8b1-d9ec07849d17)
  - @[attribute](e3b4e851-a0d9-4588-8f99-cf4591d7b047)
  - @[attribute](ff5271de-7964-41cf-9fa6-6b74d428ad61)
  - @[attribute](2530f32d-0636-453d-ae4a-1e7da2e3f466)
  - @[attribute](8ba2553a-d950-48d5-8c88-1af14919fc07)
  - @[attribute](baba5cef-bd0b-46e6-8a51-5b599a16cbdd)
  - @[attribute](1ddca77e-d5af-4c1f-8ab8-477b3340523d)
  - @[attribute](8eb2783c-280e-4586-ab07-5b3d581c2dd6)
  - @[attribute](0d98663d-fa6c-46ab-aecd-befdaa07f76c)
  - @[attribute](48aac423-0aa3-46a8-a128-136a2025a5df)
  - @[attribute](824a8c28-0922-4d20-a7f8-cdadc3860746)
  - @[attribute](f2afcff8-c16f-4cfb-b6e5-6add6a4f1f7a)
  - @[attribute](941a97d5-76a9-4145-bfcf-fd9e4bb3dd75)
  - @[attribute](bc9bec2d-3499-483e-9803-d4980770e5dd)
  - @[attribute](d5a2385f-d647-455a-b19a-9cfc3513625e)
  - @[attribute](2fab13db-51a8-48b3-9412-57bac89165a5)
  - @[attribute](d6ef95bd-4b66-497f-b6fa-712d84da96ee)
  - @[attribute](4d1c4b04-929e-41da-8b47-9985df8c003d)
  - @[attribute](49071501-6019-4a53-9c80-1ec631f1c80e)
  - @[attribute](790d0526-00f4-4a85-89cf-1deab722984f)
  - @[attribute](749c34ee-4461-4027-afc0-b0b5b27fd276)
  - @[attribute](5e5179f1-2c68-49ec-9f30-46f963ea1ad6)
  - @[attribute](4b7ddf80-945b-49aa-a8eb-21c6be142403)
  - @[attribute](f06ef434-3f27-4543-a86d-53f3027e809a)
  - @[attribute](6b23a35d-3400-40fd-91f7-572666942ee6)
  - @[attribute](96852336-e896-4553-802f-479d0d98a5c9)
  - @[attribute](586acda1-401b-46dc-8628-2e083a272c32)
  - @[attribute](9532071e-c4d5-4cf2-9c36-3e8914c79d7b)
  - @[attribute](b5bb44f5-8e6f-483a-ad7b-2d19849e1a0c)
  - @[attribute](559b6889-35ed-4cfa-a8b6-5e104b9e570a)
  - @[attribute](6b141970-4afc-47df-8fa2-304f9751dd86)
  - @[attribute](6b88c858-cbd2-4e19-bdc3-ee7932caff66)
  - @[attribute](70704013-0c6f-4bcd-9a87-71a1cacea37b)
  - @[attribute](9c48f850-1029-45ce-8c16-380208e09fca)
  - @[attribute](2a47f62c-9e94-4600-a2d0-454614db3237)
  - @[attribute](470b4dc3-c742-41ea-a50d-db25aa891d18)
  - @[attribute](5b2ee5f6-9743-4276-92e6-1b8dc2d4562f)
  - @[attribute](7669e353-a83b-40ea-a5b0-b398818b0d8d)
  - @[attribute](aec40988-402f-499a-9af1-c60579447ffb)
  - @[attribute](38e3007c-9c9a-403d-85c4-23771e0d344e)
  - @[attribute](a2f5ade6-46d9-4c41-afa7-26ecbc64f120)
  - @[attribute](db7e40a0-82a4-467b-b454-cb0dc55f68fa)
  - @[attribute](704d76f8-0092-4c0e-b29f-341ba315751c)
  - @[attribute](f6f77364-2730-4409-9905-cebae3c196de)
  - @[attribute](f7236340-8bfd-43b1-9ae4-4bfef7ba751f)
  - @[attribute](06c2aaea-1c04-472a-971e-e1dc00d3cb48)
  - @[attribute](2384d799-9996-4d9c-8d8c-84c3413fd6bb)
  - @[attribute](00e8f882-bcb8-4f74-9879-904f29efcc74)
  - @[attribute](a30846f6-652e-48f3-9363-35e44baebc54)
  - @[attribute](1582f7f2-1699-4003-bcd7-83310687b4c7)
  - @[attribute](3883b48c-73b9-4192-b40a-0e787801fede)
  - @[attribute](cfc4b24b-120f-4aba-a292-6f29afefc1ca)
  - @[attribute](b209d543-9b67-4bdf-96b2-03d4ec607602)
  - @[attribute](c9e99ddc-e22b-4354-a49a-3ae839406e39)
  - @[attribute](7d71d5e0-bd3d-4b53-a0f0-0185cb1ce218)
  - @[attribute](1ff7801b-fbc1-47a9-a3df-da2c057ada08)
  - @[attribute](a8d7ba28-ab1b-4544-baf0-7cee0e6ff5d5)
  - @[attribute](1b7fef52-1671-49a9-8f6e-13310cb51f4f)
  - @[attribute](00bc70d1-1ba1-4080-ac4b-f04071b699b7)
  - @[attribute](36a3fda6-191c-4029-9901-3445aa77ef66)
  - @[attribute](d0102f9e-cfe9-4790-8cb7-fd75492feb85)
  - @[attribute](f68f9074-aa58-4e45-996b-b1f0abe0f256)
  - @[attribute](2c190305-5266-4555-bfd8-121e1e967090)
  - @[attribute](048996ab-73d2-41b3-90cf-667f0177f050)
  - @[attribute](46dd01d6-c566-4d78-bcaa-7ec803157f6a)
  - @[attribute](2d2840cf-e273-40db-9583-4d389d9d66e3)
  - @[attribute](0b6e8ed5-acef-447a-b216-ab2116959d90)
  - @[attribute](f53d5200-203c-4803-9805-24f3e682a430)
  - @[attribute](b1509644-481e-47ea-850a-3ec200dd5b42)
  - @[attribute](7c7f1420-91fc-40f0-8243-af4d1c801f24)
  - @[attribute](f903c60e-ac88-42c3-b4b7-7b7ed3e27aa1)
  - @[attribute](45bc1e8f-f93b-470b-8904-c08c15ca02dc)
  - @[attribute](7439e255-3bbe-4911-a01a-57bedb317738)
  - @[attribute](8ae0f4a0-d853-41f0-b976-3c3a17f06cb4)
  - @[attribute](7b0f4aa9-58d3-4fec-8340-d8aa11972046)
  - @[attribute](b2bfea8f-f852-4247-a22c-0f26cb697ffe)
  - @[attribute](177ab580-7984-402b-a02c-ea304e452671)
  - @[attribute](e831f534-fd52-4ece-b17f-92a0e368dedf)
  - @[attribute](722ff820-cf68-45a9-8290-64dd991107f0)
  - @[attribute](6500396b-ed98-4e1e-871f-da7534b444d3)
  - @[attribute](c4330445-ad2a-49d8-9b43-d89d4927e0d5)
  - @[attribute](8b76c9ea-04a8-43bf-bc65-0ca6ed610b97)
  - @[attribute](06c58061-1884-4d19-90d7-27ec1637446b)
  - @[attribute](386fb275-20d0-46e6-a553-412bcfdde874)
  - @[attribute](2666bceb-911d-4dbf-9808-27f6399c1f31)
  - @[attribute](f864800f-0aaf-426a-a981-1f7c9af81295)
  - @[attribute](c1790ca4-1d28-46fa-b4f7-bf375ee3f349)
  - @[attribute](b7c9e20b-d3a5-416f-a73d-fc54d0048e20)
  - @[attribute](6d0d2a4e-2c8f-4bf3-bacd-25567d82b614)
  - @[attribute](086ec3b3-1fa4-4742-b1fd-a4a7a7ae1f20)
  - @[attribute](e88d4593-0692-4c4d-ab35-cf7f26edd8a4)
  - @[attribute](1205c71c-3ff4-4aac-934f-54a0054789bf)
  - @[attribute](39665b2d-79bf-4c1b-a555-9b705a4433ad)
  - @[attribute](5a9bd661-125c-41b1-87f9-2c60c9a13518)
  - @[attribute](b08209ca-4120-4500-9072-05e14e010020)
  - @[attribute](770832c2-61a9-44b8-a5fd-5f81fba385c8)
  - @[attribute](8fd4518f-cc17-4762-9e0b-384da7ee13b3)
  - @[attribute](1d254be1-9c2a-49ff-a368-567673b113ec)
  - @[attribute](c4197981-ef72-4832-b894-597f6dac2be2)
  - @[attribute](b3d45776-cb4b-496c-b49f-c11404cb9bcd)
  - @[attribute](cf5c3649-9608-49a0-957c-4597f513c7f1)
  - @[attribute](72cf1ee1-4f2d-4998-8bbc-259db3b66005)
  - @[attribute](04c1798e-1acd-47e6-b0b2-6fd3bc8144e7)
  - @[attribute](7d6eb965-8aff-4426-90b9-dfce80eb2380)
  - @[attribute](c6928334-b617-4ebc-b41f-c3a10e6ef0ec)
  - @[attribute](0ce667da-db24-4e1a-9a80-b09068701665)
  - @[attribute](5573130f-641f-4a84-9e75-c768821fa3d6)
  - @[attribute](68bc79a2-2e93-4e6e-8022-05189fb93043)
  - @[attribute](4194f8d2-78e3-4bfc-b8fe-f254a5f68da1)
  - @[attribute](49dc4624-b191-40a8-a334-9653669affdb)
  - @[attribute](fe2f5f84-409d-4597-94a5-26bd252211e7)
  - @[attribute](d148b003-6f2e-4b43-9330-bfadaf723cb0)
  - @[attribute](adc27baf-37da-48b6-9aba-071aeccaeac8)
  - @[attribute](ffd48e48-83b7-46ec-94cf-69c7996c2a01)
  - @[attribute](481b2a1f-feea-41cf-9b22-562d130c8d60)
  - @[attribute](79d06bdd-6ce0-4d4f-9a60-d53813857e54)
  - @[attribute](02296619-1adb-4026-9dfe-c32a69360ced)
  - @[attribute](5b46b776-f3bb-48ac-8fb9-7b6241324afd)
  - @[attribute](d3971601-0d7e-4a07-a318-e42f593f9e31)
  - @[attribute](2ea21157-6feb-45cd-9ce6-b581ecd2face)
  - @[attribute](4c1b64a9-e69f-4b33-8ea6-8acfa6f3bc7f)
  - @[attribute](c11fed29-66e0-4724-b238-50abf68ad935)
  - @[attribute](dacab6f4-8e38-43a2-bd3c-9929c0274ae9)
  - @[attribute](eaee3a5d-9598-42d6-ac0d-101befec17f8)
  - @[attribute](2626882c-6d6b-4685-8010-985ef7158986)
  - @[attribute](095d9670-ad81-41b2-9e53-c30f3ce76180)
  - @[attribute](c142480a-c9fa-44eb-b85f-3f108920d4f9)
  - @[attribute](ccd47e8e-d1f7-4405-acb4-574b2159bc12)
  - @[attribute](cfd2c42b-e25a-48fa-a99f-9ccd01c44627)
  - @[attribute](c3169ef0-0fc7-4094-a84a-c00da1526dff)
  - @[attribute](d77d4f41-7c34-42a9-a824-a1e3a3cc9409)
  - @[attribute](e82fc658-77d1-4206-bcbf-60ceb4650747)
  - @[attribute](401f05bf-f43d-4dfc-8eda-ee2e81991892)
  - @[attribute](ad566164-661d-46a3-aa28-6340840a730e)
  - @[attribute](3db49b2d-b490-4246-a36e-8a54e71348fa)
  - @[attribute](8d3a66eb-150c-4ae7-8d19-dfd2fa49742e)
  - @[attribute](01069d36-8877-4707-a784-1e87dc243e30)
  - @[attribute](8778a081-7d0e-4110-a871-4d1e7679d9e6)
  - @[attribute](a68a993b-cab9-4f66-b151-3af058cdcaa7)
  - @[attribute](abe18622-1794-4a3a-b0f5-ee1d78f7365c)
  - @[attribute](7a7c42cf-bb99-4ca2-86ac-8edcb1aac638)
  - @[attribute](6d6488e6-f91b-4cbf-b40d-64c59ef2091b)
  - @[attribute](66a378b4-42ef-4dc7-84f3-e1ef04d29c55)
  - @[attribute](194943b9-357a-48ce-94f9-b16c04b6dd8c)
  - @[attribute](e744a967-ba71-48c9-8c91-e72c06b518dc)
  - @[attribute](71145102-ee43-4be4-b552-e168aa1db380)
  - @[attribute](b55e6bdf-60d0-4c2d-86d0-96fec5f90952)
  - @[attribute](622b8a0a-ff33-4834-bec3-9ea91ef53084)
  - @[attribute](dda426b5-8244-4922-9f7e-06e3f5025c68)
  - @[attribute](9c7c5f7c-07d3-4a41-a17d-646d9cb67a80)
  - @[attribute](da85b2c5-dadd-43f1-a42a-a2b185db70f8)
  - @[attribute](3635ba39-6aa8-466c-9700-e1bbda8d73dd)
  - @[attribute](82a54b0d-bf02-4e56-a357-090cba457269)
  - @[attribute](21579f1f-942b-4a57-a150-2275e0c365b7)
  - @[attribute](0dabfcb0-d88f-4889-933d-7ec46f070b58)
  - @[attribute](5ff88d92-eea8-4328-96a1-733d25adccff)
  - @[attribute](5fcd2219-a35f-4f02-8657-e251fb797a7f)
  - @[attribute](ac6769d1-d265-4b58-b5cc-f67fd78687ba)
  - @[attribute](3b1b340c-276a-49b1-8cf1-ca3f51b1100d)
  - @[attribute](f102a30f-4f90-4caf-b3de-f1a92d15cb5b)
  - @[attribute](638d25c9-d2e5-47cf-8a6e-3b1d4a1f9b46)
  - @[attribute](7f94604a-7b56-468f-8c48-287731504509)
  - @[attribute](aea81f0c-70be-47d7-b56f-dde12ffbda62)
  - @[attribute](42c53860-f686-440c-baca-1f45dced2a3e)
  - @[attribute](8dce72d8-26c3-4354-a793-bc1b2f783171)
  - @[attribute](8cfc84db-5e15-4796-86d6-a790d6ecb205)
  - @[attribute](b20ed711-3df5-4f4f-8963-5d55e712d6e4)
  - @[attribute](e579022f-99db-40a3-b044-79ee31be4f8d)
  - @[attribute](8d97926b-40b1-430a-a4e6-0b95afdcbf2f)
  - @[attribute](3375fa08-ad4a-44f6-8a6c-a68e2dc674fb)
  - @[attribute](daeeea25-833c-4b5a-a79e-f55145b14b9e)
  - @[attribute](e849f603-1089-451b-b821-bd8c990b083d)
  - @[attribute](8cdf0318-57ae-4f78-b51f-66c097ff288e)
  - @[attribute](1034af14-433e-416e-b50a-e177cc0ea7ba)
  - @[attribute](4229661c-5a49-44c4-b952-d388ca51ded9)
  - @[attribute](88d0be45-83a3-4df7-b66c-037ca594c398)
  - @[attribute](4fa60996-eb72-4334-b587-718b77655120)
  - @[attribute](d340ed2e-9f75-44d5-ba8e-5a2d1a0c12fa)
  - @[attribute](9637444d-53e9-4234-9efc-6b42888fdafc)
  - @[attribute](512c533e-89ce-446b-98a9-965dd818886c)
  - @[attribute](eae809bb-cdcf-4530-be2c-cee459429a17)
  - @[attribute](a0b8b40a-5488-4c80-bc34-6bc386f8355f)
  - @[attribute](7d1dbd0b-94c9-433c-af8b-a85ee162e1f1)
  - @[attribute](65963864-0962-4e95-ba8c-2979d660ab31)
  - @[attribute](d1f178ce-41c7-474e-b57e-f43e0d45f357)
  - @[attribute](eb7d1a24-70c9-42ef-a385-df7624e77230)
  - @[attribute](6c228c03-7e38-4c65-96d8-752147552504)
  - @[attribute](0318eb4f-c42b-4af7-a566-bab6d3c55381)
  - @[attribute](75d9d550-82e5-4569-bc68-6ba8ab171684)
  - @[attribute](f6a6b17e-4c4d-4875-b0aa-042df6bef4bb)
  - @[attribute](2ca715c4-e155-4d50-a804-d7d25cbb012b)
  - @[attribute](5983f4de-0dd9-47c3-86e1-d930b0b790a4)
  - @[attribute](e7cb16e9-17ef-4203-bb44-4b026e425a71)
  - @[attribute](0ca41c1c-cf12-41e0-bb33-f9df4b752a51)
  - @[attribute](33327655-bb2c-4081-b93f-d3ef8ee6243f)
  - @[attribute](601a4d3b-ca11-4703-94eb-3ed7d7b4a263)
  - @[attribute](01ab9452-1914-401f-9ce5-655350ec93dd)
  - @[attribute](6ba9d26c-f372-48eb-863a-cd510aa91325)
  - @[attribute](b8fd9e97-7f69-4fcc-91f8-063a52b14d5b)
  - @[attribute](1896e609-f1c7-4a17-adf5-093935e2d0ca)
  - @[attribute](91bd5fdf-03a2-4d47-8f33-45d82cc0dc5b)
  - @[attribute](dd6a5222-bef7-414b-98a5-81532a63930e)
  - @[attribute](7f886336-bbbc-42c7-a61e-d99e4e808e3e)
  - @[attribute](c820f712-3d01-4d7c-b417-7db158f7cf72)
  - @[attribute](0a31a4a5-c110-4832-999f-56075eefa110)
  - @[attribute](3a009a66-f918-4f87-90c6-baa0efe4d34a)
  - @[attribute](0d329b85-50cf-440f-8c69-1ae58df3f3a2)
  - @[attribute](1d359197-df37-421c-bb61-b9a9325230fa)
  - @[attribute](57deddc5-82c4-4917-9e5d-d385f8ff52ce)
  - @[attribute](31b87fa9-5125-43d0-bd74-05a2ac6dc963)
  - @[attribute](59694935-7573-4fb2-a538-1527908b057c)
  - @[attribute](10892704-758b-4781-880f-39a153f6161a)
  - @[attribute](dd8b5448-11a1-46e9-8286-85e48862783f)
  - @[attribute](e77768cf-9041-4f52-aec4-3d3e1185b02d)
  - @[attribute](1894caf3-4b88-4f96-9b00-372290254629)
  - @[attribute](12df92f9-e822-4622-b220-ba78daac27e3)
  - @[attribute](217679ad-5f31-420b-9a72-40d7fa48582b)
  - @[attribute](6b522b34-ae19-4c49-bac4-4e5380b8facf)
  - @[attribute](a6d3ec6e-682f-40ef-99a7-47dee734a54a)
  - @[attribute](b029e4ba-27f7-4fc3-9289-25af6ac18958)
  - @[attribute](ab465e1f-43ed-4fec-9c2e-8e80b6281e34)
  - @[attribute](496f07d7-b001-40c9-a9e1-8adbff0e60d2)
  - @[attribute](d7da54e1-368d-47df-a189-6ded4266fe01)
  - @[attribute](477dcfea-53d9-401a-bf8b-b8bb57945111)
  - @[attribute](2b131089-6d29-4591-b229-b54d7afa52da)
  - @[attribute](073bd00e-4b9d-4ea1-b985-491e8edc79ce)
  - @[attribute](adcb3673-cf4e-404c-a75e-c7588c82f633)
  - @[attribute](f708e0f0-4b3f-4508-98db-f153563fa2b3)
  - @[attribute](643f2c86-c91d-4962-bcef-43fd46bfadfd)
  - @[attribute](dfd365ee-b21a-4abe-8d31-3973a3cad93b)
  - @[attribute](3b02980b-05a9-42e9-a4c0-70771e322e25)
  - @[attribute](b3927aa0-1c5e-4aff-a7c8-1aac57ee5306)
  - @[attribute](b69afe75-6bf5-40cc-8cea-b25ff4d3bbd9)
  - @[attribute](62acc5ae-7b70-4cd1-948f-5766ef3fd16c)
  - @[attribute](25c71ed1-e5fa-4d07-88a1-b4cfc709472a)
  - @[attribute](7e175abc-ba71-4975-aab4-ce44bc179d49)
  - @[attribute](8068d270-916d-4931-bae1-e6f0ae137abb)
  - @[attribute](f3c19fa3-d041-464c-b0e3-212f5e4ec851)
  - @[attribute](824f4675-c7bf-48ba-8da6-30b684f0b0e7)
  - @[attribute](4fb22dbb-9f33-45f2-977a-82b0f6db8b6a)
  - @[attribute](c6400285-26e0-474f-8da0-01126c80ced5)
### ATT&CK Matrix
@[galaxymatrix](c4e851fa-775f-11e7-8163-b774922098cd)
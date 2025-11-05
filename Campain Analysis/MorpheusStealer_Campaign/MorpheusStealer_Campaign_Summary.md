# MorpheusStealer Campaign Analysis

## Campaign Overview
- **Campaign Name**: MorpheusStealer Campaign 2025
- **Threat Level**: Medium
- **Status**: Active
- **First Observed**: September 21, 2025
- **Malware Family**: Information Stealer

## Key Indicators of Compromise (IOCs)

### Command & Control Infrastructure
- **Primary C2**: 27.124.34.203
- **Secondary C2**: 185.117.91.141

### Additional Infrastructure (12 IPs)
- 123.249.70.191
- 106.52.208.143
- 193.112.206.250
- 115.159.92.22
- 61.135.130.179
- 47.105.65.102
- 218.30.103.192
- 111.229.19.220
- 124.221.149.34
- 101.143.171.91
- 124.222.218.20

### File Hashes
- **SHA256**: 6e1b152e34c76fab5414c4210a28bb5ca47b2155e6205e58e7df78ee9de6cb64
- **MD5**: f7b73ce9323e25a5f143c7c3922e277a

## MITRE ATT&CK Techniques
- **T1555**: Credentials from Password Stores
- **T1539**: Steal Web Session Cookie
- **T1005**: Data from Local System
- **T1041**: Exfiltration Over C2 Channel
- **T1055**: Process Injection
- **T1027**: Obfuscated Files or Information

## Malware Capabilities
- **Primary**: Credential theft from browsers and applications
- **Secondary**: Browser data exfiltration (cookies, autofill, history)
- **Persistence**: Registry-based persistence mechanism
- **Communication**: Custom User-Agent for C2 communications
- **Data Exfiltration**: HTTP POST to C2 servers

## Detection Rules
- YARA rule for file-based detection
- Snort rule for network traffic detection  
- Sigma rule for process-based detection

## Recommended Actions
1. Block all identified IP addresses at network perimeter
2. Monitor for file hashes across endpoint security solutions
3. Deploy provided detection rules in SIEM/EDR platforms
4. Review browser security configurations
5. Implement additional monitoring for credential theft activities

## MISP Event Details
- **Total Attributes**: 45
- **Network IOCs**: 13 IP addresses, 3 URLs, 2 domains
- **File IOCs**: 2 hashes, 5 filenames
- **Detection Rules**: 3 (YARA, Snort, Sigma)
- **Attribution**: Unknown cybercriminal group
- **TLP Classification**: AMBER

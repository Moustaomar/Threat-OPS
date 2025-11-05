# MISP Report - APT28 Operation Phantom Net Voxel Campaign

## Executive Summary

This MISP report documents the APT28 Operation Phantom Net Voxel campaign, a sophisticated spearphishing operation targeting Ukrainian military personnel. The campaign leverages private Signal messaging for initial delivery, weaponized Office documents with VBA macros, and advanced steganography techniques to deliver the Covenant framework and BeardShell malware.

## Campaign Overview

- **Campaign Name**: APT28 Operation Phantom Net Voxel
- **Threat Actor**: APT28 (Sofacy, Fancy Bear, BlueDelta, Forest Blizzard, TAG-110)
- **Attribution**: Russian GRU - 85th Main Special Service Centre (GTsSS) of Military Unit 26165
- **Target**: Ukrainian military personnel
- **Threat Level**: High
- **Date**: September 16, 2025

## Threat Intelligence Summary

### Primary Attack Vector
- **Delivery Method**: Private Signal chat spearphishing
- **Lure Documents**: Weaponized Office documents with Ukrainian military themes
- **Social Engineering**: Impersonation of colleagues/superiors with urgent requests
- **Payload**: Covenant framework and BeardShell malware

### Key Indicators of Compromise (IOCs)

#### Weaponized Documents
- **Акт.doc** (MD5: 915179579ab7dc358c41ea99e4fcab52)
- **СЛУЖБОВА ХАРАКТЕРИСТИКА.doc** (MD5: 608877a9e11101da53bce99b0effc75b)
- **Акт_про_передачу_обладнання_в_експлуатацію_150425.doc** (MD5: 0fbc2bf2f66fc72c521a9b8561bab1da)

#### Steganographic Payloads
- **windows.png** - PNG file containing encrypted shellcode
- **windows1.png** - Additional steganographic payload
- **windows2.png** - Additional steganographic payload
- **windows3.png** - Additional steganographic payload
- **Koala.png** - Additional steganographic payload

#### Malware Components
- **Covenant Framework** - .NET-based C2 framework
- **GruntHTTPStager** - Covenant component for initial C2 communication
- **BeardShell** - C++ malware using cloud storage for C2
- **SlimAgent** - Spyware component

#### Infrastructure
- **Koofr** - Primary cloud storage for Covenant framework
- **Icedrive** - Cloud storage service for BeardShell C2
- **Signal** - Private messaging platform for spearphishing

## Technical Analysis

### Infection Chain
1. **Initial Delivery**: Malicious Office documents delivered via Signal chat
2. **Document Execution**: VBA macros execute upon document opening
3. **COM Hijacking**: User-level COM hijack to load malicious DLL
4. **Steganography**: Shellcode extracted from PNG files
5. **Covenant Framework**: .NET assembly execution for C2 communication
6. **BeardShell Deployment**: Secondary payload via WAV file and DLL
7. **Persistence**: Long-term persistence through cloud storage C2

### Encryption Details
- **Algorithm**: ChaCha20-Poly1305
- **Key**: F9685510DD90C05856950D86C12CF7A2CC9D148AACC187DDDDFCE0C9EDAE6EE3
- **Nonce**: 12 bytes
- **Tag**: 16 bytes
- **AAD**: 16 bytes

### Steganography Implementation
- **LSB Steganography**: Least significant bit steganography in PNG files
- **Dynamic Size Calculation**: Size calculation based on image data
- **Multiple Payloads**: Various PNG files containing different payloads

## MITRE ATT&CK Mapping

### Initial Access
- **T1566.001**: Spearphishing Attachment
- **T1566.003**: Spearphishing via Service
- **T1078.004**: Valid Accounts: Cloud Accounts

### Execution
- **T1059.001**: Command and Scripting Interpreter: PowerShell
- **T1204.002**: User Execution: Malicious File
- **T1055.012**: Process Injection: Process Hollowing

### Persistence
- **T1505.003**: Server Software Component: Web Shell
- **T1078.004**: Valid Accounts: Cloud Accounts
- **T1053**: Scheduled Task/Job

### Defense Evasion
- **T1027**: Obfuscated Files or Information
- **T1140**: Deobfuscate/Decode Files or Information
- **T1562.001**: Impair Defenses: Disable or Modify Tools

### Command and Control
- **T1071.001**: Application Layer Protocol: Web Protocols
- **T1102.003**: Web Service: OneDrive
- **T1104**: Multi-Stage Channels

### Exfiltration
- **T1041**: Exfiltration Over C2 Channel
- **T1567.002**: Exfiltration Over Web Service: To Cloud Storage

## Detection Recommendations

### Network-Based Detection
- Monitor for connections to Koofr and Icedrive cloud storage services
- Track Signal messaging communications
- Detect encrypted C2 communication patterns
- Monitor cloud storage API calls

### Endpoint Detection
- Monitor Office macro execution
- Track DLL loading activities
- Detect PNG file processing for steganography
- Monitor PowerShell command execution

### Behavioral Detection
- Detect COM hijacking activities
- Monitor steganography processing
- Track cloud storage access patterns
- Detect Covenant framework execution

## Mitigation Strategies

### Technical Controls
- **Email Security**: Advanced email threat protection
- **Office Security**: Macro security and document scanning
- **Endpoint Detection**: EDR solutions for malware detection
- **Network Monitoring**: Cloud storage API monitoring

### Administrative Controls
- **User Training**: Security awareness for spearphishing
- **Signal Security**: Secure messaging practices
- **Document Security**: Secure document handling procedures
- **Cloud Security**: Cloud storage access controls

### Monitoring and Detection
- **Threat Hunting**: Proactive hunting for APT28 activities
- **IOC Monitoring**: Tracking known threat indicators
- **Behavioral Analytics**: Advanced behavioral analysis
- **Cloud Monitoring**: Cloud storage activity monitoring

## MISP Event Details

### Event Information
- **Event ID**: APT28_Operation_Phantom_Net_Voxel
- **Date**: 2025-09-16
- **Threat Level**: High (1)
- **Published**: False
- **Attribute Count**: 30

### Key Attributes
- **Weaponized Documents**: 10 MD5 hashes of malicious Office documents
- **Steganographic Files**: 5 PNG filenames for steganographic payloads
- **Malware Components**: 4 malware family names
- **Infrastructure**: 3 cloud services and communication platforms
- **Encryption**: 2 encryption-related attributes

### Tags Applied
- **Threat Actor**: APT28, Sofacy, Fancy Bear, BlueDelta, Forest Blizzard, TAG-110
- **Country**: Russia, Ukraine
- **Malware**: Covenant Framework, BeardShell, SlimAgent, GruntHTTPStager
- **Tools**: Signal, Koofr, Icedrive
- **MITRE ATT&CK**: 20+ technique mappings

## Conclusion

The APT28 Operation Phantom Net Voxel campaign represents a sophisticated and well-resourced threat operation targeting Ukrainian military personnel. The use of private Signal messaging, advanced steganography, and cloud storage for C2 operations demonstrates the evolving tactics of state-sponsored threat actors.

Organizations should implement comprehensive security measures including advanced email protection, endpoint detection and response, network monitoring, and user training to defend against similar campaigns.

---

**Report Date**: September 16, 2025  
**Threat Level**: High  
**Confidence Level**: High  
**Source**: [Sekoia.io Blog - APT28 Operation Phantom Net Voxel](https://blog.sekoia.io/apt28-operation-phantom-net-voxel/)  
**Last Updated**: September 16, 2025

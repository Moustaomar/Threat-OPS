Dears,
Hoping all is good at your side

Threat Intelligence Team has identified an active campaign by the NXSMS/OPERA1ER/Common Raven threat group targeting financial institutions, government entities, and healthcare organizations in West Africa. This represents a sophisticated APT operation with advanced capabilities including Cobalt Strike variants, custom malware families, and extensive infrastructure.

MISP Event: NXSMS/OPERA1ER/Common Raven: Advanced Persistent Threat targeting financial institutions and government entities in West Africa - Complete IOC and MITRE ATT&CK Analysis

Key Findings
•	Active Campaign: Ongoing since Q4 2024 with 500+ IOCs identified
•	Targeted Sectors: Financial Institutions, Government, Healthcare
•	Geographic Scope: West Africa (Senegal, Ivory Coast, Mali, Burkina Faso)
•	Attack Vector: Spearphishing with banking-themed lures and security software impersonation
•	Malware Families: Cobalt Strike variants, custom malware, banking trojans
•	Detection Method: Auger Prediction-Based (94.7% confidence)

Immediate Actions Required
1.	Block all C2 infrastructure IPs (196.251.x.x range, warii.club domains)
2.	Implement enhanced PowerShell monitoring and execution policy restrictions
3.	Monitor for IOCs across all systems and network traffic
4.	Update email security controls for suspicious attachments and links

Threat Actor Profile
NXSMS/OPERA1ER/Common Raven (Multiple Aliases)
Attribute	Details
Country	🇸🇳 Senegal (Suspected)
Motivation	Financial gain and espionage
Capabilities	Advanced malware development, infrastructure management, social engineering
Threat Level	HIGH - Sophisticated APT with extensive resources
Infrastructure	500+ IOCs across multiple C2 networks

Previous Campaigns
Date	Target	Method	Status
Q4 2024	Financial Institutions	Banking-themed phishing	ACTIVE
Q4 2024	Government Entities	Security software impersonation	ACTIVE
Q4 2024	Healthcare Organizations	Healthcare-themed lures	ACTIVE

Common Raven conducts both targeted campaigns against financial institutions and opportunistic attacks against government and healthcare sectors. The group demonstrates sophisticated capabilities in malware development, infrastructure management, and social engineering techniques.

Threat Actor Relationships
Common Raven operates under multiple aliases (NXSMS, OPERA1ER) and maintains relationships with various infrastructure providers and malware developers. The group demonstrates advanced capabilities across multiple attack vectors and maintains extensive C2 infrastructure.

Infrastructure Analysis
Common Raven C2 Network - Distributed Infrastructure
Infrastructure Details	Information
Primary C2 Range	196.251.x.x (Senegal-based)
Secondary Infrastructure	Global distribution across multiple providers
Domain Infrastructure	warii.club, ddrive.online, eimaragon.org
Dynamic DNS	Multiple DDNS providers for infrastructure rotation
Malware Distribution	files.ddrive.online, various phishing domains
Status	ACTIVE AND EXPANDING

Technical Analysis
The Common Raven infrastructure demonstrates sophisticated capabilities including:
•	Multi-stage malware deployment with banking trojan capabilities
•	Advanced evasion techniques and anti-analysis measures
•	Extensive use of legitimate services for C2 communication
•	Dynamic infrastructure rotation and redundancy

IOCs Summary
Network Indicators: 500+ IP addresses and domains
File Indicators: 200+ malware samples and tools
Behavioral Indicators: PowerShell execution patterns, network scanning activities

Recommendations
1.	Immediate blocking of all identified C2 infrastructure
2.	Enhanced monitoring for PowerShell-based attacks
3.	Implementation of application whitelisting
4.	Regular security awareness training for staff
5.	Network segmentation and access controls

Contact Information
For questions or additional information, please contact the Threat Intelligence Team.

Best regards,
Threat Intelligence Team

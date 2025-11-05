# MISP Report - MuddyWater Espionage (Group-IB)

## Executive Summary
MuddyWater (Iran-linked) conducted an espionage campaign leveraging custom Windows backdoors (`mononoke.exe`, `sysProcUpdate`) and HTTPS-based C2 infrastructure (`screenai.online`, created 2025-08-17). Multiple SHA256 samples were observed. The activity aligns with prior MuddyWater TTPs including PowerShell-based execution and web protocol C2.

## Campaign Overview
- **Campaign Name:** MuddyWater_Espionage_Campaign_GroupIB
- **Threat Actor:** MuddyWater
- **Target:** Government and telecom entities (per Group-IB)
- **Threat Level:** High
- **Date:** 2025-11-05
- **Source:** https://www.group-ib.com/blog/muddywater-espionage/

## Threat Intelligence Summary
### Primary Attack Vectors
- Likely spearphishing or exploitation of public-facing services (to be confirmed).

### Key Indicators of Compromise (IOCs)
- Domain: `screenai.online` (Creation date: 2025-08-17)
- SHA256 (mononoke.exe):
  - 668dd5b6fb06fe30a98dd59dd802258b45394ccd7cd610f0aaab43d801bf1a1e
  - 5ec5a2adaa82a983fcc42ed9f720f4e894652bd7bd1f366826a16ac98bb91839
- SHA256 (sysProcUpdate):
  - 1883db6de22d98ed00f8719b11de5bf1d02fc206b89fedd6dd0df0e8d40c4c56
  - 3ac8283916547c50501eed8e7c3a77f0ae8b009c7b72275be8726a5b6ae255e3
  - 76fa8dca768b64aefedd85f7d0a33c2693b94bdb55f40ced7830561e48e39c75
  - 3d6f69cc0330b302ddf4701bbc956b8fca683d1c1b3146768dcbce4a1a3932ca

## Technical Analysis
### Attack Techniques
- T1059.001 PowerShell (execution)
- T1071.001 Web Protocols (C2)
- T1547.001 Registry Run Keys (persistence; likely)
- T1573 Encrypted Channel (C2)

### Malware Capabilities
- `mononoke.exe`, `sysProcUpdate`: Windows backdoors enabling command execution and remote control; further capabilities pending deeper analysis.

## MITRE ATT&CK Mapping
- Execution: T1059.001, T1059.003
- Persistence: T1547.001, T1053.005
- Command and Control: T1071.001, T1573
- Initial Access: T1566.001 or T1190 (pending confirmation)

## Detection Recommendations
- Block/alert on DNS/HTTPS to `screenai.online`.
- Detect PowerShell with encoded commands and suspicious parent processes.
- Monitor creation of Run keys and scheduled tasks linked to observed filenames.

## Mitigation Strategies
- Email hardening, attachment detonation, macro policy enforcement.
- Restrict script execution to signed code; apply EDR hardening for LOLBins.
- Perimeter blocklists for domain and any resolved IPs.

## MISP Event Details
- **Event ID:** (populate after import)
- **Date:** 2025-11-05
- **Threat Level:** High
- **Attribute Count:** 9



# URGENT: NXSMS/OPERA1ER/Common Raven Threat Actor Alert
**From:** Threat Intelligence Team  
**To:** SOC Team, DFIR Team, Adversary Emulation Team  
**Subject:** HIGH PRIORITY - Active NXSMS/OPERA1ER/Common Raven Campaign Targeting Financial & Government Sectors  
**Date:** January 27, 2025  
**Classification:** TLP:AMBER  
**Threat Level:** CRITICAL  

---

## 🚨 EXECUTIVE SUMMARY

**Threat Actor:** NXSMS/OPERA1ER/Common Raven  
**Status:** ACTIVE CAMPAIGN  
**Target Sectors:** Financial Institutions, Government Entities, Healthcare  
**Geographic Focus:** West Africa (Senegal, Ivory Coast, Mali, Burkina Faso)  
**Primary Motivation:** Financial Gain & Espionage  
**Infrastructure:** 500+ IOCs Available  
**Detection Method:** Auger Prediction-Based Threat Intelligence  
**Confidence Level:** HIGH (Auger Prediction + Threat Intelligence Correlation)  

---

## 📋 IMMEDIATE ACTIONS REQUIRED

### 🔴 SOC TEAM - URGENT BLOCKING REQUIRED

**Priority 1: Network Blocking (IMMEDIATE)**
```
CRITICAL IPs TO BLOCK:
- 196.251.88.198 (Primary C2 - Ports: 4444,443,22)
- 196.251.118.208 (Primary C2 - Ports: 3389,22,443,4444,5985,139,80)
- 196.251.117.251 (Primary C2 - Ports: 443,22,4444,3306,143,8888,110,21)
- 192.71.249.50 (Additional C2)
- 206.123.145.172 (Secondary C2)
- 148.113.172.197 (Secondary C2)
- 45.149.241.239 (Secondary C2)
```

**Priority 2: Domain Blocking (IMMEDIATE)**
```
CRITICAL DOMAINS TO BLOCK:
- cobalt.warii.club (Cobalt Strike C2)
- wari.warii.club (C2 Infrastructure)
- warima.warii.club (C2 Infrastructure)
- banqueislamik.ddrive.online (Phishing)
- news.coris-bank.fr (Banking Phishing)
- update.mcafee-endpoint.com (Security Impersonation)
- download.nortonupdate.com (Security Impersonation)
```

### 🔴 DFIR TEAM - INVESTIGATION REQUIRED

**Priority 1: System Analysis**
- Check for PowerShell execution logs
- Analyze network connections to C2 infrastructure
- Review process injection activities
- Examine credential dumping attempts

**Priority 2: Memory Analysis**
- Look for Cobalt Strike artifacts
- Check for process hollowing techniques
- Analyze DLL injection patterns
- Review anti-analysis evasion techniques

### 🔴 ADVERSARY EMULATION TEAM - TTP ANALYSIS

**Priority 1: TTP Mapping**
- Map observed techniques to MITRE ATT&CK framework
- Identify gaps in current detection capabilities
- Develop emulation scenarios for testing
- Create detection rules for new techniques

**Priority 2: Infrastructure Analysis**
- Analyze C2 communication patterns
- Map infrastructure relationships
- Identify infrastructure rotation techniques
- Document evasion and persistence mechanisms

---

## 🎯 THREAT ACTOR PROFILE

**NXSMS/OPERA1ER/Common Raven**
- **Country:** Senegal (Suspected)
- **Motivation:** Financial gain and espionage
- **Capabilities:** Advanced malware development, infrastructure management, social engineering
- **Threat Level:** HIGH - Sophisticated APT with extensive resources
- **Infrastructure:** 500+ IOCs across multiple C2 networks
- **Active Since:** 2018
- **Target Sectors:** Financial, Government, Healthcare

---

## 🔍 TECHNICAL ANALYSIS

**Malware Families:**
- Cobalt Strike variants
- Custom banking trojans
- PowerShell-based tools
- Process injection frameworks

**Attack Vectors:**
- Spearphishing with banking themes
- Security software impersonation
- Healthcare-themed lures
- Social engineering campaigns

**Infrastructure:**
- Primary C2: 196.251.x.x range (Senegal)
- Secondary: Global distribution
- Domains: warii.club, ddrive.online, eimaragon.org
- Dynamic DNS: Multiple providers for rotation

---

## 📊 IOC SUMMARY

**Network Indicators:** 500+ IP addresses and domains
**File Indicators:** 200+ malware samples and tools
**Behavioral Indicators:** PowerShell execution patterns, network scanning

---

## 🛡️ RECOMMENDATIONS

1. **Immediate blocking** of all identified C2 infrastructure
2. **Enhanced monitoring** for PowerShell-based attacks
3. **Implementation** of application whitelisting
4. **Regular security awareness** training for staff
5. **Network segmentation** and access controls

---

**Contact:** Threat Intelligence Team for additional information

# URGENT: NXSMS/OPERA1ER/Common Raven Threat Alert
**From:** Threat Intelligence Team  
**To:** SOC Team, DFIR Team, Adversary Emulation Team  
**Subject:** CRITICAL - NXSMS/OPERA1ER/Common Raven Active Campaign  
**Date:** January 27, 2025  
**Classification:** TLP:AMBER  
**Threat Level:** CRITICAL  

---

## 🚨 EXECUTIVE SUMMARY

**Threat Actor:** NXSMS/OPERA1ER/Common Raven  
**Status:** ACTIVE CAMPAIGN  
**Targets:** Financial Institutions, Government, Healthcare  
**Focus:** West Africa (Senegal, Ivory Coast, Mali, Burkina Faso)  
**Motivation:** Financial Gain & Espionage  
**Detection:** Auger Prediction-Based (94.7% confidence)  
**IOCs:** 500+ indicators available  

---

## 📋 IMMEDIATE ACTIONS

### 🔴 SOC TEAM - BLOCK NOW
**Critical IPs:** 196.251.88.198, 196.251.118.208, 196.251.117.251, 192.71.249.50  
**Critical Domains:** cobalt.warii.club, wari.warii.club, banqueislamik.ddrive.online  
**Critical Hashes:** See IOC file for complete list  

**Alert Rules (24h):**
- PowerShell execution monitoring
- Network connections to C2 infrastructure
- Process injection activities
- Credential dumping attempts

### 🔴 DFIR TEAM - INVESTIGATE
**Priority Systems:** Check for PowerShell logs, C2 connections, process injection
**Memory Analysis:** Look for Cobalt Strike artifacts, process hollowing
**Network Analysis:** Review connections to 196.251.x.x range

### 🔴 EMULATION TEAM - ANALYZE
**TTP Mapping:** Map to MITRE ATT&CK framework
**Infrastructure:** Analyze C2 patterns and rotation techniques
**Detection Gaps:** Identify missing detection capabilities

---

## 🎯 THREAT PROFILE
**Country:** Senegal (Suspected)  
**Capabilities:** Advanced malware, infrastructure management, social engineering  
**Infrastructure:** 500+ IOCs across multiple C2 networks  
**Active Since:** 2018  

---

## 🔍 KEY FINDINGS
- **Malware:** Cobalt Strike variants, banking trojans, PowerShell tools
- **Attack Vectors:** Spearphishing, security software impersonation
- **Infrastructure:** Primary C2 in 196.251.x.x range, global distribution
- **Evasion:** Anti-analysis techniques, process injection, credential dumping

---

## 🛡️ RECOMMENDATIONS
1. **Block all C2 infrastructure** immediately
2. **Monitor PowerShell execution** and network connections
3. **Implement application whitelisting** and network segmentation
4. **Update email security** for suspicious attachments/links
5. **Conduct security awareness** training

---

**Contact:** Threat Intelligence Team for additional information

### Subject
**Action required: APT41 latest campaign coverage – IOCs, detections, hunts, and emulation**

Hello All,

I hope this message finds you well.
We are issuing an urgent threat intelligence update regarding recent activity attributed to APT41, also known as Double Dragon, BARIUM, and Winnti Group. APT41 is assessed as PRC-linked with a dual mandate of espionage and financially motivated operations. Target sectors include government, technology, healthcare, education, telecommunications, energy, finance, and manufacturing across multiple regions, with a recent expansion into African government IT services.

Threat Actor Profile: APT41 (Double Dragon / BARIUM / Winnti Group)

- Delivery Methods:
  - Spear‑Phishing: Links and lures leveraging URL shorteners (tinyurl.com, lihi.cc, reurl.cc) and themed domains.
  - Exploits/Abuse of Services: SharePoint‑centric C2, domain fronting via Cloudflare Workers and Microsoft workers; ngrok tunnels.
  - Malware Distribution: mshta‑delivered HTA from shorteners and custom delivery domains (my5353.com), hosting on InfinityFree and Cloudflare Workers.
  - Malware Families: ShadowPad, TOUGHPROGRESS, GDrive Moonwalk, DodgeBox Dropper, StealthVector.

- Command and Control (C2):
  - Tools: Impacket (Atexec, WmiExec), Cobalt Strike, Mimikatz, RawCopy, Pillager, Checkout.
  - Cloud/Services: trycloudflare.com, msapp.workers.dev, infinityfreeapp.com, ngrok-free.app, Google Calendar API (/calendar/v3/.../events).
  - Infrastructure: Russian‑hosted clusters (e.g., drproxy.pro, kacer11.ru, leadd12.ru), dynamic DNS (ddns.net, ddnsking.com), Vultr subdomains.

- Operational Patterns:
  - SharePoint C2 via web shells (`CommandHandler.aspx`, `spinstall0.aspx`) and `debug_dev.js` in Layouts paths.
  - DLL sideloading using `rundll32.exe` with `agents.exe` / `agentx.exe`.
  - Environment checks: WMIC OS locale queries and registry `Control\\International` reads.
  - Frequent infra refresh via URL shorteners and brand impersonation (githubassets.net, `*.shop`).

Recent Activity

Our latest analysis (July 2025) indicates APT41 is actively targeting African government IT services using new operational infrastructure and updated malware:
- ShadowPad backdoors and TOUGHPROGRESS loaders leveraging cloud services (Cloudflare, Microsoft workers) and the Google Calendar API for C2.
- Delivery via mshta‑executed HTA from URL shorteners and custom domain `my5353.com`.
- Infrastructure spans dynamic DNS, Vultr, and RU‑hosted clusters; SharePoint web shells present on victim infrastructure.

Recommended Actions

@Security_DFIR
- Initiate immediate threat hunting across the environment. MISP Event: `MISP JSON Event/APT41_MISP_Event.json` (screenshots to be embedded). After import, reference the assigned Event ID.
- Focus on:
  - SharePoint server artifacts: `\15\TEMPLATE\LAYOUTS\debug_dev.js`, `CommandHandler.aspx`, `spinstall0.aspx`.
  - WMIC process create and OS locale queries; registry `Control\\International` reads.
  - SMB transfers of `agents.exe`, `agentx.exe`, and web shells.
  - Network telemetry for Google Calendar API `/calendar/v3/.../events`, Cloudflare/Microsoft workers, InfinityFree, ngrok tunnels, and rare outbound to RU cluster domains.

@Security_SOC
- Block/monitor all IOCs across environments (see `APT/APT41/APT41_IOCs.csv`).
- Deploy detection rules from `APT/APT41/APT41_Detection_Rules.csv` and Sigma in `sigma_rules/APT41/`:
  - High priority: SP webshells, mshta/shorteners, Google Calendar C2, WMI exec, `rundll32` + agents*, cloud tunnels/workers, RU cluster, dynamic DNS, Vultr pattern.
- Create watchlists for domain patterns and tune around legitimate developer tunnels/PAAS usage.

@Security_Adversary_Emulation
- Emulate APT41 TTPs using the comprehensive profile in `APT/APT41/APT41_Full_Profile.md`.
- Focus on:
  - SharePoint web shell deployment and C2 communication
  - DLL sideloading with custom executables
  - WMI execution patterns and environment enumeration
  - Cloud service abuse for C2 communication
  - URL shortener abuse for payload delivery

@Security_Threat_Intelligence
- Monitor for new APT41 infrastructure and TTP evolution
- Track ShadowPad and TOUGHPROGRESS malware families
- Analyze cloud service abuse patterns
- Monitor for new targeting patterns and geographic expansion

Additional Resources

- **Comprehensive Analysis**: `APT/APT41/APT41_comprehensive_analysis.md`
- **CTI Profile**: `APT/APT41/APT41_CTI_Profile.csv`
- **Detection Rules**: `APT/APT41/APT41_Detection_Rules.csv`
- **Full Profile**: `APT/APT41/APT41_Full_Profile.md`
- **IOCs**: `APT/APT41/APT41_IOCs.csv`
- **MISP Event**: `MISP JSON Event/APT41_MISP_Event.json`

Please confirm receipt and provide status updates on implementation progress.

Best regards,
Threat Intelligence Team

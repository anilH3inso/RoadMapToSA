🚀 7-Month Senior Cybersecurity Analyst Bootcamp

A complete, day-by-day roadmap in GitHub README format — with domains, subdomains, modules, hours, and revision built in.

> Structure

6 study days + 1 review/rest day each week

4–6 focused hours/day (scale to your schedule)

Domains → Subdomains → Modules with direct resources

Weekly deliverables (reports/rules/scripts) to build your portfolio

Revision system (daily/weekly/monthly)





---

🧭 Table of Contents

How to Use

Lab & Tool Setup (Week 0)

Tracking Template

Month 1 — Core Security Foundations (Weeks 1–4)

Month 2 — SOC Operations & Threat Detection (Weeks 5–8)

Month 3 — Incident Response & Forensics (Weeks 9–12)

Month 4 — Threat Hunting & Detection Engineering (Weeks 13–16)

Month 5 — Vulnerability Management & Cloud Security (Weeks 17–20)

Month 6 — Advanced Red & Blue Skills (Weeks 21–24)

Month 7 — Senior Integration, Capstone & Revision (Weeks 25–28)

Certification Alignment

Portfolio Checklist

Notes & Tips



---

How to Use

1. Commit to 4–6 hours/day (e.g., 2 × 2-hour blocks + 30-min recap).


2. Follow the daily plan below (Days 1–6 = study/labs, Day 7 = review).


3. Ship weekly deliverables (reports/rules/scripts) into your GitHub portfolio/ folder.


4. Log findings in notes/ using daily markdown pages.


5. Monthly re-tests: rerun labs, re-answer key questions, refine detections.




---

Lab & Tool Setup (Week 0)

> Do this before Week 1. (~10–12 hours total)



Virtualization & OS

VirtualBox or VMware Workstation Player

Linux VM (Ubuntu Server), Windows 10/11 Eval, Windows Server Eval


Network & Traffic

Wireshark, tcpdump, curl, nmap


Blue Team

Splunk Free / Elastic Stack, Security Onion (for Month 7)


DFIR & Malware

Autopsy, Volatility, REMnux (Linux), FLARE VM (Win)


Offensive

Burp Suite Community, Metasploit, SecLists, wordlists


Cloud

AWS Free Tier, Azure Free/Try (pay-as-you-go with budget alerts)


Repos

notes/, detections/ (Sigma/YARA/Snort), scripts/ (Python/PS/Bash), reports/




---

Tracking Template

Copy to notes/weekly_log.md each week.

### Week X Log (Dates)
- Hours planned / done:
- Domain/Subdomain:
- Labs completed:
- Key wins:
- Gaps:
- Portfolio artifacts shipped:
- Next-week focus:

Daily block (copy per day):

**Day N (4–6h)**
- [ ] 2h Theory
- [ ] 2–3h Labs
- [ ] 30m Recap (notes/flashcards)
Links:
Takeaways:


---

Month 1 — Core Security Foundations (Weeks 1–4)

Week 1 — Networking Fundamentals (TCP/IP, DNS, HTTP/S, VPN, NAT, Firewalls)

Resources:
Cisco NetAcad (Intro) • Practical Networking (YT) • Cloudflare DNS • Wireshark tutorial

Deliverable: reports/w01_network_baseline.md (your home lab network map + captures)


Day 1 (4–6h): Intro to networks → NetAcad Basics → notes
Day 2: TCP/IP model & ports → Practical Networking TCP/IP → flashcards
Day 3: DNS deep dive → Cloudflare DNS Guide → nslookup/dig labs
Day 4: HTTP/S & TLS → Cloudflare TLS → capture HTTPS handshake
Day 5: NAT/VPN/Firewalls → home router rules demo
Day 6: Wireshark install + capture LAN/HTTPS/DNS • Wireshark Filters
Day 7 (Review): Summaries + retest + finalize report


---

Week 2 — Networking Analysis (PCAP workflow)

Resources: Wireshark sample captures • Varonis Wireshark tutorial • Malware-Traffic-Analysis

Deliverable: reports/w02_pcap_findings.md (3 suspicious PCAP cases)


Day 1: Advanced display filters & profiles
Day 2: TCP handshake analysis + resets/retransmissions
Day 3: HTTP analysis lab → Varonis Guide
Day 4: DNS tunneling/suspicious patterns
Day 5: Analyze 2 PCAPs → Malware Traffic Analysis
Day 6: Write-up of 3rd PCAP (IOC table + hypotheses)
Day 7 (Review): Recap + checklist


---

Week 3 — OS Admin Basics (Linux & Windows)

Resources: OverTheWire Bandit • Linux Journey • Microsoft Learn (Windows)

Deliverable: scripts/os_admin/ (user mgmt scripts) + reports/w03_os_hardening.md


Day 1: Linux CLI → OverTheWire Bandit
Day 2: Linux admin (services, logs, journald) → Linux Journey
Day 3: Windows admin (users, groups, services) → MS Learn Modules
Day 4: Filesystems & permissions (Linux chmod, Win icacls)
Day 5: Audit policies & basic hardening both OS
Day 6: Script user creation + baseline hardening (Bash/PowerShell)
Day 7 (Review): Summaries + test scripts


---

Week 4 — Security Fundamentals (CIA, Crypto, Security+)

Resources: NIST CSF • Prof. Messer Sec+ (SY0-701)

Deliverable: notes/secplus_flashcards.md + reports/w04_first_nmap.md


Day 1: CIA, risk, threats → NIST CSF
Day 2: Crypto basics (sym/asym, hashing, PKI)
Day 3: Certs/TLS chain, OCSP, HSTS
Day 4: Security+ playlist → Professor Messer
Day 5: Tooling survey (Nmap/Nessus/Splunk)
Day 6: First Nmap scans + service fingerprinting
Day 7 (Review): Sec+ quiz + flashcards


---

Month 2 — SOC Operations & Threat Detection (Weeks 5–8)

Week 5 — SOC Foundations (Triage, Playbooks, Metrics)

Resources: Cyber Kill Chain • CyberDefenders roadmap • BTL1 (optional)

Deliverable: playbooks/triage_playbook.md (email/phishing, brute force, malware beacon)


Day 1: SOC roles & metrics (MTTD/MTTR) + Kill Chain
Day 2: Triage process & enrichment checklists
Day 3: Build initial playbooks (email/phishing)
Day 4: Playbook (auth anomalies)
Day 5: Playbook (endpoint malware)
Day 6: Run 1–2 challenges → CyberDefenders
Day 7 (Review): Tune playbooks


---

Week 6 — SIEM Essentials (Splunk/Elastic/Sentinel)

Resources: Splunk Free + Fundamentals • Elastic SIEM • Sentinel docs

Deliverable: detections/siem_queries/ (10 saved searches) + reports/w06_bots_writeup.md


Day 1: Splunk install & ingestion → syslog, windows logs
Day 2: SPL primers (stats, eval, rex, timechart) → 3 queries
Day 3: Elastic SIEM basics → parity queries
Day 4: Microsoft Sentinel intro & KQL parity
Day 5: BoTS dataset mini-hunt (Splunk)
Day 6: Write-up: findings + dashboards
Day 7 (Review): Refactor saved searches


---

Week 7 — Threat Intelligence (MITRE ATT&CK, IOCs)

Resources: MITRE ATT&CK/Navigator • AlienVault OTX • MISP

Deliverable: threat_models/technique_maps/ + reports/w07_intel_enrichment.md


Day 1: ATT&CK overview & Navigator heatmaps
Day 2: Map 2 ATT&CK techniques to logs/detections
Day 3: IOC lifecycle, feeds, OTX lookups
Day 4: MISP basics (if available) + STIX/TAXII
Day 5: Build enrichment checklist (whois, VT*, GeoIP)
Day 6: Case study: enrich alerts from Week 6
Day 7 (Review): Update maps & gaps

*VT = VirusTotal (use free quota mindfully)


---

Week 8 — Incident Workflow (Containment → Recovery)

Resources: NIST 800-61r2 • BlueTeamLabs.online

Deliverable: reports/w08_incident_report.md (full IR write-up)


Day 1: IR lifecycle & comms plan → NIST 800-61
Day 2: Evidence handling & chain of custody
Day 3: Containment strategies (endpoint, network, cloud)
Day 4: Eradication & recovery + lessons learned
Day 5: IR challenge → BlueTeamLabs.online
Day 6: Draft IR report template & populate
Day 7 (Review): Peer-review yourself + finalize


---

Month 3 — Incident Response & Forensics (Weeks 9–12)

Week 9 — IR Methodology Deep Dive

Deliverable: runbooks/ir_runbook.md + tabletop scenario notes


Day 1: Prepare IR runbook (roles/tools/flows)
Day 2: Build triage checklists per data source
Day 3: Tabletop #1 (phishing → initial access)
Day 4: Tabletop #2 (ransomware in SMB)
Day 5: Tabletop #3 (cloud account takeover)
Day 6: Consolidate lessons & gaps
Day 7 (Review): Update runbook


---

Week 10 — Disk Forensics (Autopsy)

Resources: Autopsy docs • DFIR.training images

Deliverable: reports/w10_timeline_analysis.md + artifacts


Day 1: Imaging, hashing, verification
Day 2: Autopsy workflow (ingest, keyword, hash sets)
Day 3: File system & artifacts (prefetch, shimcache)
Day 4: Browser/email artifacts, LNK, jump lists
Day 5: Build timeline (MACB) on sample image
Day 6: Write report + IOC table
Day 7 (Review): Validate timeline


---

Week 11 — Memory Forensics (Volatility)

Resources: Volatility docs

Deliverable: reports/w11_mem_forensics.md + detections/yara/ (2 rules)


Day 1: Acquire memory & profiles
Day 2: Processes, DLLs, handles, netscan
Day 3: Detect injection/persistence in RAM
Day 4: Extract strings/yara scan memory
Day 5: Map finds to ATT&CK techniques
Day 6: Write two YARA rules from samples
Day 7 (Review): Re-run with new profile


---

Week 12 — Malware Analysis (Static + Dynamic)

Resources: REMnux • FLARE VM • Malware-Traffic-Analysis

Deliverable: reports/w12_malware_case.md + sandbox/profiles/


Day 1: Lab safety & OPSEC, hash triage
Day 2: Static: PE headers, imports, strings
Day 3: Dynamic: sandbox run, behavior, IOCs
Day 4: Network indicators & protocol decoding
Day 5: Family classification & signature ideas
Day 6: Draft report, propose detections
Day 7 (Review): Refine YARA/Sigma


---

Month 4 — Threat Hunting & Detection Engineering (Weeks 13–16)

Week 13 — Hunting Fundamentals

Deliverable: hunts/week13_hypotheses.md + 2 hunt write-ups


Day 1: Hypothesis framework (intel + environment)
Day 2: Data coverage mapping (winlogbeat/sysmon/EDR)
Day 3: Hunt #1 (lateral movement)
Day 4: Hunt #2 (credential access)
Day 5: Document queries/evidence/gaps
Day 6: Share findings → create follow-up tasks
Day 7 (Review): Consolidate


---

Week 14 — Detection Rules (Sigma, YARA, Snort)

Resources: SigmaHQ • YARA docs

Deliverable: detections/sigma/*.yml (5 rules) + unit tests


Day 1: Sigma anatomy & field mapping
Day 2: Convert 2 hunts to Sigma rules
Day 3: YARA authoring (file & mem)
Day 4: Snort/Suricata (basic rules)
Day 5: Write tests & simulate alerts
Day 6: Peer-review your rules, add metadata
Day 7 (Review): Package ruleset


---

Week 15 — Adversary Emulation (Atomic Red Team, Caldera)

Deliverable: adversary/atomic_runs.md + detection coverage map


Day 1: Setup Atomic Red Team (map safe tests)
Day 2: Execute select TTPs (collection/exfil)
Day 3: MITRE Caldera plan (priv-esc, persistence)
Day 4: Capture telemetry, validate alerts
Day 5: Tune queries, reduce FPs
Day 6: Update coverage matrix (techniques → signals)
Day 7 (Review): Close gaps


---

Week 16 — Purple Teaming (Validate & Tune)

Deliverable: reports/w16_purple_findings.md (before/after metrics)


Day 1: Select 6–8 high-value TTPs
Day 2: Run & observe (pre-tuning)
Day 3: Tune detections & thresholds
Day 4: Re-run (post-tuning), measure MTTD
Day 5: Document deltas & remaining gaps
Day 6: Roll into SIEM content pack
Day 7 (Review): Finalize report


---

Month 5 — Vulnerability Management & Cloud Security (Weeks 17–20)

Week 17 — Vulnerability Scanning (Nessus/OpenVAS)

Deliverable: reports/w17_vuln_scan.md + risk_register.xlsx


Day 1: Scanner setup, authenticated scans
Day 2: Scan Linux/Windows lab hosts
Day 3: Triage criticals, verify manually
Day 4: Recommend remediations & compensating controls
Day 5: Build risk register + SLAs
Day 6: Executive summary (1-pager)
Day 7 (Review): Validate findings


---

Week 18 — Patch Management & Risk (CVSS/CVE/NVD)

Resources: NVD • CVSS calculator

Deliverable: reports/w18_patch_plan.md


Day 1: CVSS v3.1 deep dive, calculate scores
Day 2: CVE research workflow, KEV catalog check
Day 3: Prioritization model (exploitability/exposure)
Day 4: Patch rollout plan + change mgmt
Day 5: Verification plan (post-patch scans)
Day 6: Draft policy snippet for vuln mgmt
Day 7 (Review): Tighten plan


---

Week 19 — AWS Security

Resources: AWS Well-Architected (Security) • CloudTrail/Config/IAM

Deliverable: cloud/aws_secure_baseline.md + guardrails


Day 1: IAM fundamentals (least privilege, roles)
Day 2: S3 security (block public access, SSE)
Day 3: Logging: CloudTrail/Config/GuardDuty
Day 4: Network: SGs, NACLs, VPC flow logs
Day 5: Hands-on: misconfig → detect → fix
Day 6: Draft SCPs/guardrails (if org)
Day 7 (Review): Checklist & IaC notes


---

Week 20 — Azure Security

Resources: Azure AD/Entra • Sentinel

Deliverable: cloud/azure_secure_baseline.md


Day 1: Entra ID basics (users, roles, PIM)
Day 2: Conditional Access & MFA
Day 3: Defender for Cloud / MDE integrations
Day 4: Sentinel data connectors & analytics rules
Day 5: Build 3 KQL detections
Day 6: Hardening checklist
Day 7 (Review): Summarize & compare AWS/Azure


---

Month 6 — Advanced Red & Blue Skills (Weeks 21–24)

Week 21 — Web App Security (OWASP Top 10)

Resources: OWASP Top 10 • Juice Shop

Deliverable: reports/w21_webapp_findings.md + detections/web_rules/


Day 1: A01–A03 overview & Juice Shop setup
Day 2: Auth/Session vulns (A07)
Day 3: Input vulns (A03/A08)
Day 4: Access control (A01) & IDORs
Day 5: Map attacks to logs/detections (WAF/SIEM)
Day 6: Draft Sigma for web auth abuse
Day 7 (Review): Clean write-up


---

Week 22 — Pentest Basics (Recon → Exploit → Pivot)

Deliverable: reports/w22_pentest_lab.md


Day 1: Recon (Amass, Nmap, dirb/gobuster)
Day 2: Exploit basics (Metasploit/manual)
Day 3: Post-exploitation (persistence, loot)
Day 4: Password attacks (hashcat, wordlists)
Day 5: Priv-esc footholds
Day 6: Ethics, scope, ROE, reporting
Day 7 (Review): Finalize report


---

Week 23 — Privilege Escalation (Win & Linux)

Resources: GTFOBins • winPEAS/linPEAS

Deliverable: notes/priv_esc_playbook.md + PoC steps


Day 1: Linux priv-esc primitives (SUID, PATH, capabilities)
Day 2: Windows priv-esc (UAC, services, tokens)
Day 3: winPEAS/linPEAS guided runs
Day 4: Manual exploitation of 2 paths each
Day 5: Persistence techniques (registry, crons)
Day 6: Map detectable artifacts → detections
Day 7 (Review): Consolidate


---

Week 24 — Detection Enhancement (Close the Loop)

Deliverable: detections/content_pack_v1/ + reports/w24_detection_delta.md


Day 1: Review past attacks → missed signals
Day 2: Author new Sigma/KQL/Splunk rules
Day 3: E2E test against emulations
Day 4: False positive pruning & thresholds
Day 5: Dashboards & alert routing
Day 6: Package content pack v1
Day 7 (Review): Metrics & next steps


---

Month 7 — Senior Integration, Capstone & Revision (Weeks 25–28)

Week 25 — Capstone IR Simulation (End-to-End)

Deliverable: capstone/incident_X/ (evidence, notes, final IR report)


Day 1: Scenario brief & scoping
Day 2: Collection (host + network + cloud)
Day 3: Analysis & timeline
Day 4: Containment/eradication plan
Day 5: Lessons learned + metrics
Day 6: Executive & technical reports
Day 7 (Review): QA + polish


---

Week 26 — Threat Modeling (Org-level)

Deliverable: threat_models/org_tmm.md + mitigations roadmap


Day 1: Choose reference architecture
Day 2: Identify assets & trust boundaries
Day 3: STRIDE / Kill Chain mapping
Day 4: Prioritize top 10 risks
Day 5: Map to detections/controls
Day 6: Present slide deck (store in repo)
Day 7 (Review): Iterate


---

Week 27 — SOC Process Design (Operate Like Senior)

Deliverable: soc/handbook.md + soc/runbooks/*.md


Day 1: Alert lifecycle & SLOs
Day 2: Intake model (use cases → rules → dashboards)
Day 3: Playbook catalog & versioning
Day 4: Quality program (QA, FPR, post-incident)
Day 5: Training & onboarding plan
Day 6: Tooling roadmap (12-month)
Day 7 (Review): Finalize


---

Week 28 — Full Revision & Portfolio Shipping

Deliverable: portfolio/README.md with links to best work


Day 1: Re-run toughest labs (DFIR/malware)
Day 2: Re-hunt 2 TTPs with tuned detections
Day 3: Re-scan vuln lab & validate fixes
Day 4: Clean/organize repo, add screenshots
Day 5: Write “lessons learned” essay (2 pages)
Day 6: Final mock interview Q&A (self)
Day 7 (Rest): You earned it


---

Certification Alignment

Month 1–2: CompTIA Security+ (SY0-701), Microsoft SC-200

Month 3–4: GCIH (IR), eCTHP (Threat Hunting)

Month 5: AWS Security Specialty / Azure Security Engineer

Month 6–7: eJPT (offensive basics) → later CISSP/CCSP (experience required)



---

Portfolio Checklist

[ ] 3+ PCAP investigations with IOC tables

[ ] 1 OS hardening script (Linux & Windows)

[ ] 1 full IR report (end-to-end)

[ ] 5+ Sigma rules, 2+ YARA rules, 1 Snort rule

[ ] Adversary emulation runs + coverage matrix

[ ] Content Pack v1 for SIEM (queries + dashboards)

[ ] Cloud secure baseline (AWS & Azure)

[ ] Pentest lab report + detection mapping

[ ] Capstone incident case (executive + technical)



---

Notes & Tips

Daily recap (30 min) → write what you proved, what failed, next experiment.

Version everything (rules/tests/dashboards) like code.

Automate small wins (enrichment scripts, parsing helpers).

Tell the story in reports: hypothesis → evidence → conclusion → recommendation.

Protect your budget in cloud labs (budgets/alerts).



---

Quick Links (for convenience)

Wireshark Filters: https://wiki.wireshark.org/DisplayFilters

Malware Traffic Analysis: https://www.malware-traffic-analysis.net/

Professor Messer Sec+: https://www.professormesser.com/security-plus/sy0-701/sy0-701-training-course/

MITRE ATT&CK: https://attack.mitre.org/

Splunk Free: https://www.splunk.com/en_us/download/splunk-enterprise.html

Elastic Security: https://www.elastic.co/security

BlueTeamLabs: https://blueteamlabs.online

CyberDefenders: https://cyberdefenders.org

REMnux: https://remnux.org/

FLARE VM: https://github.com/mandiant/flare-vm

OWASP Top 10: https://owasp.org/www-project-top-ten/

Juice Shop: https://owasp.org/www-project-juice-shop/

NVD: https://nvd.nist.gov/

AWS Security Pillar: https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html

Azure Security Docs: https://learn.microsoft.com/en-us/azure/security/

# Supreme Detection Engineer 
[![URL Check](https://github.com/st0pp3r/Supreme-Detection-Engineer/actions/workflows/url_check.yml/badge.svg)](https://github.com/st0pp3r/Supreme-Detection-Engineer/actions/workflows/url_check.yml/badge.svg) [![Create Bookmarks File](https://github.com/st0pp3r/Supreme-Detection-Engineer/actions/workflows/create_bookmarks.yml/badge.svg)](https://github.com/st0pp3r/Supreme-Detection-Engineer/actions/workflows/create_bookmarks.yml)

 Online resources for Detection Engineers. Detection rules, event log references, attack samples and others.

## Contents
- [Detection Rules](#detection-rules) - Online databases with detection rules.
- [Detection Logic](#detection-logic) - Resources on detection logic. 
- [Attack Samples](#attack-samples) - Attack samples, useful for replaying attacks and testing detection logic. 
- [Detection Tests & Emulation Tools](#detection-tests-&-emulation-tools) - Tools and tests for testing detection logic and emulating attacks. 
- [Logging Configuration & Best Practices](#logging-configuration-&-best-practices) - Guidelines on configuring and optimizing logging. 
- [Event Log References](#event-log-references) - Online vendor documentation and references for event logs. 
- [Resources](#resources) - Useful online resources for detection engineers. 
- [Labs](#labs) - Online labs for detection engineers. 
- [Online Tools](#online-tools) - Useful online tools for detection engineers day-to-day. 
- [Blogs](#blogs) - Blogs that regularly release detection engineering-related content. 
- [Newsletters](#newsletters) - Newsletters with updates on detection engineering. 
- [Good Reads](#good-reads) - Noteworthy blog posts related to detection engineering. 
- [Books](#books) - Books on detection engineering. 
- [Trainings](#trainings) - Available trainings focused on detection engineering. 
- [Podcasts](#podcasts) - Podcasts focused on detection engineering. 
- [Twitter/X](#twitterx) - Relevant Twitter/X accounts.

### Detection Rules
- [Sigma Rules](https://github.com/SigmaHQ/sigma) - Huge collection of detection rules from SIGMA HQ.
- [Elastic Rules](https://www.elastic.co/guide/en/security/current/prebuilt-rules.html), [Elastic Detection Rules Explorer](https://elastic.github.io/detection-rules-explorer) or [Elastic Rules GitHub Repository](https://github.com/elastic/detection-rules/tree/main/rules)- Elastic's detection rules.
- [Elastic Security for Endpoint Rules](https://github.com/elastic/protections-artifacts/tree/main)- Elastic's Security for Endpoint detection rules.
- [Splunk Rules](https://research.splunk.com/detections/) and [Splunk Rules GitHub Repository](https://github.com/splunk/security_content/tree/develop/detections) - Splunk's detection rules.
- [Sentinel Detections](https://github.com/Azure/Azure-Sentinel/tree/master/Detections) and [Sentinel Solution Rules](https://github.com/Azure/Azure-Sentinel/tree/master/Solutions)- Collection of KQL detection queries for Sentinel.
- [FortiSIEM Rules](https://help.fortinet.com/fsiem/Public_Resource_Access/7_2_2/rules/rule_descriptions.htm) - FortiSIEM's detection rules.
- [Sigma Rules | The DFIR Report](https://github.com/The-DFIR-Report/Sigma-Rules/tree/main/rules/windows) - Collection of sigma rules.
- [Sigma Rules | mdecrevoisier](https://github.com/mdecrevoisier/SIGMA-detection-rules) - Collection of sigma rules.
- [Sigma Rules | Yamato Security](https://github.com/Yamato-Security/hayabusa-rules/tree/main/sigma) - Collection of sigma rules.
- [KQL Queries | SecurityAura](https://github.com/SecurityAura/DE-TH-Aura) - Collection of KQL queries.
- [KQL Queries for Sentinel | reprise99](https://github.com/reprise99/Sentinel-Queries) - Collection of KQL queries.
- [KQL Queries | Cyb3r Monk](https://github.com/Cyb3r-Monk/Threat-Hunting-and-Detection/tree/main) - Collection of KQL queries.
- [KQL Queries for DefenderATP | 0xAnalyst](https://github.com/0xAnalyst/DefenderATPQueries) - Collection of KQL queries.
- [KQL Queries | Bert-JanP](https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules/tree/main) - Collection of KQL queries.
- [KQL Search](https://www.kqlsearch.com/) - Collection of KQL queries from various GitHub repositories.
- [Attack Rule Map](https://attackrulemap.com/) - Mapping of open-source detection rules and atomic tests.
- [MITRE Cyber Analytics Repository (CAR)](https://car.mitre.org/) and [MITRE Cyber Analytics Repository (CAR) Coverage Comparison](https://car.mitre.org/coverage/) - The MITRE Cyber Analytics Repository (CAR) is a knowledge base of analytics based on the MITRE ATT&CK framework.
- [Google Cloud Platform (GCP) Community Security Analytics](https://github.com/GoogleCloudPlatform/security-analytics) - Security analytics to monitor cloud activity within Google Cloud.
- [Anvilogic Detection Armory](https://github.com/anvilogic-forge/armory/tree/main/detections) - Public versions of the sophisticated detections found within the Anvilogic Platform Armory.
- [Chronicle (GCP) Rules](https://github.com/chronicle/detection-rules) - Detection rules written for the Chronicle Platform.
- [SOC Prime](https://socprime.com/) - Great collection of free and paid detection rules.

### Detection Logic
- [Active Directory Detection Logic | Picus](https://www.picussecurity.com/hubfs/Threat%20Readiness%20-%20Active%20Directory%20Ebook%20-%20Q123/Picus-The-Complete-Active-Directory-Security-Handbook.pdf) - Handbook with active directory attack descriptions and detection recommendations.
- [Antivirus Cheatsheet | Nextron Systems](https://www.nextron-systems.com/?s=antivirus)
- [Detecting the Elusive Active Directory Threat Hunting](https://adsecurity.org/wp-content/uploads/2017/04/2017-BSidesCharm-DetectingtheElusive-ActiveDirectoryThreatHunting-Final.pdf)

### Attack Samples
- [EVTX Attack Samples](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) - Event viewer attack samples.
- [EVTX to MITRE Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack) - IOCs in EVTX format.
- [Security Datasets](https://github.com/OTRF/Security-Datasets/tree/master/datasets) - Datasets of malicious and benign indicators, from different platforms.
- [Tool Analysis Results Sheet | jpcertcc](https://jpcertcc.github.io/ToolAnalysisResultSheet) - Results of examining logs recorded in Windows upon execution of 49 tools.
- [Mordor Dataset](https://github.com/UraSecTeam/mordor) - Pre-recorded security events generated after simulating adversarial techniques.
- [Attack Data | Splunk](https://github.com/splunk/attack_data) A Repository of curated datasets from various attacks
- [Secrepo](https://secrepo.com/) - Samples of various types of Security related data.
- [PCAP-ATTACK | sbousseaden](https://github.com/sbousseaden/PCAP-ATTACK) - Container of PCAP captures mapped to the relevant attack tactic.
- [malware-traffic-analysis.net](https://malware-traffic-analysis.net/) - A site for sharing packet capture (pcap) files and malware samples.
- [NetreSec PCAPs](https://www.netresec.com/?page=PcapFiles) - This is a list of public packet capture ([PCAP](https://netresec.com/?b=22A1c18)) repositories, which are freely available on the Internet.

### Detection Tests & Emulation Tools
- [Atomic Red Team | Red Canary](https://github.com/redcanaryco/atomic-red-team/tree/master/atomics) - Library of tests mapped to the MITRE ATT&CK framework.
- [Stratus Red Team | DataDog](https://github.com/DataDog/stratus-red-team) - Basically atomic red team atomics for cloud.
- [LOLOL Farm](https://lolol.farm/)- A great collection of resources to thrive off the land.
- [MITRE Caldera](https://caldera.mitre.org/) - Adversary Emulation Framework by MITRE.
- [Active Directory Attack Tests | Picus](https://www.picussecurity.com/hubfs/Threat%20Readiness%20-%20Active%20Directory%20Ebook%20-%20Q123/Picus-The-Complete-Active-Directory-Security-Handbook.pdf) - Handbook with active directory attack tests.
- [Network Flight Simulator](https://github.com/alphasoc/flightsim#network-flight-simulator) - lightweight utility used to generate malicious network traffic.
- [APT Simulator](https://github.com/NextronSystems/APTSimulator#apt-simulator) - Windows Batch script that uses a set of tools and output files to make a system look as if it was compromised.
- [Infection Monkey](https://github.com/guardicore/monkey#infection-monkey) - Open-source adversary emulation platform.

### Logging Configuration Guidelines and Best Practices
- [OWASP Cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [Microsoft Monitoring Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/monitoring-active-directory-for-signs-of-compromise)
- [Microsoft Windows Audit Policy Recommendations](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations)
- [Malware Archaeology Cheatsheets for Windows](https://www.malwarearchaeology.com/cheat-sheets)
- [Auditd Logging Configuration | Neo23x0](https://github.com/Neo23x0/auditd/blob/master/audit.rules)
- [Sysmon Configuration | SwiftOnSecurity](https://github.com/SwiftOnSecurity/sysmon-config)
- [Sysmon Configuration | Olaf Hartong](https://github.com/olafhartong/sysmon-modular)
 
### Event Log References
- [Windows Event IDs and Audit Policies](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/advanced-security-audit-policy-settings)
- [Windows Security Log Event IDs Encyclopedia](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/default.aspx?i=j)
- [Sysmon Event IDs](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#events)
- [Cisco ASA Event IDs](https://www.cisco.com/c/en/us/td/docs/security/asa/syslog/b_syslog.html)
- [Palo Alto PAN-OS Log Fields](https://docs.paloaltonetworks.com/pan-os/10-1/pan-os-admin/monitoring/use-syslog-for-monitoring/syslog-field-descriptions)
- [Palo Alto PAN-OS Threat Categories](https://docs.paloaltonetworks.com/advanced-threat-prevention/administration/threat-prevention/threat-signature-categories)
- [FortiGate FortiOS Log Types and Subtypes](https://docs.fortinet.com/document/fortigate/7.6.1/fortios-log-message-reference/160372/list-of-log-types-and-subtypes) and [FortiGate FortiOS Log Fields](https://docs.fortinet.com/document/fortigate/7.6.1/fortios-log-message-reference/357866/log-message-fields)
- [Microsoft Defender Event IDs](https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus)
- [Microsoft Defender for Cloud Alert References](https://learn.microsoft.com/en-us/azure/defender-for-cloud/alerts-reference)
- [Microsoft Defender XDR Schemas](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables)
- [GCP Threat Detection Findings](https://cloud.google.com/security-command-center/docs/concepts-security-sources#threats)
- [GuardDuty Finding Types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html)

### Resources
- [MITRE ATT&CK®](https://attack.mitre.org/) - MITRE ATT&CK knowledge base of adversary tactics and techniques.
- [DeTT&CT](https://github.com/rabobank-cdc/DeTTECT/) - DeTT&CT aims to assist blue teams in using ATT&CK to score and compare data log source quality, visibility coverage, detection coverage and threat actor behaviors.
- [Active Directory Security (adsecurity.org)](https://adsecurity.org/?page_id=4031) - Page dedicated to Active Directory security. Includes attack descriptions and detection recommendations.
- [Zen of Security Rules | Justin Ibarra](https://br0k3nlab.com/resources/zen-of-security-rules/) - 19 rules for developing detection rules.
- [Uncoder IO](https://uncoder.io/) - Detection logic query converter.
- [Alerting and Detection Strategies (ADS) Framework | Palantir](https://github.com/palantir/alerting-detection-strategy-framework#alerting-and-detection-strategies-framework)- A structured approach to designing and documenting effective detection methodologies.
- [Detection Engineering Maturity Matrix | Kyle Bailey](https://detectionengineering.io/) - Aims to help the community better measure the capabilities and maturity of their detection function.
- [Detection Engineering Maturity (DML) Model | Ryan Stillions](https://ryanstillions.blogspot.com/2014/04/the-dml-model_21.html) - A tool for assessing an organization’s detection engineering capabilities and maturity levels.
- [MaGMa Use Case Framework](https://www.betaalvereniging.nl/wp-content/uploads/FI-ISAC-use-case-framework-verkorte-versie.pdf) - Methodology for defining and managing threat detection use cases.
- [Detection Engineering Cheatsheet | Florian Roth](https://x.com/cyb3rops/status/1592879894396293121) - Chee sheet for prioritizing detection development. 
- [Microsoft Azure Security Control Mappings to MITRE ATT&CK](https://center-for-threat-informed-defense.github.io/security-stack-mappings/Azure/README.html)

### Labs
 - [BlueTeam.Lab](https://github.com/op7ic/BlueTeam.Lab)
 - [Splunk Attack Range](https://github.com/splunk/attack_range)
 - [Detection LAB](https://github.com/clong/DetectionLab/) - Deprecated
 
### Online Tools
 - [Regex101](https://regex101.com/)
 - [CyberChef](https://gchq.github.io/CyberChef/)
 - [JSON Formatter](https://jsonformatter.curiousconcept.com/#)

### Blogs
- [FalconForce Blog](https://falconforce.nl/blogs/)
- [Red Canary Blog](https://redcanary.com/blog) and [Red Canary Blog Threat Detection Category](https://redcanary.com/blog/?topic=threat-detection)
- [Elastic Security Labs Blog](https://www.elastic.co/security-labs) and [Elastic Security Labs Blog Detection Category](https://www.elastic.co/security-labs/topics/detection-science). Also everything [Samir Bousseaden](https://www.elastic.co/security-labs/author/samir-bousseaden).
- [SpecterOps Blog](https://specterops.io/blog) and [SpecterOps on Detection series | Jared Atkinson](https://specterops.io/blog/?_sf_s=on%20detection)
- [Detect.fyi](https://detect.fyi/) - Collection of good detection engineering articles.
- [Detections.xyz](https://detections.xyz/) - Collection of good detection engineering articles.
- [Alex Teixeira on Medium](https://ateixei.medium.com/)

### Newsletters
- [Detection Engineering Weekly](https://www.detectionengineering.net/)
- [Detections Digest](https://detections-digest.rulecheck.io/) - A newsletter with many popular detection content sources.

### Good Reads
- [About Detection Engineering | Florian Roth](https://cyb3rops.medium.com/about-detection-engineering-44d39e0755f0)
- [Detection Development Lifecycle | Haider Dost](https://medium.com/snowflake/detection-development-lifecycle-af166fffb3bc)
- [Elastic releases the Detection Engineering Behavior Maturity Model](https://www.elastic.co/security-labs/elastic-releases-debmm)
- [Threat Detection Maturity Framework | Haider Dost](https://medium.com/snowflake/threat-detection-maturity-framework-23bbb74db2bc)
- [Compound Probability: You Don’t Need 100% Coverage to Win](https://medium.com/@vanvleet/compound-probability-you-dont-need-100-coverage-to-win-a2e650da21a4)
- [Prioritizing Detection Engineering | Ryan McGeehan](https://medium.com/starting-up-security/prioritizing-detection-engineering-b60b46d55051)
- [DeTT&CT : Mapping detection to MITRE ATT&CK | Renaud Frère](https://blog.nviso.eu/2022/03/09/dettct-mapping-detection-to-mitre-attck/)
- [DeTT&CT: Mapping your Blue Team to MITRE ATT&CK™](https://www.mbsecure.nl/blog/2019/5/dettact-mapping-your-blue-team-to-mitre-attack)
- [Distributed Security Alerting](https://slack.engineering/distributed-security-alerting/)
- [Deploying Detections at Scale — Part 0x01 use-case format and automated validation | Gijs Hollestelle](https://medium.com/falconforce/deploying-detections-at-scale-part-0x01-use-case-format-and-automated-validation-7bc76bea0f43)
- [From soup to nuts: Building a Detection-as-Code pipeline](https://medium.com/threatpunter/from-soup-to-nuts-building-a-detection-as-code-pipeline-28945015fc38)
- [Can We Have “Detection as Code”? | Anton Chuvakin](https://medium.com/anton-on-security/can-we-have-detection-as-code-96f869cfdc79)
- [Automating Detection-as-Code | John Tuckner](https://www.tines.com/blog/automating-detection-as-code/)
- [How to prioritize a Detection Backlog? | Alex Teixeira](https://detect.fyi/how-to-prioritize-a-detection-backlog-84a16d4cc7ae)

### Books
 - [Automating Security Detection Engineering: A hands-on guide to implementing Detection as Code](https://www.packtpub.com/en-no/product/automating-security-detection-engineering-9781837636419)
 - [Practical Threat Detection Engineering: A hands-on guide to planning, developing, and validating detection capabilities](https://www.packtpub.com/en-sg/product/practical-threat-detection-engineering-9781801076715)
 - [Malware Analysis and Detection Engineering: A Comprehensive Approach to Detect and Analyze Modern Malware](https://link.springer.com/book/10.1007/978-1-4842-6193-4)

### Trainings
- [XINTRA Attacking and Defending Azure & M365](https://www.xintra.org/training/course/1-attacking-and-defending-azure-m365)
- [Specter Ops Adversary Tactics: Detection](https://specterops.io/training/adversary-tactics-detection/)
- [FalconForce Advanced Detection Engineering in the Enterprise training](https://falconforce.nl/services/training/advanced-detection-engineering-training/)
- [TCM Security Detection Engineering for Beginners](https://academy.tcm-sec.com/p/detection-engineering-for-beginners)
- [LetsDefend Detection Engineering Path](https://letsdefend.io/detection-engineering)
- [SANS SEC555: Detection Engineering and SIEM Analytics](https://www.sans.org/cyber-security-courses/detection-engineering-siem-analytics/)

### Podcasts
- [Detection Challenging Paradigms | SpecterOps](https://www.dcppodcast.com/all-episodes)
- [Darknet Diaries](https://darknetdiaries.com/) - Not detection engineering focused but one of my favorites.
- [Detection at Scale](https://podcasts.apple.com/us/podcast/detection-at-scale/id1582584270)

### Twitter/X
- [@sigma_hq](https://x.com/sigma_hq)
- [@cyb3rops](https://x.com/cyb3rops)
- [@frack113](https://x.com/frack113)
- [@SBousseaden](https://x.com/SBousseaden)
- [@SecurityAura](https://x.com/SecurityAura)
- [@Oddvarmoe](https://x.com/Oddvarmoe)
- [@jaredcatkinson](https://x.com/jaredcatkinson)
- [Awesome Detection List](https://x.com/i/lists/952735755838738432)

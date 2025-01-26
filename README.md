# Supreme Detection Engineer [![URL Check](https://github.com/st0pp3r/Supreme-Detection-Engineer/actions/workflows/url_check.yml/badge.svg)](https://github.com/st0pp3r/Supreme-Detection-Engineer/actions/workflows/url_check.yml/badge.svg)

 Online sources for Detection Engineers. Detection rules, online resources, event log references and others.

## Contents
- [Detection Rules](#detection-rules) - Online databases with rules, use cases and detection logic.
- [Attack Samples](#attack-samples) - Attack samples, useful for replying attacks and testing detection logic.
- [Event Log References](#event-log-references) - Online vendor documentation and references for event logs.
- [Resources](#resources) - Useful online resources for detection engineers.
- [Must Reads](#must-reads) - Online vendor documentation for event logs.
- [Books](#books) - Recommended books on security, detection, and event log analysis for in-depth learning.
- [Trainings](#trainings) - Available trainings.
- [Twitter](#twitter) - Relevant Twitter accounts and threads for real-time security updates and insights.

### Detection Rules
- [Sigma Rules](https://github.com/SigmaHQ/sigma) - Huge collection of detection rules from SIGMA HQ.
- [Elastic Rules](https://www.elastic.co/guide/en/security/current/prebuilt-rules.html), [Elastic Detection Rules Explorer](https://elastic.github.io/detection-rules-explorer) or [Elastic Detection Rules Repository](https://github.com/elastic/detection-rules/tree/main/rules)- Elastic's detection rules.
- [Splunk Rules](https://research.splunk.com/detections/) and [Splunk Detection Rules Repository](https://github.com/splunk/security_content/tree/develop/detections) - Splunk's detection rules.
- [FortiSIEM Rules](https://help.fortinet.com/fsiem/Public_Resource_Access/7_2_2/rules/rule_descriptions.htm) - FortiSIEM's detection rules.
- [SOC Prime](https://socprime.com/) - Great collection of free and paid detection rules.
- [Sentinel Detections](https://github.com/Azure/Azure-Sentinel/tree/master/Detections) - Collection of KQL detection queries for Sentinel.
- [The DFIR Report Detection Rules](https://github.com/The-DFIR-Report/Sigma-Rules/tree/main/rules/windows) - Collection of rules from https://thedfirreport.com/.
- [Sigma Detection Rules from mdecrevoisier](https://github.com/mdecrevoisier/SIGMA-detection-rules) - Collection of sigma rules from [mdecrevoisie](https://github.com/mdecrevoisier).
- [Sigma Detection Rules from Yamato Security](https://github.com/Yamato-Security/hayabusa-rules/tree/main/sigma) - Collection of sigma rules from [Yamato-Security](https://github.com/Yamato-Security).
- [KQL Queries for Sentinel from reprise99](https://github.com/reprise99/Sentinel-Queries) - Collection of KQL queries from [reprise99](https://github.com/reprise99).
- [KQL Queries from Cyb3r Monk](https://github.com/Cyb3r-Monk/Threat-Hunting-and-Detection/tree/main) - Collection of KQL queries from [Cyb3r Monk](https://github.com/Cyb3r-Monk).
- [KQL Queries for DefenderATP from 0xAnalyst](https://github.com/0xAnalyst/DefenderATPQueries) - Collection of KQL queries from [0xAnalyst](https://github.com/0xAnalyst).
- [KQL queries from Bert-JanP](https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules/tree/main) - Collection of KQL queries from [Bert-JanP](https://github.com/Bert-JanP).
- [KQL Search](https://www.kqlsearch.com/) - Collection of KQL queries from various github repositories.

### Attack Samples
- [EVTX Attack Samples](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) - Event viewer attack samples from [sbousseaden](https://github.com/sbousseaden/).
- [EVTX to MITRE Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack) - IOCs in EVTX format from [mdecrevoisier](https://github.com/mdecrevoisier).
- [Security Datasets](https://github.com/OTRF/Security-Datasets/tree/master/datasets) - Datasets of malicious and benign indicators, from different platforms from [OTRF](https://github.com/OTRF).
- [Tool Analysis Results Sheet from jpcertcc](https://jpcertcc.github.io/ToolAnalysisResultSheet) - Results of examining logs recorded in Windows upon execution of 49 tools.

### Event Log References
- [Windows Audit Policies and Event IDs](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/advanced-security-audit-policy-settings) - Documentation of Windows Event IDs and Audit Policies from Microsoft.
- [Windows Security Log Events Encyclopedia](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/default.aspx?i=j) - Documentation of Windows Event IDs.
- [Sysmon Event IDs](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#events) - Event ID description for Sysmon.
- [Cisco ASA Log Event IDs](https://www.cisco.com/c/en/us/td/docs/security/asa/syslog/b_syslog.html) - Cisco's ASA Event IDs syslog log format and log description.
- [Palo Alto PAN-OS](https://docs.paloaltonetworks.com/pan-os/10-1/pan-os-admin/monitoring/use-syslog-for-monitoring/syslog-field-descriptions) - Palo Alto's log field descriptions.
- [FortiGate FortiOS Log Types and Subtypes](https://docs.fortinet.com/document/fortigate/7.6.1/fortios-log-message-reference/160372/list-of-log-types-and-subtypes) and [FortiGate FortiOS Log Fields](https://docs.fortinet.com/document/fortigate/7.6.1/fortios-log-message-reference/357866/log-message-fields) - Log format and log fields documentation for fortiOS.
- [Microsoft Defender Event IDs](https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus) - Event IDs references for Microsoft Defender Antivirus.
- [Antivirus Cheatsheet from Nextron Systems](https://www.nextron-systems.com/?s=antivirus) Antivirus Event Analysis Cheat Sheet.

### Resources
- [MITRE ATT&CK®](https://attack.mitre.org/) - MITRE ATT&CK knowledge base of adversary tactics and techniques.
- [Active Directory Security](https://adsecurity.org/?page_id=4031) - Page dedicated to Active Directory security. Includes attack descriptions and detection recommendations.
- [Red Canary's Atomics](https://github.com/redcanaryco/atomic-red-team/tree/master/atomics) - Library of tests mapped to the [MITRE ATT&CK®](https://attack.mitre.org/) framework.
- [Uncoder IO](https://uncoder.io/) - Detection logic query converter.

### Must Reads

### Books
 - [Automating Security Detection Engineering: A hands-on guide to implementing Detection as Code](https://www.packtpub.com/en-no/product/automating-security-detection-engineering-9781837636419)
 - [Practical Threat Detection Engineering: A hands-on guide to planning, developing, and validating detection capabilities](https://www.packtpub.com/en-sg/product/practical-threat-detection-engineering-9781801076715)
 - [Malware Analysis and Detection Engineering: A Comprehensive Approach to Detect and Analyze Modern Malware](https://link.springer.com/book/10.1007/978-1-4842-6193-4)

### Trainings
- [XINTRA Attacking and Defending Azure & M365](https://www.xintra.org/training/course/1-attacking-and-defending-azure-m365)
- [Specter Ops Adversary Tactics: Detection](https://specterops.io/training/adversary-tactics-detection/)
- [FalconForce Advanced Detection Engineering in the Enterprise training](https://falconforce.nl/services/training/advanced-detection-engineering-training/)

### Twitter
- [@cyb3rops](https://x.com/cyb3rops)
- [@SBousseaden](https://x.com/SBousseaden)
- [@Oddvarmoe](https://x.com/Oddvarmoe)
- [@sigma_hq](https://x.com/sigma_hq)


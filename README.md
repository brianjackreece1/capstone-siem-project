 CAPSTONE PROJECT 3: Security Information and Event Management (SIEM)

 1. Overview

This project implements a laboratory-based **Security Information and Event Management (SIEM)** environment using **Splunk Enterprise**, **Splunk Universal Forwarder**, **Windows**, **Ubuntu Linux**, and **VirtualBox**.

The purpose of the project is to demonstrate fundamental Security Operations Center (SOC) activities, including centralized log collection, security event monitoring, detection engineering, controlled attack simulation, incident investigation, event correlation, and SOC dashboard development.

The environment was designed using a VirtualBox Host-Only network to provide an isolated laboratory for generating and analyzing security telemetry.


 2. Project Objectives

The main objectives of this project are to:

1. Deploy and configure Splunk Enterprise as a SIEM platform.
2. Configure Windows and Ubuntu systems as security telemetry sources.
3. Deploy Splunk Universal Forwarders.
4. Configure centralized Windows and Linux log collection.
5. Create dedicated Splunk indexes for Windows and Linux telemetry.
6. Monitor Windows Security, System, Application, and PowerShell events.
7. Monitor Linux authentication and system logs.
8. Simulate controlled security events in an isolated laboratory.
9. Develop SPL-based security detection queries.
10. Investigate security events and construct incident timelines.
11. Develop a SOC monitoring dashboard.
12. Document findings, evidence, and remediation recommendations.


 3. Lab Environment

The laboratory consists of:

1. A physical Windows host running Splunk Enterprise.
2. A Windows virtual machine used as a Windows security telemetry source.
3. An Ubuntu Linux virtual machine used as a Linux security telemetry source.
4. VirtualBox Host-Only networking.
5. Splunk Universal Forwarder on the Windows and Ubuntu systems.

The laboratory network uses the `192.168.56.0/24` subnet.

Splunk receives forwarded events through TCP port `9997`.

The primary systems are:

1. Windows Host / Splunk Enterprise: `192.168.56.1`
2. Windows VM: `192.168.56.20`
3. Ubuntu VM: `192.168.56.30`



 4. Technologies Used

1. Splunk Enterprise
2. Splunk Universal Forwarder
3. Microsoft Windows
4. Ubuntu Linux
5. Oracle VirtualBox
6. Splunk Processing Language (SPL)
7. Windows Event Logs
8. Linux system and authentication logs



 5. Repository Structure


capstone-siem-project/
│
├── README.md
│
├── configuration/
│   ├── windows-inputs.conf
│   └── ubuntu-inputs.conf
│
├── documentation/
│   └── SIEM_Capstone_Report.docx
│
├── queries/
│   └── detection-queries.txt
│
└── screenshots/
    └── Project evidence screenshots
```

The repository contains the project documentation, Splunk configuration examples, SPL detection queries, and visual evidence collected during the laboratory implementation.



 6. Data Collection

 6.1 Windows Telemetry

The Windows Universal Forwarder was configured to collect:

1. Application events
2. Security events
3. System events
4. PowerShell Operational events

Windows telemetry was assigned to the `windows` Splunk index.

Example search:


index=windows


The configured Windows event sources include:


WinEventLog:Application
WinEventLog:Security
WinEventLog:System
WinEventLog:Microsoft-Windows-PowerShell/Operational


 6.2 Linux Telemetry

The Ubuntu Universal Forwarder was configured to monitor:


/var/log/syslog
/var/log/auth.log


Linux telemetry was assigned to the `linux` Splunk index.

Example searches:

```
index=linux
```

```spl
index=linux sourcetype=syslog
```

```
index=linux sourcetype=linux_secure
```

---

 7. Security Event Simulations

The project includes controlled security-event simulations designed to generate telemetry for detection and investigation.

 7.1 SSH Brute-Force Simulation

Multiple unsuccessful SSH authentication attempts were generated against the Ubuntu system.

The Ubuntu authentication logs recorded events including:

```
Failed password
Invalid user
authentication failure
```

 Basic Detection

```spl
index=linux sourcetype=linux_secure "Failed password"
```

 Brute-Force Detection

```
index=linux sourcetype=linux_secure "Failed password"
| rex "Failed password for (?:invalid user )?(?<user>\S+) from (?<src_ip>\S+)"
| stats count by src_ip user
| where count >= 3
| sort - count
```

The observed source IP recorded during the laboratory test was:

```
192.168.56.1
```

The project reports the observed source address rather than assuming a source address based solely on the planned network topology.

 7.2 Unauthorized Local Administrator Account

A controlled laboratory account was created and added to the local Windows Administrators group.

The activity was investigated using Windows Security Event IDs:

```
4720 — User account created
4732 — Member added to a security-enabled local group
```

 Account Creation Detection

```
index=windows EventCode=4720
```

 Administrator Group Modification

```
index=windows EventCode=4732
```

 Correlation

```
index=windows (EventCode=4720 OR EventCode=4732)
| sort _time
```

This correlation allows account creation and subsequent privilege assignment activity to be examined together.

 7.3 Windows Process Creation

Windows process creation telemetry was investigated using Event ID `4688`.

 Detection

```
index=windows EventCode=4688
```

The project successfully captured Windows process-creation telemetry.

A captured Event ID 4688 example showed process activity involving:

```
C:\Windows\System32\lsass.exe
```

This demonstrates successful process-creation telemetry collection, but it should not be interpreted as evidence of a PowerShell command unless the corresponding PowerShell process is specifically captured.

 7.4 PowerShell Activity

PowerShell Operational logging was enabled on the Windows system.

Local verification confirmed PowerShell Operational events, including:

```
Event ID 4104 — Script Block Logging
```

 Detection Query

```
index=windows EventCode=4104
```

A harmless PowerShell command such as:

```
Get-Process
```

can be used to generate PowerShell activity in the isolated laboratory environment.

 Validation Note

PowerShell Operational events were confirmed locally on the Windows VM. However, successful forwarding of Event ID 4104 into Splunk was **not conclusively verified** during the documented testing.

Therefore, this project does not claim successful Splunk indexing of Event ID 4104 without corresponding evidence.

 7.5 Security Audit Log Clearing

An optional laboratory scenario involves clearing the Windows Security Event Log.

The relevant Windows event is:

```
Event ID 1102
```

 Detection

```
index=windows EventCode=1102
```

This scenario should only be performed on an isolated and disposable laboratory Windows VM after required evidence has been captured.

---

 8. Detection Engineering

The project demonstrates several foundational SOC detection use cases, including:

1. SSH brute-force authentication attempts.
2. Windows account creation.
3. Windows privileged group modification.
4. Windows process creation.
5. PowerShell script activity.
6. Windows Security log clearing.
7. General Windows and Linux event monitoring.
8. Event correlation between account creation and privilege changes.

The complete SPL detection queries are available in:

```
queries/detection-queries.txt
```

---

 9. SOC Dashboard

A Splunk SOC dashboard was developed to provide centralized visibility into the laboratory environment.

The dashboard provides monitoring for:

1. Windows events.
2. Linux events.
3. Failed SSH authentication.
4. New account creation.
5. Privileged group changes.
6. Windows process creation.
7. Security log clearing.

 9.1 Windows Events

```
index=windows
```

 9.2 Linux Events

```spl
index=linux
```

 9.3 Failed SSH Authentication

```
index=linux sourcetype=linux_secure "Failed password"
```

 9.4 Account Creation

```
index=windows EventCode=4720
```

 9.5 Privileged Group Changes

```
index=windows EventCode=4732
```

 9.6 Process Creation

```
index=windows EventCode=4688
```

 9.7 Security Log Clearing

```
index=windows EventCode=1102
```



 10. Incident Investigation Methodology

The investigation process follows a simplified SOC workflow:

1. Telemetry collection.
2. Event detection.
3. Alert investigation.
4. Event correlation.
5. Timeline construction.
6. Impact assessment.
7. Containment and remediation.
8. Lessons learned.

For each simulated security event, the investigation considers:

* Timestamp.
* Source host.
* Source IP.
* User or account.
* Event ID.
* Event type.
* Process or activity.
* Target resource.
* Authentication result.
* Related events.
* Potential impact.
* Recommended remediation.



 11. Evidence and Screenshots

The `screenshots/` directory contains evidence from the laboratory implementation and investigation.

The evidence includes:

1. VirtualBox Host-Only network configuration.
2. Windows VM network configuration.
3. Ubuntu network configuration.
4. Splunk Web interface.
5. Splunk receiver configuration.
6. Port 9997 connectivity testing.
7. Splunk indexes.
8. Windows Universal Forwarder.
9. Windows input configuration.
10. Windows event ingestion.
11. Windows Security events.
12. Windows Application events.
13. Windows System events.
14. Ubuntu input configuration.
15. Linux event ingestion.
16. Linux authentication logs.
17. SSH detection.
18. Account creation events.
19. Administrator group modification events.
20. Process creation events.
21. PowerShell activity.
22. Security log clearing.
23. Detection rules.
24. Final Splunk SOC dashboard.
25. Incident timeline.

The screenshots retain the original evidence naming and numbering used during the project.



 12. Key Findings

The implementation demonstrated that:

1. Splunk can centralize telemetry from Windows and Ubuntu systems.
2. Splunk Universal Forwarder can transmit endpoint logs to a central Splunk instance.
3. Windows Security events provide valuable evidence for account and privilege changes.
4. Windows Event ID 4688 provides process-creation telemetry.
5. Ubuntu authentication logs provide evidence of failed SSH authentication.
6. SPL can transform raw logs into structured detection logic.
7. Correlation of related Windows events provides additional investigation context.
8. A centralized SOC dashboard improves visibility across multiple telemetry sources.

---

 13. Limitations

 13.1 PowerShell Forwarding

PowerShell Operational events were confirmed locally on the Windows VM, but successful forwarding of Event ID 4104 to Splunk was not conclusively verified.

 13.2 Process-Creation Evidence

Event ID 4688 was successfully captured. However, the documented example involved `lsass.exe` rather than a PowerShell `Get-Process` execution.

Therefore, the project does not claim that the captured 4688 event proves execution of `Get-Process`.

 13.3 Laboratory Environment

The project was implemented in an isolated VirtualBox laboratory.

Production environments may differ because of:

* Windows auditing configuration.
* Endpoint security policies.
* Network architecture.
* Splunk configuration.
* Log retention policies.
* User privileges.
* Operating system versions.


 14. Security and Ethical Considerations

All security testing performed for this project was conducted within a controlled laboratory environment.

The simulations are intended for educational and defensive security purposes.

The techniques demonstrated in this project should not be used against systems, networks, accounts, or services without appropriate authorization.

The repository should not contain:

* Passwords.
* API keys.
* Private keys.
* Authentication tokens.
* Production credentials.
* Unnecessary personal information.


 15. Future Improvements

Future development of the laboratory could include:

1. Reliable forwarding of PowerShell Event ID 4104.
2. Additional Windows Security auditing policies.
3. Splunk correlation searches.
4. Automated alerts.
5. Risk-based alerting.
6. Advanced process-parent/child analysis.
7. Additional Linux authentication detections.
8. Threat-intelligence integration.
9. Automated incident-response workflows.
10. Alert severity classification.
11. Enhanced SOC dashboard visualizations.
12. Additional endpoint telemetry.
13. More advanced SPL correlation techniques.



 16. Conclusion

This project demonstrates the design and implementation of a functional SIEM laboratory using Splunk Enterprise and Splunk Universal Forwarder.

The environment successfully collected and analyzed Windows and Ubuntu security telemetry, simulated controlled security events, developed SPL-based detection queries, investigated security events, and provided centralized SOC visibility through a Splunk dashboard.

The project provides practical experience across the following SOC activities:

* SIEM deployment.
* Log collection.
* Detection engineering.
* Event correlation.
* Incident investigation.
* Security monitoring.
* Remediation.

The completed laboratory provides a foundation for further development into a more advanced SOC environment involving automated alerting, threat intelligence, correlation searches, risk-based detection, and incident response.



 17. Project Author

NAME: JACKREECE BRIAN IBIYEKEBO

SIEM / SOC Capstone Project

Project: CAPSTONE PROJECT 3: Security Information and Event Management (SIEM)

SIEM Platform: Splunk Enterprise

Endpoint Telemetry: Splunk Universal Forwarder

Virtualization: VirtualBox

Operating Systems: Windows and Ubuntu Linux



 18. Disclaimer

This repository is intended strictly for **educational, defensive security, and laboratory purposes**.

All security simulations were conducted within a controlled laboratory environment.

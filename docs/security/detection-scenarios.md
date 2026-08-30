# Detection Scenarios
## Overview

This document defines controlled and synthetic detection scenarios for the Inovix MVP.

The scenarios are intended to support security research, implementation planning, testing, and demonstration.

No unauthorized systems are accessed, scanned, or attacked as part of these scenarios.

---



## Scenario 1: Brute-Force Activity
### Attack Scenario

A source repeatedly attempts to authenticate using unsuccessful login attempts.

The expected flow is:

Repeated Failed Login Attempts
↓
Security Events
↓
Detection
↓
Risk Assessment
↓
Incident



### Observable Indicators

Relevant indicators may include:

- Repeated failed login attempts
- Source IP address
- Target username or account
- Number of attempts
- Frequency of attempts
- Time window between attempts



### Expected Event

The event should represent failed authentication activity.

The exact event schema depends on the implemented event-ingestion and normalization logic.



### Detection Condition

The detection logic should identify a suspicious pattern of repeated failed authentication attempts.

The exact number of attempts, frequency, and time-window threshold are:



**TBD — implementation threshold**

No fixed threshold should be documented until confirmed by the Security Engine implementation.



### Expected Severity

Severity should depend on the evidence and implemented scoring logic.

Repeated failed authentication activity with stronger evidence may produce a higher severity and risk level.



### Expected Evidence

Expected evidence may include:

- Source identifier or IP address
- Target account or username
- Failed attempt count
- Relevant timestamps
- Detection rule or reason
- Severity
- Risk score

Only evidence produced by the implemented system should be presented as confirmed output.



### Expected Outcome

The suspicious activity may result in:

- A detection result
- A calculated risk score
- A security event
- Incident creation, if supported by the implemented workflow

The final response behavior must be verified against the implementation.

---



## Scenario 2: Possible Port-Scan Activity
### Attack Scenario

A source generates multiple connection attempts that may indicate reconnaissance or scanning behavior.

The expected flow is:

Multiple Connection Attempts
↓
Suspicious Scanning Pattern
↓
Detection
↓
Risk Assessment



### Observable Indicators

Relevant indicators may include:

- Multiple destination ports
- Multiple connection attempts
- Source identifier or IP address
- Target system
- Connection timestamps
- Frequency of connection attempts



### Expected Event

The event should represent connection activity that can be evaluated for suspicious scanning patterns.

The exact event format depends on the implemented event-ingestion logic.



### Detection Condition

The detection logic should identify patterns consistent with possible port scanning.

The exact thresholds for:

- Number of ports
- Number of connection attempts
- Time window
- Required pattern

are:



**TBD — implementation threshold**

A possible port scan should not automatically be described as a confirmed attack without sufficient evidence.



### Expected Severity

Severity should depend on the available evidence and implemented risk-scoring logic.

The scenario should reflect uncertainty where the available evidence does not confirm malicious intent.



### Expected Evidence

Expected evidence may include:

- Source identifier or IP address
- Target system
- Destination ports
- Connection count
- Relevant timestamps
- Detection reasoning
- Severity
- Risk score



### Expected Outcome

The activity may generate:

- A possible port-scan detection
- A risk assessment
- A security event

Incident creation depends on the implemented correlation and incident workflow.

---



## Scenario 3: Normal Activity
### Scenario

A normal event is processed through the Inovix workflow without indicators that meet the implemented detection conditions.

The expected flow is:

Normal Event
↓
Analysis
↓
No Significant Detection
↓
No Unnecessary Incident



### Purpose

This scenario demonstrates that Inovix should not treat every event as malicious.

The absence of malicious indicators should be handled according to the available evidence and implemented detection logic.



### Expected Evidence

Depending on implementation, the result may include:

- Event information
- Analysis result
- Detection status
- Risk score
- Explanation or reason for no significant detection



### Expected Outcome

Normal activity should not create an unnecessary high-severity incident.

The exact behavior must match the implemented detection, correlation, and incident logic.

---



## Scenario Safety

All scenarios in this document are intended for controlled testing and demonstration.

The following rules apply:

- Use synthetic or authorized test data.
- Do not scan unauthorized systems.
- Do not use real stolen credentials.
- Do not execute malware.
- Do not claim detection or blocking behavior unless verified.
- Keep implementation thresholds marked as TBD until confirmed.



## Documentation Status

These scenarios provide the initial security research and testing foundation for the Inovix MVP.

Implementation-specific detection conditions, thresholds, evidence, and response behavior must be updated after verification with the relevant developers.
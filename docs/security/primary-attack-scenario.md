# Primary Attack Scenario

## Scenario Overview

The primary controlled attack scenario for the Inovix MVP demonstrates how a suspicious URL can be identified, analyzed, assigned a risk level, and converted into a security event for further correlation and incident handling.

The demonstration uses a safe and synthetic phishing or suspicious URL scenario. No real malware, stolen credentials, or unauthorized systems are involved.



## Attack Scenario

The demonstration flow is:

Suspicious URL
↓
Browser Guard
↓
URL Analysis
↓
Rules + ML + Threat Intelligence
↓
Risk Score
↓
Warn / Controlled Block
↓
Security Event
↓
Correlation
↓
Incident
↓
SOC

The exact implementation of each component must be verified against the current codebase before being documented as implemented.



## Attacker Objective

The simulated attacker objective is to convince a user to interact with a suspicious or phishing-style URL.

In a real-world attack, such a URL could potentially be used for credential theft, malicious downloads, redirection, or other harmful activity.

For the Inovix MVP demonstration, the scenario remains controlled and synthetic.



## User and Device Impact

If a suspicious URL is successfully accessed without detection, potential impacts may include:

- Credential exposure
- Exposure to malicious content
- Unauthorized redirection
- Download of potentially harmful files
- Increased risk to the affected user or device

The exact prevention capabilities of Inovix remain dependent on the implemented response functionality.



## Expected Security Signals

The suspicious URL may generate observable indicators such as:

- Suspicious domain or URL structure
- Unusual URL patterns
- Known or suspected indicators of compromise
- Reputation or threat-intelligence matches
- Other characteristics identified by the implemented detection logic

Detection conditions and scoring thresholds must not be assumed unless confirmed by the implementation.



## Detection Point

The expected detection point is the Browser Guard or another implemented Inovix event-ingestion component.

The input is expected to enter the Inovix security workflow where it can be normalized and evaluated by the available detection mechanisms.



## Detection Process

The intended analysis flow is:

Input
↓
Normalization
↓
Rule-Based Detection
↓
ML / Anomaly Analysis
↓
Threat Intelligence Enrichment
↓
Risk Assessment

The availability and implementation status of ML, threat intelligence, correlation, and other components must be verified before they are presented as implemented functionality.



## Expected Severity

The expected severity depends on the evidence produced by the detection process.

A suspicious URL with limited evidence may result in a lower severity level, while strong evidence of malicious activity may result in a higher severity level.

The final severity assigned during the demo must reflect the implemented Inovix prototype risk logic.



## Expected Risk

Inovix prototype risk bands are:

- Low: 0–29
- Medium: 30–59
- High: 60–79
- Critical: 80–100

These ranges are prototype-specific risk bands and are not claimed to be industry-standard production thresholds.

The exact risk score for the demo scenario should be generated or confirmed by the implemented scoring logic.



## Expected Evidence

The demonstration should provide evidence that explains why the event was considered suspicious.

Depending on implementation, evidence may include:

- The analyzed URL or target
- Detection indicators
- Rule matches
- Anomaly score
- Threat-intelligence information
- Risk score
- Severity
- Detection timestamp
- Event or incident identifier

Only evidence actually produced by the implementation should be shown as confirmed demo output.



## Expected Inovix Response

Based on the implemented response capability, Inovix may:

- Warn the user
- Simulate a controlled block
- Generate a security event
- Send the event for correlation
- Create or support creation of an incident
- Display the result in the SOC or dashboard interface

The final documented response must distinguish between implemented behavior, planned behavior, and simulated demo behavior.



## Expected Dashboard Result

The expected dashboard or SOC result is a visible security record containing the relevant information about the suspicious activity.

Depending on the implemented dashboard functionality, this may include:

- Event details
- Detection status
- Severity
- Risk score
- Supporting evidence
- Incident status
- Response status

Dashboard fields and behavior remain TBD until verified with the responsible implementation owner.



## Limitations

This scenario is designed for a controlled hackathon demonstration.

The following limitations apply:

- The attack scenario uses safe and synthetic data.
- No malware is executed.
- No real credentials are used.
- No unauthorized systems are accessed or scanned.
- Detection thresholds must be based on implementation or remain TBD.
- Third-party threat-intelligence or security tooling must not be presented as functionality built entirely by Inovix.
- Planned components must remain clearly distinguished from implemented components.


## Documentation Status

This document defines the security research and intended demonstration scenario for the Inovix MVP.

Implementation-specific behavior must be verified with the relevant developers before final documentation and demo claims are made.
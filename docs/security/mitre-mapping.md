# MITRE ATT&CK Mapping

## Overview

This document maps the selected Inovix security scenarios to relevant MITRE ATT&CK techniques.

The mappings are based on the intended attack behavior and must be verified against official MITRE ATT&CK material.

These mappings describe the security scenarios used for research and demonstration. A MITRE mapping does not by itself confirm that a technique was successfully detected by the current implementation.

---

## Scenario 1: Suspicious URL / Phishing-Style Link

### Scenario

A user encounters or attempts to access a suspicious or phishing-style URL through a controlled demonstration scenario.

### MITRE ATT&CK Mapping

Where the controlled scenario represents a phishing message containing a malicious or suspicious link:

**T1566.002 — Phishing: Spearphishing Link**

If the scenario only analyzes a URL without representing phishing delivery, this mapping should be treated as a research reference rather than a confirmed representation of the implemented detection.

### Why It Applies

MITRE ATT&CK T1566.002 describes phishing activity involving a malicious or suspicious link delivered to a victim.

The Inovix demonstration scenario may represent this type of activity when the suspicious URL is presented as part of a controlled phishing-style delivery flow.

### Expected Evidence

Depending on the implementation, evidence may include:

- The analyzed URL
- Domain or URL characteristics
- Detection indicators
- Rule matches
- Threat-intelligence information where implemented
- Risk score
- Severity

### Inovix Detection

The intended detection flow may include:

URL Input

↓

Normalization

↓

Rule-Based Analysis

↓

Additional Analysis where implemented

↓

Risk Assessment

ML and threat-intelligence functionality must only be documented as implemented when confirmed by the current codebase.

### Confidence and Limitations

T1566.002 is applicable when the scenario represents phishing delivery through a malicious or suspicious link.

If Inovix only analyzes a standalone URL without demonstrating the phishing delivery mechanism, the mapping remains a research reference rather than proof that the complete MITRE technique is being detected.

The demonstration does not involve a real phishing campaign or compromise of a real system.

## Scenario 2: Brute-Force Activity

### Scenario

A source repeatedly generates failed authentication attempts against an account or service.

### Technique

Brute Force

### MITRE ATT&CK Mapping

**T1110 — Brute Force**

### Why It Applies

The scenario represents repeated attempts to gain access through authentication attempts.

The exact subtype of brute-force activity should only be documented when the implemented scenario provides sufficient evidence.

### Expected Evidence

Expected evidence may include:

- Source identifier or IP address
- Target account or username
- Repeated failed authentication attempts
- Attempt count
- Relevant timestamps
- Detection reason
- Risk score
- Severity

### Inovix Detection

The intended detection condition is a pattern of repeated failed login attempts.

The exact threshold for:

- Number of attempts
- Time window
- Frequency

is:

**TBD — implementation threshold**

### Confidence and Limitations

Repeated failed authentication attempts can indicate brute-force activity, but detection should consider available context.

The demonstration scenario uses controlled or synthetic events and does not involve unauthorized access attempts.

---

## Scenario 3: Possible Port Scan

### Scenario

A source generates connection attempts across multiple destination ports or services, producing a pattern that may indicate reconnaissance activity.

### Technique

Network Service Scanning

### MITRE ATT&CK Mapping

**T1046 — Network Service Discovery**

### Why It Applies

Network Service Discovery can involve attempts to identify available services by interacting with network ports and services.

The controlled Inovix scenario represents a possible scanning or service-discovery pattern based on synthetic or authorized connection events.

### Expected Evidence

Expected evidence may include:

- Source identifier or IP address
- Target system
- Multiple destination ports
- Connection attempts
- Relevant timestamps
- Detection reasoning
- Risk score
- Severity

### Inovix Detection

The intended detection logic identifies patterns that may be consistent with network service scanning.

The exact detection thresholds for:

- Number of ports
- Number of attempts
- Time window
- Required event pattern

are:

**TBD — implementation threshold**

### Confidence and Limitations

Multiple connection attempts alone do not always confirm malicious scanning activity.

The detection should therefore be described as a **possible port scan** unless the available evidence and implemented logic support a stronger conclusion.

No unauthorized systems are scanned as part of the Inovix demonstration.

---

## Scenario 4: Normal Activity

### Scenario

A normal event passes through the Inovix workflow without producing sufficient evidence of suspicious or malicious activity.

### MITRE ATT&CK Mapping

No MITRE ATT&CK technique is assigned to normal activity.

### Why

MITRE ATT&CK mappings are used to describe adversary behavior and techniques.

A normal-activity scenario is included to demonstrate that the system should not treat every event as malicious.

### Expected Evidence

Depending on implementation, evidence may include:

- Event details
- Analysis result
- Detection status
- Risk score
- Explanation for the result

### Inovix Detection

The expected result is:

Normal Event
↓
Analysis
↓
No Significant Detection
↓
No Unnecessary Incident

The exact behavior must match the implemented detection and incident logic.

---

## Mapping Status

The MITRE ATT&CK mappings in this document are based on the selected controlled scenarios:

| Scenario | MITRE ATT&CK Technique | Status |
|---|---|---|
| Suspicious URL / Phishing | T1566.002 — Spearphishing Link | Research Mapping |
| Brute-Force Activity | T1110 — Brute Force | Research Mapping |
| Possible Port Scan | T1046 — Network Service Discovery | Research Mapping |
| Normal Activity | No adversary technique | Not Applicable |

## Limitations

- MITRE mappings must not be treated as proof that a technique has been detected.
- Detection claims must match the actual Inovix implementation.
- Synthetic demonstration events must be clearly identified as synthetic.
- Detection thresholds remain TBD until confirmed by implementation.
- Additional MITRE mappings should only be added when relevant scenarios or implemented detection capabilities are verified.

## Documentation Status

This document provides the MITRE ATT&CK research mapping for the current Inovix MVP scenarios.

Implementation-backed detection status must be updated after verification with the relevant developers.
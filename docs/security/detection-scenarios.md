# Secondary Detection Scenarios

## Overview

This document defines the secondary controlled detection scenarios for the Inovix MVP.

The scenarios are designed for security research, controlled demonstration, detection validation, and implementation-backed documentation.

The documented scenarios are:

1. Brute-Force Activity
2. Possible Port-Scanning Activity
3. Normal Activity

All scenarios must use synthetic or otherwise authorized test data.

---

# Scenario 1: Brute-Force Activity

## Attack Scenario

A source generates repeated failed login attempts against an account or service.

The controlled scenario represents possible brute-force activity.

Expected flow:

Repeated Failed Login Attempts

↓

Security Events

↓

Detection

↓

Risk Assessment

↓

Possible Incident

↓

Response

## Observable Indicators

Relevant indicators may include:

- Repeated failed login attempts.
- Source IP address or source identifier.
- Target account or username.
- Attempt frequency.
- Number of failed attempts.
- Relevant timestamps.
- Time window of the activity.

## Expected Event

The security events should represent repeated failed authentication attempts using controlled or synthetic data.

The exact event schema depends on the implemented monitoring and ingestion components.

Status: TBD — implementation-dependent event schema.

## Detection Condition

The intended detection logic is based on identifying a pattern of repeated failed authentication attempts.

The exact values for:

- Number of attempts.
- Time window.
- Attempt frequency.
- Source grouping.
- Target account grouping.

must match the implemented detection logic.

Until confirmed:

**Threshold: TBD — implementation threshold**

## Severity

The severity depends on the evidence available and the implemented classification logic.

Repeated failed authentication attempts may represent suspicious activity, but the available context should be considered before assigning a final classification.

## Expected Evidence

Evidence may include:

- Source identifier.
- Target account.
- Number of failed attempts.
- Relevant timestamps.
- Detection reasoning.
- Security findings.
- Risk score.
- Severity or risk classification.
- Response decision where implemented.

## Expected Inovix Response

Depending on the implemented workflow, the system may:

- Record the security event.
- Generate a detection finding.
- Assign a risk assessment.
- Support incident creation where implemented.
- Recommend monitoring or review.

No automated account blocking or containment should be claimed unless separately implemented and verified.

## Limitations

Repeated failed login attempts do not automatically prove a successful brute-force attack.

The scenario uses controlled or synthetic events and does not involve unauthorized access attempts.

---

# Scenario 2: Possible Port-Scanning Activity

## Attack Scenario

A source generates multiple connection attempts across different destination ports or services.

The resulting pattern may indicate reconnaissance or possible network service scanning.

Expected flow:

Multiple Connection Attempts

↓

Security Events

↓

Suspicious Scanning Pattern

↓

Detection

↓

Risk Assessment

↓

Security Event

## Observable Indicators

Relevant indicators may include:

- Source IP address or source identifier.
- Target system.
- Multiple destination ports.
- Number of connection attempts.
- Attempt frequency.
- Relevant timestamps.
- Connection pattern.

## Expected Event

The demonstration should use synthetic or authorized connection events.

The scenario must not involve scanning unauthorized systems.

The exact event format depends on the implemented monitoring and ingestion components.

Status: TBD — implementation-dependent event schema.

## Detection Condition

The intended detection logic identifies patterns that may be consistent with possible port-scanning activity.

The exact detection conditions for:

- Number of ports.
- Number of connection attempts.
- Time window.
- Frequency.
- Required event pattern.

must match the implemented Security Engine logic.

Until confirmed:

**Threshold: TBD — implementation threshold**

## Severity

The severity depends on the available evidence and implemented classification logic.

Multiple connection attempts alone should not automatically be treated as proof of malicious activity.

The scenario should therefore be described as a **possible port scan** unless the available evidence supports a stronger conclusion.

## Expected Evidence

Evidence may include:

- Source identifier.
- Target system.
- Destination ports.
- Connection attempt count.
- Relevant timestamps.
- Detection reasoning.
- Security findings.
- Risk score.
- Severity or risk classification.

## Expected Inovix Response

Depending on the implemented workflow, Inovix may:

- Record the security event.
- Identify a suspicious connection pattern.
- Generate a detection finding.
- Assign a risk assessment.
- Support further investigation or incident handling where implemented.

Any automated blocking, containment, or remediation must remain marked as Planned or TBD unless verified.

## Limitations

The scenario represents controlled or synthetic activity.

No unauthorized systems may be scanned.

Multiple connection attempts alone do not necessarily prove malicious reconnaissance.

---

# Scenario 3: Normal Activity

## Scenario

A normal security-related event passes through the Inovix workflow without producing sufficient evidence of suspicious or malicious activity.

Expected flow:

Normal Event

↓

Analysis

↓

No Significant Detection

↓

Low or No Risk

↓

No Unnecessary Incident

## Purpose

This scenario demonstrates that Inovix should not classify every event as malicious or suspicious without sufficient evidence.

It supports the requirement that uncertainty and lack of suspicious indicators should be handled appropriately.

## Observable Indicators

The event should not contain sufficient implemented indicators to trigger a significant detection.

Depending on the input type, normal characteristics may include:

- No suspicious social-engineering language.
- No credential-related request.
- No financial request.
- No impersonation indicators.
- No other implemented detection conditions.

The exact result must match the current implementation.

## Expected Evidence

Evidence may include:

- Submitted event.
- Analysis result.
- Detection status.
- Risk score.
- Verdict.
- Explanation for the result.

## Expected Inovix Response

The expected behavior is:

- Process the event.
- Perform supported analysis.
- Avoid generating unnecessary high-risk findings.
- Avoid creating an unnecessary incident where incident handling is implemented.
- Return the appropriate safe or low-risk result based on the actual implementation.

## Limitations

A normal result only reflects the evidence and detection capabilities currently available to the implementation.

It must not be interpreted as a guarantee that the event is completely harmless.

---

# Safety Requirements

All secondary detection scenarios must follow these rules:

- Use synthetic or authorized test data.
- Do not attack unauthorized systems.
- Do not scan third-party systems without explicit permission.
- Do not use real stolen credentials.
- Do not execute malware.
- Do not expose secrets.
- Clearly distinguish simulated activity from verified implementation behavior.

---

# Documentation Status

These scenarios provide the secondary security research and controlled demonstration foundation for the Inovix MVP.

Implementation-specific detection thresholds, event schemas, incident criteria, response behavior, and correlation logic must only be documented as implemented after verification.

Any remaining TBD values represent information that has not yet been confirmed by the relevant implementation.
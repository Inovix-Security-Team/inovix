# Inovix Demo Flow

## Overview

This document describes the controlled demonstration flow for the current Inovix MVP implementation.

The demonstration uses safe and synthetic security input to show how information moves through the implemented security analysis pipeline.

Only functionality confirmed by the current codebase is described as implemented.

---

## Demo Objective

The current demonstration shows how security-related input moves through the implemented Inovix security engine.

The confirmed implementation flow is:

Security Input

↓

Input Validation

↓

Normalization

↓

Rule-Based Analysis

↓

Detection Findings

↓

Risk Scoring

↓

Verdict Generation

↓

Impact Assessment

↓

Response Decision

↓

Verification Result

The current implementation does not perform actual blocking, containment, remediation, incident creation, correlation, or SOC/dashboard display.

---

## Current Implemented Demo Scenario

The current implemented demonstration can use suspicious or phishing-style text containing one or more security indicators.

For example, a controlled synthetic input may contain:

- A URL
- Suspicious social-engineering language
- A credential request
- A financial request
- Possible impersonation language

The exact result depends on the indicators present in the input.

The demonstration must use synthetic or authorized test data only.

---

## Implemented Processing Flow

### 1. Provide Security Input

A security-related text input is provided to the Inovix Security Engine.

The input may include:

- Content
- Source
- Event type
- Optional metadata

**Status: Implemented**

↓

### 2. Validate Input

The Security Engine validates the submitted content before processing.

Invalid input produces an appropriate security-engine error.

**Status: Implemented**

↓

### 3. Normalize Input

The validated input is normalized into the internal event structure used by the Security Engine.

**Status: Implemented**

↓

### 4. Rule-Based Analysis

The current analyzer checks for selected indicators, including:

- URL presence
- Suspicious social-engineering language
- Credential-related requests
- Financial requests
- Selected impersonation language

**Status: Implemented**

↓

### 5. Generate Detection Findings

When supported indicators are detected, the rule-based detector creates explainable findings.

Each finding can contain:

- Rule ID
- Severity
- Reason
- Indicator

**Status: Implemented**

↓

### 6. Calculate Risk Score

The current implementation calculates a risk score from the severities of generated findings.

The score is normalized to a maximum of 100.

**Status: Implemented**

↓

### 7. Generate Verdict

The current implementation produces one of the following verdicts:

- SAFE
- SUSPICIOUS
- MALICIOUS
- UNKNOWN

The verdict is generated from the calculated risk score.

**Status: Implemented**

↓

### 8. Basic Impact Assessment

The Security Engine generates a basic impact assessment.

Current impact levels include:

- LOW
- MEDIUM
- HIGH

**Status: Implemented**

↓

### 9. Safe Response Decision

The current Security Engine produces a response decision.

Possible actions include:

- NO_ACTION
- MONITOR
- REVIEW

This stage does not execute real blocking, containment, or remediation.

**Status: Implemented**

↓

### 10. Verification Result

The current implementation returns a verification result indicating the state of the response workflow.

Response execution is currently not performed by the foundation Security Engine.

**Status: Implemented as a safe result structure**

---

## Example Demo Flow

A controlled synthetic suspicious message enters the system.

Example:

```text
Urgent action required. Verify account information at
https://example.test and provide your password.

The expected processing flow is:

Synthetic Security Input

↓

Validation

↓

Normalization

↓

URL Detected

Suspicious Language Detected

Credential Request Detected

↓

Detection Findings Generated

↓

Risk Score Calculated

↓

Verdict Generated

↓

Impact Assessment

↓

Safe Response Decision

↓

Verification Result

The exact score, verdict, and findings must be taken from the actual execution result and must not be manually claimed in advance.

Brute-Force Demo Scenario

Brute-force activity is documented as a controlled secondary security scenario.

The intended flow is:

Repeated Failed Login Events

↓

Detection

↓

Risk Assessment

↓

Possible Incident

However, the current Security Engine implementation does not yet confirm a dedicated brute-force detection rule.

Therefore:

Status: Pending implementation

The demo must not claim that brute-force detection is currently implemented until the relevant detection logic exists and is verified.

Possible Port-Scan Demo Scenario

Possible port-scanning activity is documented as a controlled secondary security scenario.

The intended flow is:

Multiple Connection Attempts

↓

Possible Scanning Pattern

↓

Detection

↓

Risk Assessment

However, the current Security Engine implementation does not yet confirm a dedicated port-scan detection rule.

Therefore:

Status: Pending implementation

No unauthorized systems may be scanned for demonstration purposes.

Normal Activity Scenario

A normal input can pass through the Security Engine without generating security findings.

Expected flow:

Normal Input

↓

Validation

↓

Normalization

↓

Analysis

↓

No Findings

↓

Risk Score: 0

↓

SAFE Verdict

↓

LOW Impact

↓

NO_ACTION

This scenario demonstrates that the current implementation can return a safe result when no configured indicators are detected.

Status: Implemented

Planned Demo Components

The following components are part of the intended Inovix MVP direction but are not confirmed as implemented in the current codebase:

AI or ML anomaly scoring
Threat-intelligence enrichment
Event correlation
Incident creation
Browser Guard integration
Automated or controlled blocking
SOC/dashboard integration

These components must remain planned or pending until implementation is verified.

Demo Evidence

The demonstration should capture actual output from the implemented Security Engine.

Relevant evidence may include:

Input content
Source
Event type
Detection findings
Rule IDs
Severity
Detection reasons
Indicators
Risk score
Verdict
Impact level
Response decision
Verification status

Only information produced by the actual implementation should be presented as confirmed demo output.

Safety Requirements

All demonstration scenarios must follow these rules:

Use synthetic or authorized test data.
Do not attack external or unauthorized systems.
Do not scan unauthorized systems.
Do not use real stolen credentials.
Do not execute malware.
Do not expose secrets.
Do not claim blocking or prevention unless it has actually been implemented and verified.
Clearly distinguish implemented behavior from planned or simulated behavior.
Implementation Status Summary
Demo Capability	Current Status
Security input processing	Implemented
Input validation	Implemented
Input normalization	Implemented
Rule-based analysis	Implemented
Explainable findings	Implemented
Risk scoring	Implemented
Verdict generation	Implemented
Basic impact assessment	Implemented
Safe response decision	Implemented
Verification result structure	Implemented
Normal activity handling	Implemented
Brute-force detection	Pending
Possible port-scan detection	Pending
AI/ML anomaly scoring	Pending
Threat-intelligence enrichment	Pending
Event correlation	Pending
Incident creation	Pending
Browser Guard	Pending
Automated prevention/blocking	Pending
SOC/dashboard display	Pending
Documentation Status

This demo flow reflects the current implementation-backed documentation for the Inovix Security Engine.

As additional components are implemented, this document should be updated only after their behavior has been verified against the relevant codebase or confirmed by the responsible developer.
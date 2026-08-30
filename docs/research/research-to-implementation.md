# Research to Implementation Mapping

## Overview

This document connects Inovix security research with the current and planned project implementation.

The purpose is to prevent research findings, documentation, and project claims from becoming disconnected from the actual codebase.

A feature is only marked as implemented when its behavior has been confirmed through the relevant implementation.

---

## Research to Implementation Mapping

| Research Finding | Inovix Implementation | Status |
|---|---|---|
| Suspicious URL indicators | URL analysis and security evaluation workflow | Planned / Verify |
| Phishing-style link detection | Browser Guard and URL analysis | Planned |
| Repeated failed login indicators | Brute-force detection rule | Verify Implementation |
| Port-scanning indicators | Possible port-scan detection rule | Verify Implementation |
| Event normalization | Security event processing | Verify Implementation |
| Rule-based detection | Security Engine detection logic | Verify Implementation |
| Risk classification | Risk scoring and verdict generation | Verify Implementation |
| Severity classification | Prototype risk bands | Research / Verify |
| Anomalous behavior indicators | AI or ML anomaly scoring | Planned |
| IOC or reputation enrichment | Threat intelligence integration | Pending |
| Event correlation | Correlation workflow | Pending |
| Incident prioritization | Risk and incident workflow | Pending |
| Response actions | Controlled response simulation | Planned |
| SOC visualization | Dashboard or SOC interface | Verify Implementation |

---

## Primary Scenario Mapping

### Suspicious URL / Phishing Scenario

**Research Finding**

Suspicious URLs may contain observable characteristics that can support security analysis, such as unusual URL structures, suspicious domains, reputation indicators, or other relevant signals.

**Expected Inovix Implementation**

The intended workflow is:

Suspicious URL
↓
Event Ingestion
↓
Normalization
↓
Detection and Analysis
↓
Risk Assessment
↓
Security Event
↓
Incident or Dashboard Display

**Status**

Planned / Implementation Verification Required

The exact Browser Guard, ML, threat-intelligence, correlation, incident, and response functionality must be confirmed before being documented as implemented.

---

## Brute-Force Scenario Mapping

**Research Finding**

Repeated failed authentication attempts can represent a pattern consistent with brute-force activity.

Relevant indicators may include:

- Repeated failures
- Source identifier or IP address
- Target username or account
- Attempt frequency
- Time window
- Number of attempts

**Expected Inovix Implementation**

Detection Rule
↓
Risk Assessment
↓
Security Event
↓
Possible Incident Creation

**Status**

Verify Implementation

The exact detection threshold remains:

**TBD — implementation threshold**

---

## Possible Port-Scan Scenario Mapping

**Research Finding**

Multiple connection attempts across different destination ports may indicate reconnaissance or network service scanning.

Relevant indicators may include:

- Source identifier or IP address
- Target system
- Multiple destination ports
- Connection frequency
- Number of attempts
- Time window

**Expected Inovix Implementation**

Detection Rule
↓
Possible Port-Scan Detection
↓
Risk Assessment
↓
Security Event

**Status**

Verify Implementation

The exact detection thresholds remain:

**TBD — implementation threshold**

---

## Normal Activity Mapping

**Research Finding**

A security system should not treat every event as malicious.

Normal activity is required as a comparison scenario to demonstrate that events without sufficient suspicious indicators do not automatically create unnecessary incidents.

**Expected Inovix Implementation**

Normal Event
↓
Analysis
↓
No Significant Detection
↓
No Unnecessary Incident

**Status**

Verify Implementation

The final behavior depends on the implemented detection, risk, correlation, and incident logic.

---

## Risk and Severity Mapping

The current Inovix prototype documentation uses the following risk bands:

| Score | Risk Level |
|---|---|
| 0–29 | Low |
| 30–59 | Medium |
| 60–79 | High |
| 80–100 | Critical |

These are **Inovix prototype risk bands**.

They are not presented as industry-standard production thresholds.

The implementation must be verified to confirm whether these ranges are currently used by the Security Engine and backend workflow.

**Status: Verify Implementation**

---

## Implementation Status Rules

Documentation should use the following categories:

### Implemented

The functionality exists in the current codebase and its behavior has been verified.

### Verify Implementation

Relevant code or project structure may exist, but the exact behavior still needs confirmation from the implementation or responsible developer.

### Planned

The functionality is part of the intended project direction but is not yet confirmed as implemented.

### Pending

The feature or integration requires further technical decisions or implementation.

### Research

The information is based on security research and is not automatically evidence that the corresponding functionality exists in Inovix.

---

## Verification Workflow

Research Finding
↓
Expected Implementation
↓
Codebase Review
↓
Developer Confirmation
↓
Documentation Update
↓
Implementation Status Confirmed

Documentation must not move from **Planned**, **Pending**, or **Verify Implementation** to **Implemented** without verification.

## Documentation Status

This document provides the initial cross-reference between Inovix security research and implementation.

It should be updated whenever a relevant feature is implemented, changed, verified, or removed from the project scope.
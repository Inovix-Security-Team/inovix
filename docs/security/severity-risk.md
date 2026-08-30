# Severity and Risk Classification

## Overview

This document defines the severity and risk classification used for the Inovix MVP documentation and controlled demonstration scenarios.

The ranges described here are **Inovix prototype risk bands**. They are not claimed to be industry-standard production risk thresholds.

Risk classification should be based on the evidence available from the implemented detection and analysis workflow.

---

## Inovix Prototype Risk Bands

| Score | Risk Level |
|---|---|
| 0–29 | Low |
| 30–59 | Medium |
| 60–79 | High |
| 80–100 | Critical |

---

## Low Risk

**Score Range:** 0–29

Low risk represents activity with limited or weak evidence of suspicious behavior.

The event may require logging or monitoring, but the available evidence does not currently indicate a significant security threat.

### Example

A normal event with no significant suspicious indicators may receive a low risk score.

### Expected Handling

- Record the event where applicable.
- Avoid creating an unnecessary high-severity incident.
- Continue normal monitoring if supported by the implementation.

---

## Medium Risk

**Score Range:** 30–59

Medium risk represents activity containing suspicious indicators that require attention or further analysis.

The available evidence may indicate potentially harmful behavior, but it may not be sufficient to confirm a severe security incident.

### Example

A suspicious pattern or URL with some relevant indicators may receive a medium risk score.

### Expected Handling

- Record the relevant evidence.
- Mark the activity as requiring attention.
- Support further analysis or correlation where implemented.

---

## High Risk

**Score Range:** 60–79

High risk represents activity with stronger evidence of potentially malicious or harmful behavior.

The event may require prioritization and investigation depending on the implemented incident workflow.

### Example

Repeated suspicious activity with multiple supporting indicators may result in a high risk classification.

### Expected Handling

- Generate or record the relevant security event.
- Preserve supporting evidence.
- Support incident creation or prioritization where implemented.
- Trigger an appropriate warning or simulated response if supported.

---

## Critical Risk

**Score Range:** 80–100

Critical risk represents activity with strong evidence of significant potential security impact.

The event should be treated as requiring urgent attention within the capabilities of the implemented prototype.

### Example

Multiple strong indicators combined with high potential impact may result in a critical risk classification.

### Expected Handling

- Prioritize the event for investigation.
- Preserve relevant evidence.
- Support incident creation where implemented.
- Trigger the implemented or simulated response workflow where available.

The exact response must not be claimed as automatic prevention or blocking unless that behavior has been verified.

---

## Severity and Risk

Severity and risk are related but should not automatically be treated as identical.

**Severity** describes the seriousness or potential impact of the detected activity.

**Risk** represents the assessment produced from the available evidence and scoring logic.

The exact relationship between severity, risk score, impact, and incident priority must match the implemented Inovix logic.

---

## Classification Principles

The Inovix prototype should follow these principles:

- A detection is not automatically proof of malicious activity.
- Evidence should support the assigned classification.
- Uncertainty should be represented where evidence is incomplete.
- Normal activity should not create unnecessary incidents.
- Detection thresholds must remain implementation-backed or explicitly marked as TBD.
- Risk scores should not be presented as industry-standard security ratings.

---

## Documentation Status

The score ranges documented here represent the current **Inovix prototype risk bands**.

Any future changes to the scoring methodology, severity logic, incident priority, or response behavior must be verified against the implementation before being documented as implemented.
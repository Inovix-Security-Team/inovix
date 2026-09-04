# Research to Implementation Mapping

## Overview

This document connects Inovix security research and planned security capabilities with the current implementation.

Its purpose is to prevent research findings, planned functionality, and implemented functionality from being treated as the same thing.

Status definitions:

- **Implemented** — confirmed by the current codebase.
- **Pending** — intended or researched but not currently implemented.
- **TBD** — implementation details are not yet finalized.
- **Research** — documented security knowledge that may support future implementation.

---

## Current Mapping

| Research Finding | Inovix Implementation | Status |
|---|---|---|
| Suspicious URL indicators | Rule-based analysis and URL detection | Implemented |
| Suspicious social-engineering language | Rule-based detection | Implemented |
| Credential request indicators | Rule-based detection | Implemented |
| Financial request indicators | Rule-based detection | Implemented |
| Possible impersonation language | Rule-based detection | Implemented |
| Risk scoring | Severity-weighted risk calculation | Implemented |
| Security verdict generation | SAFE / SUSPICIOUS / MALICIOUS verdict logic | Implemented |
| Basic impact assessment | LOW / MEDIUM / HIGH impact logic | Implemented |
| Response decision | REVIEW / MONITOR / NO_ACTION decision structure | Implemented |
| Verification | Safe verification result structure | Implemented |
| Brute-force indicators | Dedicated detection rule | Pending |
| Port-scan indicators | Dedicated detection rule | Pending |
| AI anomaly behavior | Machine-learning implementation | Pending |
| Threat intelligence / IOC enrichment | Threat-intelligence integration | Pending |
| Event correlation | Correlation engine | Pending |
| Incident creation | Incident workflow | Pending |
| SOC or dashboard display | Frontend/dashboard implementation | Pending |
| Browser Guard | Browser extension integration | Pending |

---

## Implemented Detection Research

### Suspicious URL

The current security engine identifies URL presence through rule-based analysis.

Current implementation checks whether the analyzed content contains:

- `http://`
- `https://`

A URL by itself does not automatically produce a malicious verdict.

The URL indicator contributes to the overall set of findings used for risk calculation.

**Status: Implemented**

---

### Suspicious Social-Engineering Language

The current analyzer checks for selected suspicious phrases, including:

- `verify account`
- `urgent action`
- `suspicious login`

When detected, the rule-based detector creates a finding for suspicious social-engineering language.

**Status: Implemented**

---

### Credential Request

The current analyzer checks for indicators related to credentials and authentication information.

Examples include:

- password
- OTP
- one-time password
- login credential
- credentials

When detected, the rule-based detector generates a high-severity finding.

**Status: Implemented**

---

### Financial Request

The current analyzer checks for selected financial-request indicators.

Examples include:

- transfer money
- send money
- money transfer
- UPI account
- UPI ID
- bank transfer

When detected, the rule-based detector generates a high-severity finding.

**Status: Implemented**

---

### Possible Impersonation

The current analyzer checks for selected phrases that may indicate impersonation of a trusted organization.

Examples include:

- I am from your bank
- I'm from your bank
- I am from the bank
- from your bank

When detected, the rule-based detector generates a critical-severity finding.

This detection is based on selected language indicators and does not independently prove that impersonation has occurred.

**Status: Implemented**

---

## Risk Scoring Implementation

The current security engine calculates a normalized risk score from the severity of generated findings.

Current severity weights are:

| Finding Severity | Score Weight |
|---|---:|
| LOW | 20 |
| MEDIUM | 50 |
| HIGH | 80 |
| CRITICAL | 100 |

The combined score is limited to a maximum value of 100.

**Status: Implemented**

---

## Verdict Implementation

The current security engine generates verdicts using the calculated risk score.

| Risk Score | Verdict |
|---|---|
| 0 | SAFE |
| 1–79 | SUSPICIOUS |
| 80–100 | MALICIOUS |
| Outside 0–100 | UNKNOWN |

These verdict thresholds describe the current implementation.

They are separate from the Inovix prototype risk-band documentation and must not be presented as universal industry-standard thresholds.

**Status: Implemented**

---

## Impact Assessment Implementation

The current implementation performs a basic impact assessment.

| Risk Score | Impact Level |
|---|---|
| 0 | LOW |
| 1–79 | MEDIUM |
| 80–100 | HIGH |

The impact assessment currently provides a basic explanation based on the generated risk score.

**Status: Implemented**

---

## Response Decision Implementation

The current security engine creates a safe response decision.

| Verdict | Response Action |
|---|---|
| SAFE | NO_ACTION |
| SUSPICIOUS | MONITOR |
| MALICIOUS | REVIEW |

The current implementation does not perform actual containment, blocking, or remediation.

The response structure represents a safe decision or recommendation only.

**Status: Implemented**

---

## Verification Implementation

The current verification stage is a safe foundation structure.

Response actions are not actually executed by the current security engine.

The verification result therefore represents that execution has not occurred.

**Status: Implemented as a safe result structure**

---

## Pending Research Areas

### Brute-Force Detection

Research identifies repeated failed authentication attempts as a potential detection scenario.

The current codebase does not yet confirm a dedicated brute-force detection rule.

Required implementation details include:

- Event format
- Source identifier
- Account or username
- Attempt count
- Time window
- Detection threshold

**Status: Pending**

---

### Possible Port-Scan Detection

Research identifies repeated connection attempts across multiple destination ports as a potential scanning pattern.

The current codebase does not yet confirm a dedicated port-scan detection rule.

Required implementation details include:

- Event format
- Source identifier
- Target system
- Destination ports
- Number of attempts
- Time window
- Detection threshold

**Status: Pending**

---

### Machine-Learning / Anomaly Detection

The repository contains an ML-related project structure, but the current implementation does not confirm active machine-learning analysis.

Anomaly scoring must remain documented as planned or pending until implementation is verified.

**Status: Pending**

---

### Threat Intelligence

The repository contains a threat-intelligence-related project structure, but the current implementation does not confirm active external threat-intelligence enrichment.

IOC enrichment, reputation analysis, or other threat-intelligence functionality must not be described as implemented.

**Status: Pending**

---

### Event Correlation

The intended Inovix workflow includes correlation of related security events.

The current security engine implementation does not yet confirm an event-correlation mechanism.

**Status: Pending**

---

### Incident Creation

The current security engine returns structured findings, risk information, impact information, response decisions, and verification information.

A separate incident creation and management workflow is not currently confirmed.

**Status: Pending**

---

### Browser Guard

The repository contains a browser-extension directory, but active Browser Guard functionality is not currently confirmed by the available implementation.

**Status: Pending**

---

### SOC / Dashboard

The frontend structure is currently not confirmed as an implemented SOC or dashboard application.

Dashboard behavior, incident visualization, and security-event display remain pending.

**Status: Pending**

---

## Documentation Rule

This mapping must be updated whenever implementation changes.

The following workflow should be followed:

Research Finding

↓

Implementation

↓

Developer Verification

↓

Documentation Update

A research finding must not automatically be described as an implemented Inovix capability.

Likewise, an implemented feature should be reflected in the relevant security, demo, architecture, and README documentation after verification.

---

## Current Conclusion

The current implementation confirms a foundation for:

- Input validation
- Input normalization
- Rule-based security analysis
- Explainable findings
- Risk scoring
- Verdict generation
- Basic impact assessment
- Safe response decisions
- Verification result structure

The following major MVP capabilities remain pending or require further implementation verification:

- Brute-force detection
- Possible port-scan detection
- AI or ML anomaly scoring
- Threat-intelligence enrichment
- Event correlation
- Incident creation
- Browser Guard integration
- SOC/dashboard integration
- Automated prevention or blocking

This document represents the current research-to-implementation status and should be revised as additional Inovix components are implemented and verified.
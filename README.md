# Inovix

Inovix is a cybersecurity platform being developed to support security analysis, threat detection, risk assessment, and informed response.

The current MVP implementation provides a backend foundation and a rule-based Security Engine for analyzing security-related input.

Inovix is currently under active development. This README distinguishes between functionality confirmed by the current implementation and functionality that is planned or pending.

---

## Problem

Security-related events can contain indicators that require analysis and prioritization.

The Inovix MVP explores a workflow for processing security input through:

Security Input

↓

Detection and Analysis

↓

Risk Assessment

↓

Impact Assessment

↓

Response Decision

↓

Verification Result

The project is intended to expand this workflow as additional MVP components are implemented.

---

## Current Solution

The current Inovix implementation provides a foundation for:

- Input validation
- Input normalization
- Rule-based security analysis
- Explainable security findings
- Risk scoring
- Verdict generation
- Basic impact assessment
- Safe response decision generation
- Verification result structure
- Backend API foundation
- API versioning
- Health-check endpoint
- Analysis endpoint

The current Security Engine does not perform actual blocking, containment, remediation, or other destructive response actions.

---

## Architecture

The current project structure includes:

```text
inovix/
│
├── backend/                 # FastAPI backend application
├── security-engine/         # Security analysis and detection logic
├── browser-extension/       # Browser-related component structure
├── frontend/                # Frontend component structure
├── docs/                    # Project documentation
├── tests/                   # Test structure
└── scripts/                 # Supporting scripts

The currently implemented Security Engine flow is:

Security Input
      ↓
Validation
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

Browser Guard, event correlation, incident management, SOC display, and automated prevention are not currently confirmed as implemented.

Detailed architecture documentation is available in:

docs/architecture/system-overview.md

Current Features
Implemented
Security Engine
Input validation
Input normalization
Rule-based analysis
Detection of URL presence
Detection of selected suspicious social-engineering language
Detection of credential-related requests
Detection of financial requests
Detection of selected impersonation language
Explainable security findings
Severity-based risk scoring
SAFE, SUSPICIOUS, and MALICIOUS verdict generation
Basic impact assessment
Safe response decision generation
Verification result structure
Backend
FastAPI application foundation
API versioning
Health-check endpoint
Analysis endpoint
Request and response schemas
Backend API tests
Testing
Security Engine tests
Backend API tests
Project-level test structure
Planned or Pending Features

The following capabilities are part of the intended project direction but are not currently confirmed as implemented:

Brute-force detection
Possible port-scan detection
AI or ML anomaly scoring
Threat-intelligence enrichment
Event correlation
Incident creation and management
Browser Guard functionality
Frontend implementation
SOC or dashboard integration
Automated prevention or blocking
Expanded reporting

These features must not be presented as current implemented capabilities until verified.

Security Detection

The current rule-based Security Engine can generate findings based on selected indicators.

Examples include:

Indicator	Current Detection
URL presence	URL detection
Suspicious language	Rule-based detection
Credential request	Rule-based detection
Financial request	Rule-based detection
Possible impersonation language	Rule-based detection

Detection findings contain explainable information such as:

Rule ID
Severity
Reason
Indicator

Detailed security scenarios are documented in:

docs/security/primary-attack-scenario.md
docs/security/detection-scenarios.md
docs/security/severity-risk.md
docs/security/mitre-mapping.md
Risk and Verdicts

The current Security Engine calculates a normalized risk score with a maximum value of 100.

The current implementation uses severity-based scoring for generated findings.

Current verdict behavior is:

Risk Score	Verdict
0	SAFE
1–79	SUSPICIOUS
80–100	MALICIOUS

These values describe the current implementation and should not be treated as universal industry-standard security thresholds.

The Inovix prototype risk bands are separately documented as:

Score Range	Risk Level
0–29	Low
30–59	Medium
60–79	High
80–100	Critical

Detailed information is available in:

docs/security/severity-risk.md

Response Behavior

The current Security Engine produces safe response decisions.

Verdict	Response Action
SAFE	NO_ACTION
SUSPICIOUS	MONITOR
MALICIOUS	REVIEW

The current implementation does not execute:

Blocking
Containment
Remediation
Automated prevention

Response actions currently represent safe decision structures rather than executed security actions.

Technology Stack
Confirmed Third-Party Technology
FastAPI — backend API framework
Inovix-Built Components

The following represent Inovix application logic rather than third-party security functionality:

Security Engine
Rule-based detection logic
Input validation
Input normalization
Risk scoring
Verdict generation
Impact assessment
Response decision structure
Verification structure
Proposed or Unconfirmed Components

The following have been researched or proposed but are not currently confirmed as implemented:

SQLite
scikit-learn
Wazuh
Suricata
Zeek
Streamlit
Plotly

These must remain clearly distinguished from implemented functionality.

Setup

Detailed development setup instructions are available in:

docs/setup/development-setup.md

Backend dependencies are defined in:

backend/requirements.txt

Usage

The current backend includes:

A health-check endpoint
An analysis endpoint

The exact API contract is documented in:

docs/api/api-contract.md

The analysis endpoint is currently part of the backend foundation.

Current backend analysis behavior must match the actual implementation and should not be confused with the full Security Engine integration until that integration is confirmed.

Demo

The current demonstration focuses on controlled and synthetic security input.

A supported implementation flow includes:

Synthetic Security Input
        ↓
Validation
        ↓
Normalization
        ↓
Rule-Based Analysis
        ↓
Detection Findings
        ↓
Risk Score
        ↓
Verdict
        ↓
Impact Assessment
        ↓
Safe Response Decision
        ↓
Verification Result

Additional scenarios such as brute-force detection, possible port scanning, AI anomaly scoring, event correlation, incident creation, and SOC display remain dependent on further implementation.

Detailed demo documentation is available in:

docs/demo/demo-flow.md

Security Notes

All security testing and demonstrations must use controlled, synthetic, or otherwise authorized activity.

The project must not:

Attack unauthorized systems
Scan external systems without authorization
Use real stolen credentials
Execute malware for demonstration
Expose secrets in code or documentation

A detection result must not automatically be treated as proof of malicious activity.

Likewise, planned security functionality must not be presented as implemented.

Open-Source Components

Inovix may integrate open-source or third-party components as development progresses.

Any external component must be clearly distinguished from functionality developed within Inovix.

Current research and implementation status is documented in:

docs/research/open-source-components.md

Limitations

Current limitations include:

No confirmed brute-force detection implementation
No confirmed port-scan detection implementation
No confirmed ML anomaly detection
No confirmed threat-intelligence integration
No confirmed event correlation
No confirmed incident management workflow
No confirmed Browser Guard functionality
No confirmed SOC/dashboard implementation
No automated blocking or remediation

These limitations reflect the current documented implementation state.

Future Scope

Potential future development includes:

Brute-force detection
Port-scan detection
AI or ML anomaly scoring
Threat-intelligence enrichment
Event correlation
Incident management
Browser Guard integration
SOC/dashboard implementation
Expanded response capabilities
Reporting and visualization

Future functionality will be documented as implemented only after verification.

Documentation
Area	Location
Architecture	docs/architecture/system-overview.md
API	docs/api/api-contract.md
Security Overview	docs/security/security-overview.md
Primary Attack Scenario	docs/security/primary-attack-scenario.md
Detection Scenarios	docs/security/detection-scenarios.md
Severity and Risk	docs/security/severity-risk.md
MITRE Mapping	docs/security/mitre-mapping.md
Development Setup	docs/setup/development-setup.md
Demo Flow	docs/demo/demo-flow.md
Open-Source Components	docs/research/open-source-components.md
Research to Implementation	docs/research/research-to-implementation.md
Research Notes	docs/research/research-notes.md
Current Status

Implemented

Backend API foundation
Security Engine foundation
Rule-based detection
Risk scoring
Verdict generation
Basic impact assessment
Safe response decision structure
Verification result structure
Automated tests for current components

Planned / Pending

Brute-force detection
Possible port-scan detection
AI/ML analysis
Threat intelligence
Event correlation
Incident management
Browser Guard
Frontend/dashboard
Automated prevention

Inovix is under active development.

Documentation is updated to reflect verified implementation and clearly identify planned, pending, research, or TBD functionality.
# Open-Source Components

## Overview

This document tracks open-source and third-party components relevant to the Inovix MVP.

A component is only described as implemented when its use is confirmed by the current codebase or responsible developer.

Components that are proposed, planned, or not yet integrated are clearly identified.

---

## FastAPI

### Tool

FastAPI

### Purpose

FastAPI provides the backend API framework for Inovix.

### Where Used

The current backend implementation uses FastAPI for API routing and application services.

Confirmed API components include:

- Application setup
- API versioning
- Health-check endpoint
- Analysis endpoint

### License

MIT License.

### Integration Method

FastAPI is used directly within the Inovix backend application.

### Data Produced

The backend returns structured API responses for supported endpoints.

### What Inovix Adds

Inovix defines the application structure, API schemas, analysis workflow, and security-related functionality built around the backend framework.

### Status

**Implemented**

---

## SQLite

### Tool

SQLite

### Purpose

SQLite may be used for local data storage depending on the final architecture.

### Where Used

Current repository implementation has not yet confirmed active SQLite integration.

### License

Public domain.

### Integration Method

TBD — implementation not confirmed.

### Data Produced

TBD.

### What Inovix Adds

If integrated, Inovix would define the application data models, storage logic, and security-related data handling.

### Limitations

SQLite usage and final storage architecture are not yet confirmed.

### Status

**TBD — implementation not confirmed**

---

## scikit-learn

### Tool

scikit-learn

### Purpose

scikit-learn is a potential machine-learning component for anomaly detection or other security analysis.

### Where Used

The current repository contains an ML-related structure, but machine-learning functionality is not confirmed as implemented.

### License

BSD 3-Clause License.

### Integration Method

TBD — implementation not confirmed.

### Data Produced

Potential future outputs may include anomaly scores or classification results.

These outputs must not be described as current Inovix functionality until implementation is confirmed.

### What Inovix Adds

If integrated, Inovix would define the security events, features, analysis workflow, and use of any generated results.

### Limitations

No confirmed machine-learning detection implementation is currently documented.

### Status

**Planned / TBD**

---

## Wazuh

### Tool

Wazuh

### Purpose

Wazuh is a proposed security monitoring and event-data source.

### Where Used

No confirmed Wazuh integration exists in the current Inovix implementation.

### Integration Method

TBD.

### Data Produced

Potential future data may include security alerts, monitoring events, or host-related information.

### What Inovix Adds

If integrated, Inovix would process or analyze selected security data within its own workflow.

### Limitations

Wazuh is currently a proposed component and must not be presented as implemented.

### Status

**Proposed — not confirmed as implemented**

---

## Suricata

### Tool

Suricata

### Purpose

Suricata is a proposed network security monitoring and intrusion detection component.

### Where Used

No confirmed Suricata integration exists in the current Inovix implementation.

### Integration Method

TBD.

### Data Produced

Potential future outputs may include network security events and alerts.

### What Inovix Adds

If integrated, Inovix would define how selected events are ingested, analyzed, and displayed.

### Limitations

Suricata is currently a proposed component and must not be presented as implemented.

### Status

**Proposed — not confirmed as implemented**

---

## Zeek

### Tool

Zeek

### Purpose

Zeek is a proposed network monitoring and analysis component.

### Where Used

No confirmed Zeek integration exists in the current Inovix implementation.

### Integration Method

TBD.

### Data Produced

Potential future outputs may include structured network activity and event data.

### What Inovix Adds

If integrated, Inovix would define the ingestion and analysis workflow for selected security events.

### Limitations

Zeek is currently a proposed component and must not be presented as implemented.

### Status

**Proposed — not confirmed as implemented**

---

## Streamlit / Plotly

### Tool

Streamlit / Plotly

### Purpose

These tools are proposed for possible dashboard, visualization, or SOC-related functionality.

### Where Used

The current repository does not confirm an implemented frontend dashboard using Streamlit or Plotly.

### Integration Method

TBD.

### Data Produced

Potential future outputs may include security visualizations, incident information, and analysis results.

### What Inovix Adds

If integrated, Inovix would define the dashboard workflow, displayed security information, and user interaction.

### Limitations

Dashboard technology and implementation are not yet confirmed.

### Status

**Planned / TBD**

---

## Inovix-Built Components

The following components are part of the Inovix project implementation and should not be described as third-party functionality:

- Security Engine
- Rule-based detection logic
- Input validation
- Input normalization
- Risk scoring
- Verdict generation
- Basic impact assessment
- Safe response decision structure
- Verification result structure
- Inovix backend application structure

Third-party frameworks or libraries may support these components, but the Inovix application logic built around them is project-specific.

---

## Component Status Summary

| Component | Purpose | Current Status |
|---|---|---|
| FastAPI | Backend API framework | Implemented |
| SQLite | Data storage | TBD — implementation not confirmed |
| scikit-learn | ML / anomaly analysis | Planned / TBD |
| Wazuh | Security monitoring input | Proposed |
| Suricata | Network security input | Proposed |
| Zeek | Network monitoring input | Proposed |
| Streamlit / Plotly | Dashboard / visualization | Planned / TBD |
| Inovix Security Engine | Security analysis | Implemented |

---

## Documentation Rule

Open-source and third-party components must be clearly distinguished from functionality built by Inovix.

A proposed or researched component must not be presented as implemented until its actual integration is confirmed through the codebase or responsible developer.

This document must be updated when new third-party components are integrated into the Inovix MVP.
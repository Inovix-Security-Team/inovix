# Open-Source Components

## Overview

This document tracks open-source and third-party components that are relevant to the Inovix MVP.

A component must not be described as implemented in Inovix unless its use has been confirmed by the development team or verified in the project implementation.

Proposed or evaluated tools are clearly separated from confirmed components.

---

## Proposed Security-Input Components

### Wazuh

**Purpose:** Security monitoring, log collection, and security event generation.

**Potential Use in Inovix:** Wazuh may provide security events or monitoring data that could be processed by the Inovix workflow.

**Implementation Status:** Proposed / Not Yet Confirmed

**License:** GPL-2.0

**Integration Method:** TBD — depends on final architecture.

**Data Produced:** Security alerts, log events, monitoring information, and related security telemetry.

**What Inovix Adds:** Inovix may normalize, analyze, correlate, score, and present relevant security information.

**Limitations:** Wazuh functionality is third-party functionality and must not be presented as functionality built entirely by Inovix.

---

### Suricata

**Purpose:** Network security monitoring and intrusion detection.

**Potential Use in Inovix:** Suricata may provide network-related security events for further processing and analysis.

**Implementation Status:** Proposed / Not Yet Confirmed

**License:** GPL-2.0

**Integration Method:** TBD — depends on final architecture.

**Data Produced:** Network security alerts and event information.

**What Inovix Adds:** Inovix may process Suricata-generated events together with its own detection, risk, correlation, incident, or reporting workflow.

**Limitations:** Detection capabilities provided directly by Suricata remain third-party functionality.

---

### Zeek

**Purpose:** Network security monitoring and network event generation.

**Potential Use in Inovix:** Zeek may provide structured network telemetry or event data for analysis.

**Implementation Status:** Proposed / Not Yet Confirmed

**License:** BSD-style open-source license

**Integration Method:** TBD — depends on final architecture.

**Data Produced:** Network activity and protocol-level event data.

**What Inovix Adds:** Inovix may normalize and combine relevant security events with its own analysis and risk workflow.

**Limitations:** Zeek-generated network visibility remains third-party functionality.

---

## Proposed Platform Components

### FastAPI

**Purpose:** Backend API framework.

**Potential Use in Inovix:** The current repository contains a backend foundation structured around API endpoints.

**Implementation Status:** Implementation must be verified against the current backend codebase.

**License:** MIT License

**Integration Method:** Used as part of the backend application layer where confirmed.

**Data Produced:** API request and response handling.

**What Inovix Adds:** The application-specific API logic, security workflow, validation, and integration are part of the Inovix project.

**Limitations:** FastAPI is a third-party framework and must not be presented as developed by Inovix.

---

### SQLite

**Purpose:** Lightweight database storage.

**Potential Use in Inovix:** SQLite may be used for local storage during prototype or MVP development.

**Implementation Status:** Proposed / Verify Current Implementation

**License:** Public domain

**Integration Method:** TBD — depends on confirmed storage architecture.

**Data Produced:** Structured locally stored application data.

**What Inovix Adds:** The Inovix data model, application logic, and security workflow remain project-specific.

**Limitations:** Database functionality itself is provided by SQLite.

---

### scikit-learn

**Purpose:** Machine-learning utilities and algorithms.

**Potential Use in Inovix:** May support anomaly scoring or other ML-based analysis if included in the final implementation.

**Implementation Status:** Planned / Not Yet Confirmed

**License:** BSD 3-Clause

**Integration Method:** TBD — depends on the final ML implementation.

**Data Produced:** Model predictions, anomaly scores, or other analysis output.

**What Inovix Adds:** Inovix-specific feature selection, security context, risk interpretation, and workflow integration.

**Limitations:** Machine-learning functionality must not be claimed as implemented until verified in the codebase.

---

### Streamlit

**Purpose:** Rapid application and dashboard development.

**Potential Use in Inovix:** May be used to provide a prototype or MVP interface.

**Implementation Status:** Proposed / Verify Current Implementation

**License:** Apache License 2.0

**Integration Method:** TBD — depends on confirmed frontend or dashboard implementation.

**Data Produced:** User interface and visualization output.

**What Inovix Adds:** The security-focused dashboard logic, workflows, and application-specific presentation.

**Limitations:** Streamlit is a third-party application framework.

---

### Plotly

**Purpose:** Data visualization.

**Potential Use in Inovix:** May support charts and visual representation of security events, risk, or incidents.

**Implementation Status:** Proposed / Verify Current Implementation

**License:** MIT License

**Integration Method:** TBD — depends on confirmed dashboard implementation.

**Data Produced:** Interactive or static data visualizations.

**What Inovix Adds:** Inovix-specific security data, analysis context, and dashboard workflows.

**Limitations:** Visualization capabilities provided by Plotly remain third-party functionality.

---

## Component Status Summary

| Component | Purpose | Current Status |
|---|---|---|
| Wazuh | Security monitoring | Proposed |
| Suricata | Network detection | Proposed |
| Zeek | Network telemetry | Proposed |
| FastAPI | Backend API | Verify implementation |
| SQLite | Data storage | Proposed / Verify |
| scikit-learn | ML and anomaly analysis | Planned |
| Streamlit | Dashboard or interface | Proposed / Verify |
| Plotly | Data visualization | Proposed / Verify |

## Documentation Rule

Open-source or third-party functionality must always be clearly distinguished from functionality developed by Inovix.

The documentation should follow this rule:

**Third-Party Component**
↓
Provides underlying capability or data

**Inovix**
↓
Adds project-specific processing, analysis, detection, correlation, risk assessment, incident handling, response workflow, or presentation

A proposed component must remain marked as proposed until its use is confirmed by the team or verified in the implementation.

## Documentation Status

This document represents the current research and component-tracking foundation.

Implementation status must be updated as the project architecture and codebase are verified.
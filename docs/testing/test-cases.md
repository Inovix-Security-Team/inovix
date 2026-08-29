# Inovix Comprehensive Test Cases

## 1. Event Validation & Input Handling
- **TC-EV-01**: Submit valid event format -> Expected: Ingestion success.
- **TC-EV-02**: Submit payload with missing timestamp/ID -> Expected: Validation rejection without crashing.
- **TC-EV-03**: Malformed JSON input -> Expected: Safe parsing error code.

## 2. Security & Detection Scenarios
- **TC-DET-01 (Brute Force)**: Submit 15 failed logins in sequence -> Expected: Detection triggered, Severity HIGH, Risk Score >= 80 (Critical)[cite: 2].
- **TC-DET-02 (Port Scan)**: Submit multi-port connection attempt pattern -> Expected: Port scan rule matched, risk calculated[cite: 2].
- **TC-DET-03 (Normal Activity)**: Submit standard successful user login -> Expected: No incident generated, no false positives.

## 3. Demo Mode Validation
- **TC-DEMO-01**: Execute end-to-end flow with external security tools unavailable -> Expected: Demo Mode intercepts, uses synthetic fallbacks, populates dashboard successfully[cite: 2].
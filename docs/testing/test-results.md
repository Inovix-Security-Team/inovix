# Inovix Task 002 Test Results Summary

| Scenario | Expected Result | Actual Result | Status | Notes |
| :--- | :--- | :--- | :--- | :--- |
| Normal Activity | Ingested; no false incidents | Ingested; 0 incidents created | **PASS** | Synthetic data verified |
| Brute-Force Attack | High Risk incident created | Detection triggered; Risk=85 | **PASS** | Synthetic event parsed[cite: 2] |
| Port Scan | Network anomaly rule matched | Detection triggered; Risk=65 | **PASS** | Verified via fixtures[cite: 2] |
| Invalid Payload | Reject safely with error | Reject safely; 0 crashes | **PASS** | Malformed JSON tested |
| Demo Mode | Full pipeline execution | Executed end-to-end via stubs | **PASS** | External tool independent[cite: 2] |
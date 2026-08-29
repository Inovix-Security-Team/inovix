# Inovix Executable Test Results Summary

All tests executed live against the backend service and Security Engine using PyTest.

| Test ID | Scenario | Expected Result | Executed Result | Status |
| :--- | :--- | :--- | :--- | :--- |
| TEST-001 | Normal Activity | Ingested; 0 false incidents | HTTP 200 OK; Low Risk (<30) | **PASS** |
| TEST-002 | Invalid Payload | HTTP 422 Error response | HTTP 422 Unprocessable Entity | **PASS** |
| TEST-005 | Brute-Force Attack | High Risk incident generated | Detection triggered; Risk >= 80 | **PASS** |
| TEST-006 | Port Scan Event | Port scan rule matched | Detection triggered; Risk >= 60 | **PASS** |
| TEST-007 | Malformed Event | Rejection without crash | Event REJECTED safely | **PASS** |
| TC-DEMO-01| Demo Fallback | Live engine fallback execution | Complete pipeline verified | **PASS** |
# TASK-004 Test Plan — Security Engine & Backend Integration Assurance

## Architecture & Scope
* **Backend API Suite (`tests/api/`)**: Validates endpoint health, input contract rejection, and response JSON formats.
* **Security Engine Suite (`tests/security/`)**: Validates validation, normalization, multi-indicator detection rules, boundary risk scoring, and false-positive handling.
* **Integration Suite (`tests/integration/`)**: Validates end-to-end data flow from HTTP request down to structured risk verdict.

## Known Boundaries & Limitations
* **Live IPC Channel**: Tested where implemented in backend service layer. Direct engine integration boundary is documented via integration contracts.
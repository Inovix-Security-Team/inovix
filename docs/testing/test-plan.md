# Inovix QA Test Plan & Architecture Validation

## Scope & Objective
Establish a non-destructive testing methodology for Inovix[cite: 2]. Tests focus on synthetic event processing through the security engine, risk engine, response engine, and SOC dashboard[cite: 1, 2].

## Architectural Lifecycle Flow
1. **Input Event**: Ingestion via synthetic logs[cite: 1, 2].
2. **Normalization**: Conversion to common event format[cite: 1, 2].
3. **Detection**: Rule/ML deterministic evaluation[cite: 1, 2].
4. **Risk Calculation**: Unified risk band mapping (0–29 Low, 30–59 Medium, 60–79 High, 80–100 Critical)[cite: 2].
5. **Impact Analysis**: Affected asset and service identification[cite: 1, 2].
6. **Incident Engine**: Incident record creation[cite: 1, 2].
7. **Response Engine**: Authorized containment execution[cite: 1, 2].
8. **Verification**: Confirmation of containment[cite: 1, 2].
9. **Dashboard**: Update UI display[cite: 1, 2].

## Limitations
- Synthetic events and mock stubs are used when external tools (e.g., Wazuh, Suricata, Zeek) are absent[cite: 2].
- Unauthorized or real destructive payloads are strictly prohibited[cite: 2].
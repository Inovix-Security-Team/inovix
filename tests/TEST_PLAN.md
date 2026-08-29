# Inovix QA Foundation & Master Test Plan

## Overview
This document defines the foundational testing structure, test matrix, and guidelines for validating the Inovix Security Framework across all pipeline stages[cite: 1, 2].

## Test Matrix

| Test ID | Component | Test Scenario | Expected Outcome | Actual Executed Status |
| :--- | :--- | :--- | :--- | :--- |
| TEST-001 | Backend | Health API Endpoint | HTTP 200 OK | PASS (Executable) |
| TEST-002 | Backend | Invalid Request Handling | HTTP 422 Unprocessable Entity | PASS (Executable) |
| TEST-003 | Security | Empty Input Event | Validation Error / Reject | PASS (Executable) |
| TEST-004 | Security | Safe / Normal Sample | SAFE / Low Risk (<30) | PASS (Executable) |
| TEST-005 | Security | Brute Force Payload | SUSPICIOUS / High Risk (>=80) | PASS (Executable) |
| TEST-006 | Security | Port Scan Payload | SUSPICIOUS / Risk (>=60) | PASS (Executable) |
| TEST-007 | Security | Malformed Event Sample | REJECTED / Error | PASS (Executable) |
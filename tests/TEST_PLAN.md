# Inovix QA Foundation & Master Test Plan

## Overview
This document defines the foundational testing structure, test matrix, and guidelines for validating the Inovix Security Framework across all pipeline stages.

## Initial Test Matrix

| Test ID | Component | Test Scenario | Expected Outcome | Status |
| :--- | :--- | :--- | :--- | :--- |
| TEST-001 | Backend | Health API Endpoint | HTTP 200 OK | PASS (Mock) |
| TEST-002 | Backend | Invalid Request Handling | HTTP 400 Validation Error | PASS (Mock) |
| TEST-003 | Security | Empty Input Event | Validation Error / Reject | PASS (Mock) |
| TEST-004 | Security | Safe / Normal Sample | SAFE / Low Risk (<30) | PASS (Mock) |
| TEST-005 | Security | Suspicious Payload | SUSPICIOUS / High Risk (>=60) | PASS (Mock) |
| TEST-006 | Frontend | Dashboard Load State | Render status ACTIVE | Pending |
# Inovix Local Database Design Document (SQLite)

## Overview
This document outlines the SQLite architecture for Inovix local persistent storage. The goal is to provide reliable, zero-network persistent memory for security events, engine findings, and risk assessments.

## Why SQLite?
* **Offline-First:** Runs entirely locally without network calls or external daemon processes.
* **Zero Configuration:** Native to Python via `sqlite3`, enabling portable, pip-installable distributions.
* **Lightweight & High Performance:** Ideal for real-time edge/terminal log storage with minimal system overhead.

## Entity Relationship Architecture

+-------------------------------------------------------------+
|                           EVENTS                            |
+-------------------------------------------------------------+
| id (TEXT/UUID) PRIMARY KEY                                  |
| timestamp (TEXT)                                            |
| event_type (TEXT)                                           |
| source (TEXT)                                               |
| content_hash (TEXT)                                         |
| metadata (TEXT/JSON)                                        |
| created_at (TEXT)                                           |
+-------------------------------------------------------------+
|                                 |
| 1:N                             | 1:1
v                                 v
+---------------------------+   +-----------------------------+
|         FINDINGS          |   |      RISK_ASSESSMENTS       |
+---------------------------+   +-----------------------------+
| id (INTEGER) PRIMARY KEY  |   | id (INTEGER) PRIMARY KEY    |
| event_id (TEXT) FK        |   | event_id (TEXT) FK UNIQUE   |
| rule_id (TEXT)            |   | score (INTEGER)             |
| severity (TEXT)           |   | risk_level (TEXT)           |
| reason (TEXT)             |   | verdict (TEXT)              |
| indicator (TEXT)          |   | created_at (TEXT)           |
| created_at (TEXT)         |   +-----------------------------+
+---------------------------+
## Security & Integrity Constraints
* **Foreign Keys:** Enforced at runtime on every connection via `PRAGMA foreign_keys = ON;`.
* **Parameterized Queries:** All queries execute via bound parameters (`?`) to prevent SQL injection vulnerabilities.


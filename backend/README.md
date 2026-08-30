
# 🚀 Inovix Backend

> **Backend Foundation & API Skeleton for Inovix**

The Inovix backend provides a clean, versioned API layer between the frontend and the security analysis engine.

### 🔄 Current Architecture

```text
┌──────────────┐
│   Frontend   │
└──────┬───────┘
       │
       ▼
┌──────────────────┐
│   Backend API    │
│    FastAPI       │
└──────┬───────────┘
       │
       ▼
┌──────────────────┐
│ Analysis Service │
└──────┬───────────┘
       │
       ▼
┌──────────────────┐
│   Mock Analysis  │
└──────────────────┘
```

> 🔮 **Future:** The Mock Analysis service will be replaced by the actual Inovix Security Engine without changing the frontend API contract.

---

## 📌 Task Information

| Field           | Details                           |
| --------------- | --------------------------------- |
| **Task ID**     | `BASIT-TASK-001`                  |
| **Task**        | Backend Foundation & API Skeleton |
| **Developer**   | Abdul Basit                             |
| **Framework**   | FastAPI                           |
| **API Version** | `v1`                              |
| **Branch**      | `fix/basit-task-001-review`      |
| **Status**      | ✅ Completed                   |

---

## ✨ Current Features

* ⚡ FastAPI backend foundation
* 🔢 Versioned API structure (`/api/v1`)
* ❤️ Health-check endpoint
* 🔍 Analysis endpoint with mock response
* 📦 Pydantic request/response schemas
* 🧩 Service-layer architecture
* ⚙️ Environment-based configuration
* 🚨 Structured validation error handling
* 📖 Automatic Swagger/OpenAPI documentation
* 🔐 `.env` excluded from Git

---

## 📁 Project Structure

```text
backend/
│
├── app/
│   ├── api/
│   │   └── v1/
│   │       ├── router.py
│   │       └── endpoints/
│   │           ├── health.py
│   │           └── analyze.py
│   │
│   ├── core/
│   │   ├── config.py
│   │   └── errors.py
│   │
│   ├── models/
│   │
│   ├── schemas/
│   │   └── analysis.py
│   │
│   ├── services/
│   │   └── analysis_service.py
│   │
│   └── main.py
│
├── tests/
│   └── test_api.py
│
├── .gitignore
├── pytest.ini
├── requirements.txt
└── README.md
```

---

## 🛠️ Tech Stack

| Technology      | Purpose                      |
| --------------- | ---------------------------- |
| 🐍 **Python**   | Backend programming language |
| ⚡ **FastAPI**   | REST API framework           |
| 📦 **Pydantic** | Request/response validation  |
| 🖥️ **Uvicorn** | ASGI server                  |
| 🧪 **Pytest**   | Automated testing            |

---

## ⚙️ Installation & Setup

### 1️⃣ Navigate to Backend

```bash
cd backend
```

### 2️⃣ Create Virtual Environment

```bash
python -m venv venv
```

### 3️⃣ Activate Virtual Environment

**Windows PowerShell:**

```powershell
.\venv\Scripts\Activate.ps1
```

**Linux/macOS:**

```bash
source venv/bin/activate
```

### 4️⃣ Install Dependencies

```bash
pip install -r requirements.txt
```

---

## ▶️ Run the Backend

Start the development server:

```bash
uvicorn app.main:app --reload
```

The backend will run at:

```text
http://127.0.0.1:8000
```

---

## 📖 API Documentation

FastAPI automatically provides interactive API documentation.

### Swagger UI

```text
http://127.0.0.1:8000/docs
```

### ReDoc

```text
http://127.0.0.1:8000/redoc
```

### OpenAPI Schema

```text
http://127.0.0.1:8000/openapi.json
```

---

# 🔌 API Endpoints

## ❤️ Health Check

### Request

```http
GET /api/v1/health
```

### Response

```json
{
  "status": "ok"
}
```

### Purpose

Used to verify that the backend service is running correctly.

---

## 🔍 Analyze

### Request

```http
POST /api/v1/analyze
Content-Type: application/json
```

### Request Body

```json
{
  "target": "example.com"
}
```

### Current Mock Response

```json
{
  "status": "completed",
  "target": "example.com",
  "risk_level": "low",
  "score": 10,
  "message": "Mock analysis completed successfully."
}
```

### Purpose

Provides the initial API contract for security analysis.

Currently, the endpoint uses **mock analysis data**.

In the future:

```text
POST /api/v1/analyze
        ↓
Analysis Service
        ↓
Security Engine
        ↓
Real Analysis Result
```

---

## 🚨 Error Handling

Invalid requests are handled using a structured validation response.

Example:

```json
{
  "error": "validation_error",
  "message": "The request data is invalid.",
  "details": []
}
```

The API uses appropriate HTTP status codes for validation errors.

---

## 🧪 Testing

> ⚠️ Automated tests are part of the remaining task work.

Once tests are added, run:

```bash
pytest or pytest -v
```

Required test coverage:

* ❤️ Health endpoint
* 🔍 Valid analysis request
* ❌ Invalid analysis request
* 🚨 Validation error response
* 📦 Response structure

---

## 🔐 Environment & Security

Configuration is handled through environment variables.

Create a `.env` file when environment-specific configuration is required.

Example:

```env
ENVIRONMENT=development
DEBUG=true
```

### ⚠️ Important

Never commit:

```text
.env
venv/
```

Sensitive credentials and API keys must **never be hardcoded** in the source code.

---

## 🚧 Current Scope

### ✅ Implemented

* Backend application foundation
* API v1 versioning
* Health endpoint
* Analysis endpoint
* Request/response schemas
* Analysis service
* Configuration
* Validation error handling
* Swagger/OpenAPI documentation

### ⏳ Remaining

* 🧪 Automated API tests
* 📑 API contract documentation
* 📖 Complete setup documentation
* 🧹 Final Git structure cleanup
* 🔀 Pull Request

---

## 🚫 Out of Scope for This Task

The following are intentionally **not implemented** in `BASIT-TASK-001`:

* ❌ Complete database implementation
* ❌ Authentication/authorization
* ❌ Complete Security Engine
* ❌ External API integrations
* ❌ Complex microservice architecture

These will be handled in future tasks when required.

---

## 🔮 Future Backend Flow

```text
                     ┌──────────────┐
                     │   Frontend   │
                     └──────┬───────┘
                            │
                            ▼
                  ┌──────────────────┐
                  │   FastAPI /v1    │
                  └────────┬─────────┘
                           │
                           ▼
                  ┌──────────────────┐
                  │ Analysis Service │
                  └────────┬─────────┘
                           │
                           ▼
                  ┌──────────────────┐
                  │ Security Engine  │
                  └────────┬─────────┘
                           │
                           ▼
                  ┌──────────────────┐
                  │ Analysis Result  │
                  └──────────────────┘
```

The API layer is intentionally separated from the Security Engine so that future engine implementations can be integrated without completely rewriting the backend API.

---

## 🌿 Git Workflow

Create the feature branch:

```bash
git checkout -b feature/backend-foundation
```

Check changes:

```bash
git status
```

Stage changes:

```bash
git add .
```

Commit:

```bash
git commit -m "feat: initialize backend API"
```

Push:

```bash
git push -u origin feature/backend-foundation
```

After final testing:

```text
Feature Branch
      ↓
Push
      ↓
Pull Request
      ↓
Code Review
      ↓
Merge
```

---

## 👥 Team Integration

### Frontend — Ali

Ali can use the API contract without waiting for the Security Engine.

Current endpoints:

```text
GET  /api/v1/health
POST /api/v1/analyze
```

### Security Engine — Rehan

The analysis service is designed so that the mock implementation can later be replaced with the actual Security Engine.

```text
Current:

API → Analysis Service → Mock Analysis

Future:

API → Analysis Service → Security Engine
```

---

## 📊 Task Status

| Component           | Status |
| ------------------- | ------ |
| Backend Foundation  | ✅      |
| API Versioning      | ✅      |
| Health API          | ✅      |
| Analyze API         | ✅      |
| Schemas             | ✅      |
| Service Layer       | ✅      |
| Configuration       | ✅      |
| Error Handling      | ✅      |
| Automated Tests     | ✅      |
| API Contract        | ✅      |
| Final Documentation | ✅      |
| Pull Request        | ✅      |

### 🏁 Current Status

**BASIT-TASK-001 — ✅ Completed**

The core backend foundation and API skeleton are implemented. Final testing, documentation and Pull Request preparation remain.

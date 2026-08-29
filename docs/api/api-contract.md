**Overview**
This document describes the current API foundation for Inovix.
The backend currently provides an initial versioned API structure. The API contract may evolve as the Security Engine and other components are integrated.
*Only implemented endpoints and confirmed request/response structures are documented as implemented. Future integration details remain TBD.

**API Version**

The current API version is:
v1
The API base path is:
/api/v1



**Health Check**
*Endpoint*
GET /api/v1/health

*Purpose*
This endpoint verifies that the backend service is running and responding.

*Request*
No request body is required.

*Current Response*
{
  "status": "ok"
}

Status: Implemented



**Security Analysis**
*Endpoint*
POST /api/v1/analyze

*Purpose*
This endpoint receives a target for security analysis.

The current backend implementation uses a mock analysis service. Integration with the Security Engine is planned for future development.

*Current Request Body*
{
  "target": "example.com"
}
The target field must be a non-empty string.

*Current Response*
{
  "status": "completed",
  "target": "example.com",
  "risk_level": "low",
  "score": 10,
  "message": "Mock analysis completed successfully."
}

*The current response fields include:*
status
target
risk_level
score
message

*The risk_level may currently support:*
low
medium
high
critical
unknown

The score is currently defined between 0 and 100.
Status: Implemented Foundation
The current analysis result is generated using mock analysis data.



**Validation Errors**
Invalid requests are handled using the backend's validation error handling structure.
The exact error details may depend on the invalid request.

*Example conceptual structure:*
{
  "error": "validation_error",
  "message": "The request data is invalid.",
  "details": []
}
Status: Implemented
The exact response structure may be refined as the backend evolves.



**Future Security Engine Integration**
The current analysis flow is:

POST /api/v1/analyze
        ↓
Analysis Service
        ↓
Mock Analysis
        ↓
API Response

The planned direction is:

POST /api/v1/analyze
        ↓
Analysis Service
        ↓
Security Engine
        ↓
Detection + Analysis
        ↓
Security Result
        ↓
API Response

*The final integration contract between the backend and Security Engine is currently TBD.*



**API Contract Status**
*Implemented*
API versioning through /api/v1.
GET /api/v1/health.
POST /api/v1/analyze.
Basic request validation.
Response schema for the current analysis endpoint.
Validation error handling.


*Planned*
Integration with the Security Engine.
Real analysis results.
Expanded API capabilities where required.


*TBD*
Final backend-to-Security Engine integration contract.
Final request and response schema after full integration.
Additional API endpoints.
Authentication and authorization requirements.
API deployment configuration.

**This document should be updated whenever the implemented API contract changes**
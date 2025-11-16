
# Security Assessment Report  
## Lendesk Security Challenge – Application Security Review

**Assessment Date:** November 17, 2025  
**Assessor:** Sai Teja Bandi  
**Application:** Notes Management API (Node.js / TypeScript)

---

## Executive Summary

This assessment focused on reviewing the authentication flows, note‑handling endpoints, and the overall security posture of the application. The codebase is small and straightforward, which made it easier to identify several issues that significantly weaken the application’s security model.

The most impactful issues relate to **JWT handling**, **authorization gaps**, and **overly permissive configuration defaults**. These weaknesses allow an attacker to access or manipulate other users’ data with minimal effort. Additional findings relate to input validation, error handling, and operational hardening.

Overall, the application requires several foundational fixes before it can be considered production‑ready.

---

## Key Findings Overview

| Severity | Finding |
|---------|---------|
| Critical | JWT signature not verified |
| Critical | Hardcoded and weak JWT secret |
| Critical | Missing authorization checks on user-specific resources |
| High | Error messages disclose internal details |
| High | CORS is wide open |
| Medium | Weak password policy & no rate limiting |
| Medium | Missing validation on note content |
| Low | Missing common security headers |
| Low | File-based user storage lacks basic controls |

Below is a concise breakdown of the most important issues.

---

## Detailed Findings 

### 1. JWT Validation Not Performed (Critical)

The authentication middleware decodes tokens without verifying signatures. This allows anyone to craft a token for any user and gain access.

**Impact:**  
An attacker can bypass authentication entirely and impersonate any user.

**Recommendation:**  
Use `jwt.verify()` with a strong secret and enforce expiration.

---

### 2. Hardcoded Weak JWT Secret (Critical)

The application signs tokens using the literal string `"JWT"`. This can be guessed instantly and combined with the validation issue above gives full access.

**Recommendation:**  
Store a strong secret (32+ chars) in environment variables. Avoid committing secrets to the repository.

---

### 3. No Authorization on User-Specific Endpoints (Critical)

The routes that handle notes do not confirm whether the authenticated user matches the username in the request path.

**Impact:**  
Any logged‑in user can read or write notes for any other user.

**Recommendation:**  
Add a simple authorization check comparing the token’s username with the request parameters.

---

### 4. Detailed Errors Returned to Clients (High)

The error handler returns stack traces and internal error messages. These reveal implementation details and file paths.

**Recommendation:**  
Log server-side, return generic messages client-side.

---

### 5. CORS Allows All Origins (High)

The API is exposed to any website due to a fully permissive CORS configuration. This creates CSRF and data‑exposure risks.

**Recommendation:**  
Whitelist the specific origin(s) that need API access.

---

### 6. Weak Password Requirements & No Rate Limiting (Medium)

Passwords can be as short as four characters and authentication endpoints can be brute forced without restriction.

**Recommendation:**  
Increase minimum length, add complexity checks, and apply rate limiting on authentication routes.

---

### 7. Missing Input Validation on Notes (Medium)

Notes can be arbitrarily large or empty. There are no limits or basic checks.

**Recommendation:**  
Set size limits and validate basic formatting before storing content.

---

### 8. Missing Security Headers (Low)

Standard headers (HSTS, X‑Frame‑Options, X‑Content‑Type‑Options, CSP) are not configured.

**Recommendation:**  
Use Helmet middleware for baseline hardening.

---

### 9. Local File-Based User Storage Is Insecure (Low)

User data stored in `users.json` lacks permission controls and is not suited for production environments.

**Recommendation:**  
Restrict filesystem permissions or move to a proper secure datastore.

---

## Conclusion

The application contains several high‑impact security issues, primarily around authentication and access control. Correcting the JWT handling, enforcing authorization, tightening CORS, and hardening the API with basic security controls will significantly improve the application’s security posture.

Once these foundational issues are addressed, additional improvements such as stronger password policies, rate limiting, and secure configuration will help prepare the application for more realistic production environments.

---

**Prepared by:**  
Sai Teja Bandi  
Application Security Assessment

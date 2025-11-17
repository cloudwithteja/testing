
# Lendesk Security Challenge – Web Application Security Assessment

**Assessment Date:** November 17, 2025  
**Assessor:** Sai Teja Bandi  
**Application Tested:** Node.js / TypeScript Notes Management API  
**Version:** 1.0.0

---

# Executive Summary

This assessment takes a close look at a simple Notes API built with Node.js and TypeScript. Although the application functions correctly, it contains several major security weaknesses — including multiple critical issues — that compromise authentication and give attackers full control over user data.

I reviewed the code, followed the logic behind authentication and note storage, and tested the API’s behavior when interacting with login, user creation, and note retrieval flows.
<img width="500" height="135" alt="image" src="https://github.com/user-attachments/assets/a2aad997-8f24-4a70-ba07-7d473da3cad6" />

**Overall Results:**
- **3 Critical issues**  
- **2 High issues**  
- **3 Medium issues**  
- **2 Low issues**

The most serious problem is that the application **does not actually validate JWT tokens**, allowing anyone to impersonate any user.

---

# 1. Testing Methodology

## 1.1 How I Tested

To understand the security posture of the application, I used:

- Manual code review
- Snyk
- Dependency-check
- Semgrep 
- Static analysis patterns  
- Dependency and config file review  
- Authentication/authorization testing  
- Error handling verification  
- CORS and middleware behavior review  

I looked specifically at:

- Authentication flows  
- Token creation  
- Token validation  
- Notes access  
- Error output  
- Password hashing logic  
- Redis and filesystem interaction  

## 1.2 In-Scope Components

- `/authentication/create-user`
- `/authentication/login`
- `/users/:username/notes` (GET, POST)
- JWT logic
- Redis storage
- File-based JSON user storage
- Password hashing
- Error handling
- CORS configuration

---

# 2. Detailed Findings

Below are the findings, grouped by severity.

---

## 🔴 CRITICAL-01: JWT Tokens Aren’t Actually Validated

The application uses `jwt.decode()` instead of `jwt.verify()`, meaning the server *never checks* whether the JWT was signed correctly.

**Impact:**  
Attackers can forge their own tokens and impersonate any user.

**Fix:**  
Replace `decode()` with `verify()` and require a strong, secret key.

---

## 🔴 CRITICAL-02: Weak, Hardcoded JWT Secret

The app signs tokens using `"JWT"` as the secret.  
This is extremely weak and hardcoded directly in the code.

**Implication:**  
Anyone with access to the codebase can forge valid tokens.

**Fix:**  
Use a strong secret stored in environment variables.

---

## 🔴 CRITICAL-03: Missing Authorization Checks on Notes

Even if JWT validation worked, the app would still allow users to fetch and edit *other users’ notes* because it never checks:

```ts
req.user.username === req.params.username
```

**Fix:**  
Enforce authorization logic before allowing note access.

---

## 🟠 HIGH-01: Sensitive Error Details Are Exposed

When something goes wrong, the API returns:

- Stack traces  
- Internal paths  
- Detailed error messages  

**Impact:**  
These leak internal logic and file structure.

**Fix:**  
Return generic messages on the client side.

---

## 🟠 HIGH-02: CORS Is Wide Open

CORS is configured with default settings, allowing *any domain* to send requests.

**Impact:**  
Malicious websites can perform authenticated actions on behalf of a user.

**Fix:**  
Restrict CORS to trusted domains.

---

## 🟡 MEDIUM-01: No Input Validation for Notes

Notes can contain anything, including empty values or massive payloads.

**Fix:**  
Validate content size and format.

---

## 🟡 MEDIUM-02: Weak Password Rules

Minimum password length is only 4 characters.

**Fix:**  
Increase to 12+ characters with stronger complexity.

---

## 🟡 MEDIUM-03: No Rate Limiting

The API lets attackers:

- Brute-force user accounts  
- Hammer endpoints  
- Enumerate usernames  

**Fix:**  
Add `express-rate-limit` to sensitive endpoints.

---

## 🔵 LOW-01: Missing Security Headers

Security headers like CSP, HSTS, and X-Frame-Options are missing.

**Fix:**  
Use `helmet()` to add them.

---

## 🔵 LOW-02: Insecure File Storage

User data stored in `users.json` lacks proper file-level protections.

**Fix:**  
Restrict file permissions and consider removing file storage entirely.

---

# 3. Summary of Results

## 3.1 Critical Risk Level

The most severe issues directly affect authentication and authorization:

- JWT validation is broken  
- Secret key is weak  
- Any user can read or modify any other user’s notes  

This makes the entire app vulnerable to complete compromise.

## 3.2 Priority Fixes

1. Implement proper JWT verification  
2. Move JWT secret to environment variables  
3. Add authorization checks  
4. Implement secure error handling  
5. Restrict CORS  
6. Add rate limiting  
7. Strengthen password policies  
8. Add security headers  

---

# 4. Conclusion

The assessment revealed major weaknesses in authentication, authorization, and input handling. Most issues stem from incorrect JWT usage and missing authorization logic.

The good news: these issues are straightforward to fix. Addressing the critical items first will significantly improve the application’s security posture and make it safe for production use.

---

**Prepared by:**  
**Sai Teja Bandi**  
**Date:** November 17, 2025  
**Classification:** Confidential


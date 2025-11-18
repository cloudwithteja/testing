
# Lendesk Security Challenge – Web Application Security Assessment

**Assessment Date:** November 18, 2025  
**Assessor:** Sai Teja Bandi  
**Application Tested:** Node.js / TypeScript Notes Management API  
**Version:** 1.0.0

---

# Executive Summary

This assessment takes a close look at a simple Notes API built with Node.js and TypeScript. Although the application functions correctly, it contains several major security weaknesses — including multiple critical issues — that compromise authentication and give attackers full control over user data.

I reviewed the code, followed the logic behind authentication and note storage, and tested the API’s behavior when interacting with login, user creation, and note retrieval flows.

<img width="500" height="135" alt="image" src="https://github.com/user-attachments/assets/6092a316-849b-4393-9f6f-e7384f98f996" />

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

- Manual code review and curl
 <img width="500" height="135" alt="image" src="https://github.com/user-attachments/assets/3c257cb3-0d5f-438f-bb1f-f495206a6c7c" />

 <img width="500" height="135" alt="image" src="https://github.com/user-attachments/assets/5bdd347c-e98e-48d1-aa0c-bc9567b2c02e" />


- Snyk
  
 <img width="500" height="135" alt="image" src="https://github.com/user-attachments/assets/52bb5255-bef9-4038-888d-1523d3387ba7" />

- Dependency-check 
  
  <img width="500" height="135" alt="image" src="https://github.com/user-attachments/assets/3d86da2a-9d94-41ab-bea4-ac2d742d3af9" />

- Semgrep

 <img width="500" height="135" alt="image" src="https://github.com/user-attachments/assets/d882eb5f-6f71-4d25-a3a4-f1a9d75f4f41" />

- Static analysis patterns
- npm audit

  <img width="500" height="135" alt="image" src="https://github.com/user-attachments/assets/92b050e9-920f-4c1d-b48f-4ba6edbc7639" />
  
- Authentication/authorization testing
- ZAP Scan
  
  <img width="500" height="135" alt="image" src="https://github.com/user-attachments/assets/0695ded7-0c22-4c7a-a292-adb95faf0c10" />

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

### CRITICAL-01: JWT Token Validation Bypass

**Risk Level:** CRITICAL

**Description:**\
The JWT authentication middleware uses `jwt.decode()` instead of
`jwt.verify()` to validate tokens. The `decode()` function simply
decodes the JWT payload without verifying the signature, allowing
attackers to forge arbitrary tokens.

**Location:** `src/routes/notes.ts`, lines 15-18

``` typescript
const authenticateJWT: express.RequestHandler = (req, res, next) => {
  // ... authorization header extraction ...
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.decode(token);  // ❌ NO SIGNATURE VERIFICATION
    (req as any).user = decoded;
    next();
  } catch (err) {
    res.status(403).json({ message: 'Invalid or expired token' });
  }
};
```

**Impact:**\
An attacker can create a valid-looking JWT token with any username
without knowing the secret key. This completely bypasses authentication
and allows: - Accessing any user's notes without authentication -
Creating notes on behalf of any user - Complete authentication bypass
for all protected endpoints

**Proof of Concept:**

``` bash
# Attacker can create a forged token for any user
# Example: Create token for user "alice" without password
TOKEN=$(echo -n '{"alg":"none"}' | base64).$(echo -n '{"username":"alice"}' | base64).

# Access alice's notes without authentication
curl -H "Authorization: Bearer $TOKEN" http://localhost:5000/users/alice/notes
```

**Remediation:** 1. Replace `jwt.decode()` with `jwt.verify()` and use a
strong secret key 2. Store the JWT secret in environment variables, not
hardcoded 3. Implement token expiration 4. Add token refresh mechanism

**Recommended Code Fix:**

``` typescript
const authenticateJWT: express.RequestHandler = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).json({ message: 'Missing or invalid Authorization header' });
    return;
  }

  const token = authHeader.split(' ')[1];
  try {
    const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-from-env';
    const decoded = jwt.verify(token, JWT_SECRET) as { username: string };
    (req as any).user = decoded;
    next();
  } catch (err) {
    res.status(403).json({ message: 'Invalid or expired token' });
  }
};
```

------------------------------------------------------------------------

### CRITICAL-02: Hardcoded JWT Secret Key

**Risk Level:** CRITICAL

**Description:**\
The JWT signing secret is hardcoded as the string `'JWT'` in the
authentication route, making it trivial for attackers to forge valid
tokens once they discover this weak secret.

**Location:** `src/routes/authentication.ts`, line 36

``` typescript
const token = jwt.sign({ username: req.body.username }, 'JWT');  // ❌ HARDCODED SECRET
```

**Impact:** - Predictable and weak secret key - Any attacker who reviews
the code or decompiles the application can create valid tokens -
Combined with the jwt.decode() vulnerability, this makes authentication
completely ineffective - All user accounts are compromised

**Evidence:** The secret `'JWT'` is only 3 characters, far below the
recommended minimum of 256 bits (32 characters) for HS256 algorithm.

**Remediation:** 1. Generate a strong, random secret key (minimum 256
bits) 2. Store the secret in environment variables 3. Never commit
secrets to version control 4. Implement key rotation mechanism 5. Use
different secrets for different environments

**Recommended Implementation:**

``` typescript
// In .env.template
JWT_SECRET=<generate-strong-random-secret-here>
JWT_EXPIRATION=1h

// In src/config.ts
export const config = {
  servicePort: importEnv.SERVICE_PORT,
  redisUrl: importEnv.REDIS_URL,
  jwtSecret: importEnv.JWT_SECRET,
  jwtExpiration: importEnv.JWT_EXPIRATION || '1h',
};

// In src/routes/authentication.ts
const token = jwt.sign(
  { username: req.body.username },
  config.jwtSecret,
  { expiresIn: config.jwtExpiration }
);
```

------------------------------------------------------------------------

### CRITICAL-03: Broken Access Control - No Authorization Check

**Risk Level:** CRITICAL

**Description:**\
The notes endpoints authenticate users but don't verify that the
authenticated user matches the username in the URL path. Any
authenticated user can access or modify any other user's notes.

**Location:** `src/routes/notes.ts`, lines 32-50

``` typescript
router.post('/:username/notes', authenticateJWT, function (req: express.Request, res: express.Response) {
  getNotesController().then((controller: NotesController) => {
    controller
      .createUserNotes(req.params.username, req.body.notes)  // ❌ NO AUTHORIZATION CHECK
      // ...
  });
});

router.get('/:username/notes', authenticateJWT, function (req: express.Request, res: express.Response) {
  getNotesController().then((controller: NotesController) => {
    controller
      .getUserNotes(req.params.username)  // ❌ NO AUTHORIZATION CHECK
      // ...
  });
});
```

**Impact:** - Horizontal privilege escalation - User A can read User B's
notes - User A can create/modify notes for User B - Complete violation
of data confidentiality and integrity - Violation of OWASP Top 10 -
Broken Access Control (A01:2021)

**Proof of Concept:**

``` bash
# User "alice" logs in
TOKEN_ALICE=$(curl -s -X POST http://localhost:5000/authentication/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"alicepass"}' | jq -r '.token')

# Alice can access Bob's notes using her own token
curl -H "Authorization: Bearer $TOKEN_ALICE" \
  http://localhost:5000/users/bob/notes

# Alice can create notes for Bob
curl -X POST -H "Authorization: Bearer $TOKEN_ALICE" \
  -H "Content-Type: application/json" \
  -d '{"notes":"Malicious note from Alice"}' \
  http://localhost:5000/users/bob/notes
```

**Remediation:** Implement proper authorization by verifying the
authenticated user matches the requested resource owner:

``` typescript
router.post('/:username/notes', authenticateJWT, function (req: express.Request, res: express.Response) {
  const authenticatedUser = (req as any).user.username;
  const requestedUsername = req.params.username;
  
  if (authenticatedUser !== requestedUsername) {
    res.status(403).json({ message: 'Forbidden: Cannot access other users\' notes' });
    return;
  }
  
  getNotesController().then((controller: NotesController) => {
    controller.createUserNotes(requestedUsername, req.body.notes)
      .then((notes) => res.json(notes).end())
      .catch(handleUnknownError(res));
  });
});
```

------------------------------------------------------------------------

### HIGH-01: Sensitive Information Disclosure in Error Responses

**Risk Level:** HIGH

**Description:**\
The error handler exposes full error messages and stack traces to
clients, revealing sensitive information about the application's
internal structure, file paths, and implementation details.

**Location:** `src/utils/error.ts`, lines 4-14

``` typescript
export const handleUnknownError = (res: express.Response) => {
  return (e: Error) => {
    res
      .status(500)
      .json({
        errors: [{
          code: 500,
          message: 'Unknown error',
          details: e.message,      // ❌ EXPOSES ERROR DETAILS
          stack: e.stack           // ❌ EXPOSES STACK TRACE
        }]
      })
      .end();
  };
};
```

**Impact:** - Information disclosure about application internals - Stack
traces reveal file paths, library versions, and code structure - Assists
attackers in reconnaissance - May expose database connection strings,
internal IPs, or other sensitive data - Violation of OWASP Top 10 -
Security Misconfiguration (A05:2021)

**Evidence:** Stack traces in production environments can reveal: -
Server-side file paths (`/app/src/controllers/...`) - Framework and
library versions - Internal function names and logic flow - Database
errors with query details

**Remediation:** 1. Differentiate between development and production
error handling 2. Log full errors server-side only 3. Return generic
error messages to clients 4. Implement proper error monitoring/logging

**Recommended Implementation:**

``` typescript
export const handleUnknownError = (res: express.Response) => {
  return (e: Error) => {
    // Log full error server-side
    console.error('Error occurred:', {
      message: e.message,
      stack: e.stack,
      timestamp: new Date().toISOString()
    });
    
    // Return generic error to client
    const isDevelopment = process.env.NODE_ENV === 'development';
    res.status(500).json({
      errors: [{
        code: 500,
        message: 'An internal error occurred',
        ...(isDevelopment && { details: e.message, stack: e.stack })
      }]
    }).end();
  };
};
```

------------------------------------------------------------------------

### HIGH-02: Unrestricted CORS Configuration

**Risk Level:** HIGH

**Description:**\
The application uses `cors()` without any configuration, allowing
requests from any origin. This permits malicious websites to make
authenticated requests to the API on behalf of users.

**Location:** `src/app.ts`, line 9

``` typescript
app.use(cors());  // ❌ ALLOWS ALL ORIGINS
```

**Impact:** - Cross-Site Request Forgery (CSRF) attacks - Malicious
websites can access user data if users are logged in - API can be called
from any domain - Tokens can be stolen via XSS attacks on any domain -
Data exfiltration from authenticated sessions

**Attack Scenario:** A user visits a malicious website while logged into
the notes application. The malicious site can: 1. Extract the JWT token
from localStorage/cookies 2. Make authenticated API calls to read/write
notes 3. Exfiltrate sensitive data

**Remediation:** Configure CORS to only allow trusted origins:

``` typescript
import cors from 'cors';

const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'];

app.use(cors({
  origin: function(origin, callback) {
    // Allow requests with no origin (mobile apps, curl, etc.)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.indexOf(origin) === -1) {
      const msg = 'The CORS policy for this site does not allow access from the specified Origin.';
      return callback(new Error(msg), false);
    }
    return callback(null, true);
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
```

------------------------------------------------------------------------

### MEDIUM-01: Missing Input Validation on Notes Endpoint

**Risk Level:** MEDIUM

**Description:**\
The notes creation endpoint doesn't validate the `notes` input, allowing
users to submit empty notes, excessively long notes, or potentially
malicious content.

**Location:** `src/controllers/notes.ts`, lines 7-10

``` typescript
async createUserNotes(username: string, notes: string): Promise<Notes> {
  const existingNotes = await this.notesData.findByUsername(username);
  return this.notesData.create(username, notes);  // ❌ NO VALIDATION
}
```

**Impact:** - Database/Redis storage exhaustion with large payloads -
Potential for NoSQL injection depending on storage backend - Acceptance
of malicious or malformed data - No content-length restrictions

**Evidence:** No validation exists for: - Note length (could be
megabytes) - Note content (could contain injection payloads) - Note
format or encoding

**Remediation:** Implement input validation:

``` typescript
const MAX_NOTE_LENGTH = 10000; // 10KB

async createUserNotes(username: string, notes: string): Promise<Notes> {
  // Validate input
  if (!notes || typeof notes !== 'string') {
    throw new Error('Notes must be a non-empty string');
  }
  
  if (notes.trim().length === 0) {
    throw new Error('Notes cannot be empty');
  }
  
  if (notes.length > MAX_NOTE_LENGTH) {
    throw new Error(`Notes exceed maximum length of ${MAX_NOTE_LENGTH} characters`);
  }
  
  // Sanitize input if needed
  const sanitizedNotes = notes.trim();
  
  return this.notesData.create(username, sanitizedNotes);
}
```

------------------------------------------------------------------------

### MEDIUM-02: Weak Password Requirements

**Risk Level:** MEDIUM

**Description:**\
The password validation allows passwords as short as 4 characters, which
is insufficient for modern security standards and vulnerable to
brute-force attacks.

**Location:** `src/authentication/user.ts`, line 12

``` typescript
export const MIN_PASSWORD_LENGTH = 4;  // ❌ TOO WEAK
```

**Impact:** - Accounts vulnerable to brute-force attacks - Dictionary
attacks more likely to succeed - Reduced password entropy - Users may
choose weak passwords like "1234"

**Current Password Policy:** - Minimum length: 4 characters (very
weak) - No complexity requirements - No restriction on common passwords

**Remediation:** Implement stronger password requirements:

``` typescript
export const MIN_PASSWORD_LENGTH = 12;
export const PASSWORD_REGEX = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/;

export function validateAccount(username: string, password: string) {
  const errors = [];
  
  // ... existing username validation ...
  
  if (!password || password.trim().length === 0) {
    errors.push({ code: UserError.PASSWORD_REQUIRED, message: 'Password is required' });
  } else if (password.length < MIN_PASSWORD_LENGTH) {
    errors.push({
      code: UserError.PASSWORD_TOO_SHORT,
      message: `Password must be at least ${MIN_PASSWORD_LENGTH} characters`,
    });
  } else if (!PASSWORD_REGEX.test(password)) {
    errors.push({
      code: UserError.PASSWORD_COMPLEXITY,
      message: 'Password must contain uppercase, lowercase, number, and special character',
    });
  }
  
  return { errors };
}
```

Additionally, consider implementing: - Password strength meter on
client-side - Check against common password lists - Account lockout
after failed attempts - Multi-factor authentication (MFA)

------------------------------------------------------------------------

### MEDIUM-03: Missing Rate Limiting

**Risk Level:** MEDIUM

**Description:**\
The application has no rate limiting on authentication endpoints,
allowing unlimited login attempts and user creation requests. This
enables brute-force attacks and account enumeration.

**Location:** `src/routes/authentication.ts` (entire file)

**Impact:** - Brute-force password attacks - Account enumeration
(determining valid usernames) - Credential stuffing attacks - Service
abuse through mass account creation - Resource exhaustion

**Attack Scenarios:** 1. **Brute Force:** Attacker tries thousands of
password combinations 2. **Account Enumeration:** Attacker can determine
valid usernames by response timing 3. **DoS:** Mass user creation
requests could overwhelm the system

**Remediation:** Implement rate limiting using middleware like
`express-rate-limit`:

``` bash
npm install express-rate-limit
```

``` typescript
import rateLimit from 'express-rate-limit';

// Rate limiter for authentication endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 requests per windowMs
  message: 'Too many authentication attempts, please try again later',
  standardHeaders: true,
  legacyHeaders: false,
});

// Apply to authentication routes
router.post('/create-user', authLimiter, function (req, res) { ... });
router.post('/login', authLimiter, function (req, res) { ... });

// Rate limiter for API endpoints
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
});

app.use('/users', apiLimiter);
```

Additional recommendations: - Implement CAPTCHA after multiple failed
attempts - Add account lockout mechanism - Use exponential backoff for
failed login attempts

------------------------------------------------------------------------

### LOW-01: Missing Security Headers

**Risk Level:** LOW

**Description:**\
The application doesn't set security-related HTTP headers, leaving it
vulnerable to various client-side attacks like clickjacking, XSS, and
MIME-type sniffing.

**Location:** `src/app.ts` (missing configuration)

**Missing Headers:** - `X-Content-Type-Options: nosniff` -
`X-Frame-Options: DENY` - `X-XSS-Protection: 1; mode=block` -
`Strict-Transport-Security` (HSTS) - `Content-Security-Policy`

**Impact:** - Clickjacking attacks - MIME-type sniffing
vulnerabilities - Cross-Site Scripting (XSS) attacks - Man-in-the-Middle
(MITM) attacks

**Remediation:** Use the `helmet` middleware to set security headers:

``` bash
npm install helmet
```

``` typescript
import helmet from 'helmet';

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  },
}));
```

------------------------------------------------------------------------

### LOW-02: Insecure File Storage in Console Application

**Risk Level:** LOW

**Description:**\
The console application uses a file-based storage system
(`FileUserData`) that writes user data including hashed passwords to
`users.json` in the current directory without proper permissions or
encryption.

**Location:** `src/data/file/user.ts` and `src/data/file/json-file.ts`

``` typescript
protected writeData(data: T) {
  fs.writeFileSync(this.filename, JSON.stringify(data));  // ❌ NO ENCRYPTION, DEFAULT PERMISSIONS
}
```

**Impact:** - Password hashes stored in plaintext JSON file - File
permissions may allow other users to read - No encryption at rest - Data
could be exposed if file system is compromised

**Evidence:** The `.gitignore` file includes `users.json`, indicating
this file is created at runtime and should not be committed. However,
there's no validation of file permissions or encryption.

**Remediation:** 1. Set restrictive file permissions (600 - owner
read/write only) 2. Store sensitive data in secure storage (e.g.,
encrypted database) 3. Implement encryption at rest 4. Use Redis for all
environments (not just development)

``` typescript
import fs from 'fs';

protected writeData(data: T) {
  const jsonData = JSON.stringify(data);
  // Write with restrictive permissions
  fs.writeFileSync(this.filename, jsonData, { mode: 0o600 });
}
```

------------------------------------------------------------------------
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

**Prepared by:**  **Sai Teja Bandi**  
**Date:** November 18, 2025  
**Classification:** Confidential


# Test Plan - Secure Notes API

This document outlines the testing strategy for the secure-notes-api project. Tests are organized by functionality and test type (unit, integration, security), and should be implemented in the order listed below.

## Foundation: Cryptography & Utilities

### 1. Unit Tests: `src/__tests__/unit/lib/utils.test.ts`
**Purpose:** Test utility functions in isolation

- `hasProperties()`
  - ✓ Returns true when all properties exist
  - ✓ Returns false when any property is missing
  - ✓ Returns false when property is undefined
  - ✓ Works with single and multiple properties

- `sanitizeObjectForDb()`
  - ✓ Converts Buffer to base64 string
  - ✓ Preserves non-Buffer values
  - ✓ Handles mixed Buffer and non-Buffer objects

**Why first:** No dependencies, fast feedback, validates helper functions used elsewhere.

---

### 2. Unit Tests: `src/__tests__/unit/lib/crypto.test.ts`
**Purpose:** Test cryptographic functions in isolation

- Password hashing (argon2)
  - ✓ Hash generation produces consistent hashes for same input
  - ✓ Hash verification accepts correct password
  - ✓ Hash verification rejects incorrect password
  - ✓ Different passwords produce different hashes

- Master key derivation
  - ✓ Derives key from password + salt
  - ✓ Same password + salt produces same key
  - ✓ Different salt produces different key
  - ✓ Key has correct length (32 bytes)

- AES-GCM encryption/decryption
  - ✓ Encrypts plaintext to ciphertext
  - ✓ Decrypts ciphertext back to plaintext
  - ✓ Decryption fails with wrong password
  - ✓ Decryption fails with tampered ciphertext
  - ✓ Each encryption produces different ciphertext (due to random IV)

**Why second:** Core security functions, other auth logic depends on these.

---

### 3. Unit Tests: `src/__tests__/unit/lib/auth.test.ts`
**Purpose:** Test JWT and token creation/verification in isolation

- Access token creation
  - ✓ Creates valid JWT with userId and masterKey payload
  - ✓ Token includes correct expiration (900s)
  - ✓ Token can be verified with JWT_SECRET

- Refresh token creation
  - ✓ Creates valid JWT with userId
  - ✓ Includes encrypted masterKey (encrypted with JWT_SECRET)
  - ✓ Token includes correct expiration (7 days)
  - ✓ Token can be verified with JWT_SECRET

- Token verification
  - ✓ Verifies valid token successfully
  - ✓ Rejects expired token
  - ✓ Rejects token with invalid signature
  - ✓ Rejects malformed token

**Why third:** Builds on crypto tests, needed for middleware/route tests.

---

## Middleware

### 4. Unit Tests: `src/__tests__/unit/middleware/use-access-token.test.ts`
**Purpose:** Test access token middleware in isolation

- Valid token
  - ✓ Extracts token from Authorization header
  - ✓ Verifies token signature
  - ✓ Adds `decodedToken` to request
  - ✓ Calls next()

- Invalid/Missing token
  - ✓ Returns 401 when Authorization header missing
  - ✓ Returns 401 when token invalid/expired
  - ✓ Returns 401 when token signature invalid

**Why here:** Tests middleware independently before integration tests.

---

### 5. Unit Tests: `src/__tests__/unit/middleware/error-handler.test.ts`
**Purpose:** Test global error handler

- Mongoose validation errors
  - ✓ Catches and formats validation error
  - ✓ Returns 400 status

- Mongoose cast errors
  - ✓ Catches and formats cast error
  - ✓ Returns 400 status

- Duplicate key errors (11000)
  - ✓ Catches and formats duplicate error
  - ✓ Returns 409 status

- Unexpected errors
  - ✓ Catches unexpected error
  - ✓ Returns 500 status

**Why here:** Foundation for integration tests that might throw errors.

---

## Integration Tests

### 6. Integration Tests: `src/__tests__/integration/auth-flow.test.ts`
**Purpose:** Test complete authentication flow end-to-end

- User registration
  - ✓ POST /auth/register with valid payload → user created in DB
  - ✓ Password stored as hash
  - ✓ Master key derived and encrypted
  - ✓ Returns 201 + tokens in response

- User login
  - ✓ POST /auth/login with correct credentials → tokens issued
  - ✓ POST /auth/login with wrong password → 401
  - ✓ POST /auth/login with non-existent user → 401
  - ✓ Access token contains userId and masterKey
  - ✓ Refresh token stored in httpOnly cookie

- Token refresh
  - ✓ POST /auth/refresh with valid refresh token → new tokens issued
  - ✓ New access token is different from old
  - ✓ New refresh token is different from old
  - ✓ POST /auth/refresh without refresh token → 401

- User logout
  - ✓ POST /auth/logout marks refresh token as revoked
  - ✓ Revoked token cannot be used to refresh
  - ✓ User cannot access protected routes after logout

**Why here:** Validates auth flow works with database; builds on unit tests.

---

### 7. Integration Tests: `src/__tests__/integration/note-operations.test.ts`
**Purpose:** Test note CRUD with authentication

- Create note (authenticated)
  - ✓ POST /notes with valid token → note created
  - ✓ Note encrypted in database
  - ✓ Returns 201 + note data

- Read notes
  - ✓ GET /notes with valid token → user's notes returned
  - ✓ POST /notes without valid token → 401

- Update note
  - ✓ PUT /notes/:id with valid token → note updated
  - ✓ Can only update own notes (different user → 403)

- Delete note
  - ✓ DELETE /notes/:id with valid token → note deleted
  - ✓ Can only delete own notes

**Why here:** Validates protected routes work with middleware.

---

## Security Tests

### 8. Security Tests: `src/__tests__/security/token-rotation.test.ts`
**Purpose:** Verify token rotation prevents old token reuse

- Refresh token invalidation
  - ✓ After refresh, old refresh token is marked revoked in DB
  - ✓ Attempting to use old refresh token → 401
  - ✓ New refresh token works

- Access token independence
  - ✓ Old access token still works until expiration (not revoked on refresh)
  - ✓ After logout, refresh token revoked but access token may still work (until expiration)

**Why security:** Tests the invariant "revoked tokens cannot be reused" which is critical for security.

---

### 9. Security Tests: `src/__tests__/security/token-revocation.test.ts`
**Purpose:** Verify token revocation is properly enforced

- Logout revocation
  - ✓ Logout revokes refresh token in database
  - ✓ Future refresh attempts fail with revoked token

- Database revocation check
  - ✓ Even with valid JWT signature, revoked token is rejected
  - ✓ Verification checks both JWT validity AND database revocation status

**Why security:** Tests that revocation is enforced at the database layer, not just JWT layer.

---

### 10. Security Tests: `src/__tests__/security/encryption-integrity.test.ts`
**Purpose:** Verify encryption/decryption preserves data integrity

- Master key encryption in tokens
  - ✓ Master key encrypted in refresh token with JWT_SECRET
  - ✓ Master key decrypted from token matches original
  - ✓ Tampering with encrypted masterKey makes decryption fail

- Master key encryption in database
  - ✓ Master key encrypted in user document with password
  - ✓ Can decrypt with correct password
  - ✓ Cannot decrypt with wrong password

- Note content encryption
  - ✓ Note content encrypted in database
  - ✓ Decrypted with user's masterKey

**Why security:** Validates the invariant "encrypted data cannot be accessed without correct keys".

---

### 11. Security Tests: `src/__tests__/security/cors-validation.test.ts`
**Purpose:** Verify CORS configuration prevents unauthorized access

- Allowed origins
  - ✓ Requests from `https://secure-notes.gillesdeblock.com` allowed
  - ✓ Requests from `http://localhost:5173` allowed
  - ✓ CORS preflight (OPTIONS) succeeds for allowed origins

- Blocked origins
  - ✓ Requests from unauthorized origin rejected
  - ✓ `Access-Control-Allow-Origin` header not sent
  - ✓ Browser would block response

**Why security:** Prevents CSRF and unauthorized cross-origin access.

---

### 12. Security Tests: `src/__tests__/security/master-key-security.test.ts`
**Purpose:** Verify master key derivation and storage is secure

- Key derivation
  - ✓ Master key derived from password using argon2 KDF
  - ✓ Same password + salt produces same key (deterministic)
  - ✓ Different passwords produce different keys
  - ✓ Salt is stored, used in key derivation

- Key in transit
  - ✓ Master key sent in access token (JWT encrypted)
  - ✓ Master key sent in refresh token (JWT encrypted with JWT_SECRET)
  - ✓ Master key never sent in plaintext

- Key at rest
  - ✓ Master key stored encrypted in database (encrypted with password)
  - ✓ Master key cannot be recovered without password

**Why security:** Validates the invariant "master key cannot be compromised".

---

## Testing Summary

| Category | Count | Location | Focus |
|----------|-------|----------|-------|
| Unit - Utilities | 1 file | `unit/lib/` | Pure functions |
| Unit - Crypto | 1 file | `unit/lib/` | Encryption/hashing |
| Unit - Auth | 1 file | `unit/lib/` | JWT operations |
| Unit - Middleware | 2 files | `unit/middleware/` | Request handling |
| Integration | 2 files | `integration/` | Full flows + database |
| Security | 5 files | `security/` | Invariants & properties |
| **Total** | **~12 files** | | |

---

## Execution Order

1. **Unit Tests First** (1-5): Foundation, fast, no DB
2. **Integration Tests** (6-7): Validates components work together
3. **Security Tests** (8-12): Validates security properties hold

This order ensures:
- ✅ Catch bugs early (unit tests)
- ✅ Validate integration works (integration tests)
- ✅ Confirm security invariants hold (security tests)
- ✅ Reusable setup (MongoDB Memory Server initialized once)

---

## Running Tests

```bash
npm test                          # Run all tests
npm test:watch                    # Watch mode
npm test:coverage                 # Coverage report

npm test -- src/__tests__/unit    # Unit tests only
npm test -- src/__tests__/integration  # Integration only
npm test -- src/__tests__/security     # Security only
```

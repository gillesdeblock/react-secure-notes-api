# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`secure-notes-api` is a Node.js/Express backend for the secure notes web application [(see repository)](https://github.com/gillesdeblock/react-secure-notes).

It supports user authentication, encryption, and secure data storage. The API uses MongoDB for persistence and implements JWT-based authentication with refresh tokens and master key encryption for sensitive data.

## Common Commands

- **Start development server** (with hot reload): `npm run dev`
  - Runs on port 3000 by default (configurable via `PORT` env var)
  - Uses ts-node-dev with `--inspect` flag for debugging
  - Entry point: `src/server.local.ts` (auto-loads `.env`)
- **Build TypeScript to JavaScript**: `npm run build`
  - Outputs to `dist/` directory
  - Uses strict TypeScript configuration

## Architecture

### Authentication & Security Flow

The API implements a multi-layer authentication system:

1. **User Registration/Login**: Passwords hashed with argon2, credentials validated before token creation
2. **Access Token (JWT)**: Short-lived (900s default), includes `userId` and `masterKey`
3. **Refresh Token (JWT)**: Long-lived (7 days), self-contained JWT that includes encrypted `masterKey`, stored in MongoDB for validation/revocation
4. **Master Key Encryption**: Each user has a master key derived from their password using argon2 KDF. Encrypted with AES-GCM using the user's password in the database. Also embedded (encrypted with JWT_SECRET) in refresh tokens for self-contained token flow.

Key files:

- [`src/lib/auth.ts`](src/lib/auth.ts): JWT creation, verification, refresh token management
- [`src/lib/crypto.ts`](src/lib/crypto.ts): Password hashing, master key derivation, AES-GCM encryption
- [`src/middleware/use-access-token.ts`](src/middleware/use-access-token.ts): JWT validation middleware

### Route Structure

Routes are organized by resource in [`src/routes/`](src/routes/):

- `auth.ts`: POST `/auth/login`, `/auth/register`, `/auth/refresh`, `/auth/logout`
- `user.ts`: User profile endpoints
- `note.ts`: Note CRUD operations

### Middleware

- [`connect-db.ts`](src/middleware/connect-db.ts): MongoDB connection initialization
- [`use-access-token.ts`](src/middleware/use-access-token.ts): JWT verification for protected endpoints (extracts `decodedToken` from Authorization header). **Not used on POST /auth/refresh** — refresh endpoint is self-contained and decodes the refresh token JWT directly.
- [`error-handler.ts`](src/middleware/error-handler.ts): Global Express error handler — catches Mongoose validation errors, cast errors, duplicate key errors (11000), and unexpected errors; registered last in [`src/app.ts`](src/app.ts). Enabled by `express-async-errors` (imported at the top of `app.ts`), which patches async route handlers to forward thrown errors to this handler automatically.

### Data Models

MongoDB schemas in [`src/models/`](src/models/):

- `user.ts`: User document with password hash, KDF salt, encrypted master key
- `note.ts`: Note document with encrypted content
- `refresh-token.ts`: Refresh token hashes for revocation tracking

### Types

TypeScript types in [`src/types/`](src/types/):

- `index.ts`: Re-exports all types from `note.ts`, `user.ts`, `token.ts`, `request.ts`
- `user.ts`: `User`, `UserDocument`
- `note.ts`: `Note`, `NoteDocument`, `NoteCreatePayload`
- `token.ts`: `RefreshToken`, `AccessTokenPayload`
- `request.ts`: `AuthenticatedRequest` (extends Express `Request` with `decodedToken: AccessTokenPayload`)
- `express.d.ts`: Express augmentation adding `decodedToken` to the base `Request` type
- `global.d.ts`: Global type overrides

### Utilities

- [`src/lib/utils.ts`](src/lib/utils.ts): `hasProperties` (property presence check), `sanitizeObjectForDb` (converts `Buffer` values to base64 strings)
- [`src/lib/mongoose.ts`](src/lib/mongoose.ts): Mongoose connection management

## Key Implementation Details

### Access Token Payload

Contains `userId` and `masterKey` (base64-encoded). The `masterKey` is derived from the user's password and encrypted in the database; it's sent in the JWT so the client can decrypt user data without re-asking for the password.

### Refresh Token Flow

The refresh endpoint (`POST /auth/refresh`) is **self-contained** and does not require an Authorization header:

1. Client sends refresh token from httpOnly cookie (no Authorization header needed)
2. Server validates the refresh token:
   - Verifies JWT signature with `JWT_SECRET`
   - Checks expiration date in the database
   - Checks revocation status in the database
3. Server extracts `userId` and `masterKey` directly from the refresh token JWT
4. Server creates a new access token and new refresh token, revokes the old refresh token

**Token rotation:** On every refresh, the previous refresh token is revoked (marked with `revokedAt`). This prevents token reuse and limits the blast radius of token leakage. The new refresh token is a fresh JWT with a new IV and auth tag for the encrypted masterKey.

### CORS Configuration

Allowed origins hardcoded in [`src/app.ts`](src/app.ts): `https://secure-notes.gillesdeblock.com` and `http://localhost:5173`. Credentials are enabled for both.

### Response Format

The API returns:

- JSON responses via `res.json()` or `res.status(xxx).json()`
- HTTP status codes set manually (no `http-status` dependency)
- Cookies for token storage (httpOnly, secure, sameSite: 'none')

## Development Tips

- Use `npm run dev` with the `--inspect` flag enabled for remote debugging
- Add new routes by creating files in [`src/routes/`](src/routes/) and importing them in [`src/app.ts`](src/app.ts)
- Middleware execution order matters: CORS → JSON parsing → Cookie parsing → DB connection → Routes → Error handler
- TypeScript strict mode is enabled; all types must be explicitly defined
- Async route handlers do not need try/catch — `express-async-errors` forwards any thrown error to the global error handler automatically

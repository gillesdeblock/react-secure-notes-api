# secure-notes-api

A secure REST API for managing encrypted notes, built with Node.js, Express, and TypeScript. Notes are end-to-end encrypted using per-user master keys so that sensitive content is never stored in plaintext — not even in the database.

Pairs with the [react-secure-notes](https://github.com/gillesdeblock/react-secure-notes) frontend.

---

## Table of Contents

- [Features](#features)
- [Tech Stack](#tech-stack)
- [Security Architecture](#security-architecture)
- [API Endpoints](#api-endpoints)
- [Getting Started](#getting-started)
- [Environment Variables](#environment-variables)

---

## Features

- **End-to-end encryption** — note content is encrypted with AES-256-GCM using a per-user master key before being stored in MongoDB
- **Password-based key derivation** — master keys are derived from the user's password using Argon2id (OWASP-recommended), so only the user can decrypt their own notes
- **JWT authentication** — short-lived access tokens (15 min) embedded in HTTP-only cookies
- **Refresh token rotation** — long-lived refresh tokens (7 days) are rotated on every use and fully revoked on logout, preventing token reuse attacks
- **Input validation** — all endpoints validated with Joi schemas via `express-joi-validation`
- **Global async error handling** — powered by `express-async-errors`, with structured error responses for validation failures, duplicate keys, and unexpected errors
- **TypeScript strict mode** — fully typed codebase with no implicit `any`

---

## Tech Stack

| Category | Technology |
|---|---|
| Runtime | Node.js + TypeScript |
| Framework | Express.js |
| Database | MongoDB + Mongoose |
| Auth | JWT (`jsonwebtoken`) + Argon2id + bcrypt |
| Encryption | AES-256-GCM (Node.js built-in `crypto`) |
| Validation | Joi + `express-joi-validation` |

---

## Security Architecture

Authentication and encryption are layered to ensure the server never has access to plaintext note content:

1. **Registration** — a random master key is generated for the user. It is encrypted with a key derived from their password (Argon2id KDF + AES-256-GCM) and stored in that encrypted form.
2. **Login** — the password is used to re-derive the decryption key, which decrypts the master key. The master key is embedded in the signed JWT access token so subsequent requests can decrypt notes without re-asking for the password.
3. **Notes** — each note's title and content are individually encrypted with AES-256-GCM using the user's master key and a random 12-byte IV. GCM authentication tags prevent silent data tampering.
4. **Refresh tokens** — stored as bcrypt hashes in MongoDB. On each refresh the old token is revoked and a new one is issued (rotation). Logout revokes all active tokens for the user.

---

## API Endpoints

| Method | Path | Description |
|---|---|---|
| POST | `/auth/register` | Create an account |
| POST | `/auth/login` | Login and receive token cookies |
| POST | `/auth/refresh` | Rotate the refresh token |
| POST | `/auth/logout` | Revoke all refresh tokens |
| GET | `/me` | Get the authenticated user's profile |
| GET | `/notes` | List all notes (decrypted) |
| POST | `/notes` | Create an encrypted note |
| GET | `/notes/:id` | Get a single note |
| PUT | `/notes/:id` | Update a note |
| DELETE | `/notes/:id` | Delete a note |
| POST | `/notes/batch-remove` | Delete multiple notes by ID |
| GET | `/health` | Health check |

---

## Getting Started

### Prerequisites

- Node.js 18+
- MongoDB running locally (or a remote URI)

### 1. Clone the repository

```bash
git clone https://github.com/gillesdeblock/secure-notes-api.git
cd secure-notes-api
```

### 2. Install dependencies

```bash
npm install
```

### 3. Configure environment variables

Create a `.env` file at the project root:

```env
MONGO_URI=mongodb://localhost:27017/secure-notes-api
JWT_SECRET=replace_with_a_long_random_secret
PORT=3000
```

See [Environment Variables](#environment-variables) for details on each value.

### 4. Start the development server

```bash
npm run dev
```

The API will be available at `http://localhost:3000`. The server hot-reloads on file changes.

To build for production:

```bash
npm run build
```

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `MONGO_URI` | Yes | MongoDB connection string (e.g. `mongodb://localhost:27017/secure-notes-api`) |
| `JWT_SECRET` | Yes | Secret used to sign JWTs — use a cryptographically random string of 64+ characters |
| `PORT` | No | Port the server listens on (default: `3000`) |

# Centralized Identity Provider (IdP) & Single Sign-On (SSO) Microservice

Production-grade **OAuth 2.1 Authorization Server, OpenID Connect (OIDC) Discovery Provider, and Centralized Single Sign-On (SSO) Hub** built with **Node.js, TypeScript (`strict: true`), Express.js, MongoDB (Mongoose), and Redis**.

Designed to serve as the single central authentication authority across multiple personal SPAs, mobile apps, and backend microservices—eliminating duplicated auth logic and shared JWT secrets.

> See [docs/SECURITY_AUDIT.md](./docs/SECURITY_AUDIT.md) for the complete Phase 1 security audit of the legacy codebase and remediation matrix.

---

## Core Security & Protocol Capabilities

- **OAuth 2.1 Authorization Code + PKCE (`S256`) Only:** Enforces mandatory `S256` Proof Key for Code Exchange for all public and confidential clients. Explicitly rejects deprecated Implicit (`response_type=token`), ROPC (`grant_type=password`), and `plain` PKCE flows.
- **Asymmetric `RS256` Signing & `JWKS` Discovery:** Signs 15-minute Access Tokens (and optional OIDC `id_token`s) with a 2048-bit RSA Private Key (`kid` RFC 7638 thumbprint). Downstream services verify tokens independently via `GET /.well-known/jwks.json` with zero shared secrets and seamless key rotation (`RSA_PREVIOUS_PUBLIC_KEYS_BASE64`).
- **Atomic Refresh Token Rotation & Reuse Detection (Redis):** Long-lived Refresh Tokens (`7–30` days) are stored strictly in `HttpOnly`, `Secure`, `SameSite` cookies and tracked by token family (`rt:family:<id>`) in Redis via an atomic Lua script. Replaying a previously rotated token triggers immediate revocation of the entire session family.
- **Authorization Code Replay Protection:** Single-use short-lived (`120s`) authorization codes are atomically consumed in Redis. Replaying an already-exchanged authorization code immediately revokes all tokens issued from that grant (RFC 6749 Section 10.5).
- **Zero-Friction Multi-App SSO & Consent Engine:** Browser `idp_sso_session` cookies enable seamless Single Sign-On across registered first-party projects while supporting interactive scope consent screens (`requireConsent: true`) for third-party/untrusted clients.
- **Dynamic Per-Client CORS & Strict Redirect Validation:** Automatically validates browser `Origin` headers against registered `OAuthClient.allowedOrigins` (cached in Redis with instant cache invalidation on client CRUD) and enforces exact character-for-character `redirect_uri` matching before any redirect.
- **Hardened Upstream Social OAuth (Google & GitHub):** Native OAuth 2.0 + PKCE + single-use Redis `state` CSRF verification with verified-email safe account linking.

---

## Enterprise Layered Architecture

```text
src/
├── config/             # Zod Env validation, MongoDB, Redis (Lua atomic ops), RS256 Keys/JWKS, Dynamic CORS
├── constants/          # HTTP statuses, internal & RFC 6749 error codes, token TTLs, scopes, enums
├── modules/
│   ├── auth/           # Register, Login, Refresh, Logout, TokenFamilyService, Google/GitHub OAuth
│   ├── oauth/          # /authorize, /token, /revoke, PKCE S256 verifier, Consent engine, JWKS & OIDC discovery
│   ├── clients/        # CRUD to register personal projects (client_id, allowedOrigins, redirectUris, secret rotation)
│   └── users/          # /me profile (scope-aware), password rotation, active session management, RBAC/scopes
├── middlewares/        # Request ID tracing, Helmet CSP, Rate limiters, Zod validator, RS256 authGuard, Error handler
├── utils/              # AppError/OAuthProtocolError, asyncHandler, Argon2id/SHA-256 helpers, PKCE, JWT, Cookies
├── types/              # Global TypeScript interfaces & Express Request augmentation
├── app.ts              # Express pipeline assembly & dependency wiring
└── server.ts           # Bootstrap & graceful SIGTERM/SIGINT shutdown
```

---

## Quick Start

### 1. Install Dependencies & Generate `RS256` Keys

```bash
npm install
cp .env.example .env
npm run keygen
```

`npm run keygen` generates `./keys/private.pem` and `./keys/public.pem` (git-ignored) and prints Base64 environment variables (`RSA_PRIVATE_KEY_BASE64`, `RSA_PUBLIC_KEY_BASE64`) ready for production secret managers.

### 2. Run Locally (with Docker MongoDB + Redis)

```bash
docker compose up -d mongodb redis
npm run dev
```

Or launch the entire containerized stack:

```bash
docker compose up --build -d
```

### 3. Run Verification & Security Test Suite

```bash
npm run typecheck
npm test
npm run build
```

---

## Key Endpoints Overview

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/.well-known/jwks.json` | Public RSA JSON Web Key Set (`RS256`) for independent JWT verification |
| `GET` | `/.well-known/openid-configuration` | Standard OIDC / OAuth 2.1 server discovery metadata |
| `GET` | `/oauth/authorize` | OAuth 2.1 Authorization Endpoint (`response_type=code`, `code_challenge_method=S256`) |
| `POST` | `/oauth/authorize/decision` | Interactive user consent approval/denial handler |
| `POST` | `/oauth/token` | OAuth 2.1 Token Endpoint (`authorization_code`, `refresh_token`) |
| `POST` | `/oauth/revoke` | RFC 7009 Refresh Token family revocation |
| `POST` | `/api/v1/auth/register` | First-party account registration (Argon2id) |
| `POST` | `/api/v1/auth/login` | First-party & SSO credential authentication |
| `POST` | `/api/v1/auth/refresh` | First-party `HttpOnly` cookie refresh rotation |
| `POST` | `/api/v1/auth/logout` | Revoke current refresh family & SSO session |
| `POST` | `/api/v1/auth/logout-all` | Global logout across all devices and client apps |
| `GET` | `/api/v1/auth/google` & `/callback` | Upstream Google OAuth 2.0 + PKCE + Redis CSRF `state` |
| `GET` | `/api/v1/auth/github` & `/callback` | Upstream GitHub OAuth 2.0 + PKCE + Redis CSRF `state` |
| `CRUD` | `/api/v1/clients` | Register & manage personal client applications (`ADMIN` role) |
| `GET/PATCH` | `/api/v1/users/me` | Scope-aware authenticated user profile & session management |

---

## Verifying Tokens in Your Other Personal Projects

Any downstream Node.js / Express / NestJS / Next.js backend can verify Access Tokens issued by this IdP **without sharing any secret keys**, using `jose` against `/.well-known/jwks.json`:

```typescript
import { createRemoteJWKSet, jwtVerify } from 'jose';

const JWKS = createRemoteJWKSet(
  new URL('https://auth.yourdomain.com/.well-known/jwks.json'),
);

export async function verifySsoAccessToken(bearerToken: string) {
  const { payload } = await jwtVerify(bearerToken, JWKS, {
    algorithms: ['RS256'],
    issuer: 'https://auth.yourdomain.com',
    audience: 'cl_your_registered_project_client_id',
  });

  return {
    userId: payload.sub,
    roles: payload.roles as string[],
    scopes: String(payload.scope ?? '').split(' '),
  };
}
```

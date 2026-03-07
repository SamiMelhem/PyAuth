<div align="center">

# PyAuth

### Building Better Auth for Python

Learn from the best parts of [Better Auth](https://better-auth.com), [django-allauth](https://github.com/pennersr/django-allauth), [Authlib](https://github.com/authlib/authlib), [FastAPI Users](https://github.com/fastapi-users/fastapi-users), and [Python Social Auth](https://github.com/python-social-auth).

[Vision](#about-the-project) · [MVP](#mvp) · [Development](#development) · [Issues](../../issues)

[![Python](https://img.shields.io/badge/python-3.10%2B-000000?style=flat&logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/pypi/v/fastapi?style=flat&colorA=000000&colorB=000000&logo=fastapi&logoColor=white)](https://pypi.org/project/fastapi/)
[![SQLAlchemy](https://img.shields.io/pypi/v/sqlalchemy?style=flat&colorA=000000&colorB=000000&logo=sqlalchemy&logoColor=white)](https://pypi.org/project/sqlalchemy/)
[![Pydantic](https://img.shields.io/pypi/v/pydantic?style=flat&colorA=000000&colorB=000000&logo=pydantic&logoColor=white)](https://pypi.org/project/pydantic/)

</div>

## About the Project

PyAuth is an authentication library for Python focused on delivering a Better Auth-style developer experience in the Python ecosystem. The goal is to build a framework-agnostic auth system with batteries-included primitives for credentials, sessions, email verification, OAuth, and organization-aware application patterns.

The long-term vision is for PyAuth to plug into multiple Python frameworks, including FastAPI, Litestar, Flask, and Django Ninja, while exposing a consistent core architecture and adapter interface underneath.

### Why PyAuth

Authentication in Python is powerful, but fragmented.

Many libraries solve one part of the problem well, but few provide a cohesive developer experience across credentials, OAuth, session management, adapters, verification flows, and framework integration. Features like passkeys, magic links, OTP, and team or organization workflows are either missing, split across multiple packages, or require significant custom glue code.

PyAuth exists to explore a more unified approach:

- Framework-friendly auth that can plug into modern Python backends.
- A standardized adapter interface across SQLAlchemy and future data layers.
- Better defaults for crypto, cookies, sessions, and account linking.
- A cleaner developer experience than piecing together multiple auth packages by hand.

## Design Goals

- Support modern Python frameworks with a shared authentication core.
- Keep framework-specific integration thin and predictable.
- Provide secure defaults for passwords, sessions, tokens, and cookies.
- Make auth strategies composable instead of tightly coupled to one stack.
- Keep the MVP practical: one strong adapter, a few strong flows, and room to expand.

## MVP

The MVP is intentionally focused on the smallest useful surface area needed to prove the architecture. Once Phase 3 is completed, the MVP should cover local credentials, database-backed browser sessions, provider login for Google and GitHub, and email-driven verification and recovery flows on top of one shared core.

### 1. Core Architecture

- `PyAuth` main entry point for configuration and framework integration.
- A typed config schema powered by Pydantic v2 for settings such as session expiration, hashing configuration, and cookie behavior.
- Standardized error handling through a unified `PyAuthError` abstraction that can map cleanly to framework-specific HTTP responses.
- Crypto utilities for:
  - Password hashing with Argon2id.
  - Secure token generation for sessions and verification flows.

### 2. Data Layer

PyAuth uses an adapter pattern so auth logic can stay stable while persistence evolves.

- An abstract base adapter with shared operations such as `create_user`, `get_user_by_email`, `create_session`, and `update_account`.
- A standard schema shape that adapters must map to:
  - User
  - Account
  - Session
  - Verification
- MVP adapter target:
  - Async SQLAlchemy adapter for PostgreSQL and SQLite.

### 3. Authentication Strategies

#### Email and Password

- Registration with normalized email handling, modern password policy, Argon2id hashing, and user creation.
- Login with credential lookup, password verification, and session creation.
- Password reset with single-use hashed recovery tokens, email delivery, token verification, and password update.

References: NIST SP 800-63B-4, OWASP Authentication Cheat Sheet, OWASP Password Storage Cheat Sheet, OWASP Forgot Password Cheat Sheet

#### Session Management

- High-entropy opaque session token generation.
- Database-backed session storage.
- Hashed token storage so leaked session tables do not expose bearer secrets directly.
- Secure cookie defaults with `HttpOnly`, `Secure`, and `SameSite` controls, with room for `__Host-` style deployment defaults.

References: OWASP Session Management Cheat Sheet, MDN Set-Cookie, NIST SP 800-63B-4, RFC 6265

#### Social Authentication

MVP providers:

- Google
- GitHub

Core flow requirements:

- One-time `state` generation to protect against CSRF and callback replay.
- Authorization code exchange with PKCE using `S256`.
- Provider-subject-based account identity, with cautious email-based linking only when provider data is trustworthy.
- Exact redirect handling and issuer-aware validation for multi-provider safety.

References: RFC 6749, RFC 7636, RFC 9700, RFC 9207, Google Identity docs, GitHub OAuth docs

#### Email Verification

- Verification by magic link or code using a purpose-scoped, single-use token.
- Ownership proof through email delivery, separate from lightweight syntax validation.

References: OWASP Input Validation Cheat Sheet, OWASP Authentication Cheat Sheet, RFC 5321

### 4. Framework Integration

PyAuth will expose a translation layer so the core system is not tied directly to one framework request object.

- `PyAuthRequest` as the normalized request abstraction.
- MVP framework target:
  - FastAPI / Starlette

Planned FastAPI integration:

- `PyAuthRouter` for mounting endpoints such as:
  - `/api/auth/sign-in`
  - `/api/auth/sign-up`
  - `/api/auth/callback/{provider}`
- `get_current_user` dependency that reads the session cookie, validates the session, and returns the user.

## MVP Feature Checklist

This checklist mixes the Phase 3 strategy surface with the remaining MVP infrastructure still needed to ship the full package.

| Component | Feature | Details |
| --- | --- | --- |
| Core | `PyAuth` class | Main entry point used to initialize config and integrations |
| Core | Client | Python client, with room for a generated JS client later |
| Database | `SQLAlchemyAdapter` | Async SQLAlchemy support for PostgreSQL and SQLite |
| Strategy | Email and Password | Sign up, sign in, password reset, and modern password policy |
| Strategy | Session Management | Database-backed opaque sessions with hashed token storage and secure cookie defaults |
| Strategy | OAuth2 | Google and GitHub authorization-code login with PKCE and cautious account linking |
| Strategy | Email Verification | Magic-link or code-based email ownership proof with expiring single-use tokens |
| Security | Rate limiter | Brute-force protection for sign-in endpoints |
| Security | CSRF | Double-submit cookie or similar protection |
| Transport | Bearer and Cookie | Browser sessions and API token use cases |
| Utils | Mailer | Simple SMTP interface for verification and recovery emails |

## Supported Framework Direction

The MVP is centered on FastAPI first, but the broader framework direction is:

- FastAPI
- Litestar
- Flask
- Django Ninja

The intent is not to hard-code auth behavior into each framework independently, but to build a shared core with thin framework bindings on top.

## Standards and References

PyAuth is being designed with common authentication and web security standards in mind. The list below is a compact standards-focused summary; the Phase 3 sections above and `docs/reference/phase-3-auth-strategies.md` include the fuller practical reference set, including MDN and provider documentation.

- RFC 7519: JSON Web Token, if stateless tokens are added.
- RFC 6749: OAuth 2.0.
- RFC 7636: PKCE.
- RFC 9700: OAuth 2.0 security best current practice.
- RFC 9207: Authorization server issuer identification.
- RFC 6238: TOTP for future 2FA support.
- RFC 6265: HTTP cookies, including `Secure` and `HttpOnly`.
- RFC 5321: SMTP and mailbox delivery semantics relevant to email flows.
- NIST SP 800-63B-4: password and session guidance for modern digital identity systems.
- OWASP Authentication Cheat Sheet: practical web authentication guidance.
- OWASP Password Storage Cheat Sheet: password hashing guidance, including Argon2id.
- OWASP Forgot Password Cheat Sheet: password recovery flow guidance.
- OWASP Session Management Cheat Sheet: session token lifecycle and cookie usage guidance.
- OWASP Input Validation Cheat Sheet: pragmatic email address validation and verification guidance.

## Development

This project uses [`uv`](https://docs.astral.sh/uv/) for dependency management.

### Install dependencies

```bash
uv sync --all-extras --dev
```

### Add a package

```bash
uv add <package>
```

### Add a development dependency

```bash
uv add --dev <package>
```

### Run Python commands

```bash
uv run python
uv run pytest
```

### Update dependencies

```bash
uv lock --upgrade
uv sync
```

## Inspiration

PyAuth is heavily inspired by the ideas and trade-offs explored in:

- [Better Auth](https://better-auth.com)
- [django-allauth](https://github.com/pennersr/django-allauth)
- [Authlib](https://github.com/authlib/authlib)
- [FastAPI Users](https://github.com/fastapi-users/fastapi-users)
- [Python Social Auth](https://github.com/python-social-auth)

## Contribution

PyAuth is an open-source project in active MVP development.

You can help by:

- Opening issues for missing auth flows, framework integrations, and adapter ideas.
- Suggesting improvements to the core architecture and developer experience.
- Contributing implementation work as the MVP takes shape.

## Security

If you discover a security issue related to PyAuth, please avoid posting sensitive details in a public issue. A dedicated security reporting process can be added as the project matures.

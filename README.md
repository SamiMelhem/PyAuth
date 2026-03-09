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

The current MVP is a working authentication stack for Python backend applications built around one shared core, one production-oriented adapter story, and one shipped framework integration path.

### Current MVP

- `PyAuth` is the main entry point for auth configuration, flows, tokens, and integrations.
- `PyAuthSettings` provides typed Pydantic v2 configuration for hashing, JWTs, sessions, cookies, OAuth, verification, and mailer behavior.
- `PyAuthError` and its typed subclasses provide a unified error model that maps cleanly into framework responses.
- The data layer uses an adapter pattern, with async `SQLAlchemyAdapter` support for SQLite and PostgreSQL-shaped deployments.
- The shared schema model covers `User`, `Account`, `Session`, and `Verification`.
- Local credentials are implemented with email normalization, Argon2id password hashing, sign-up, sign-in, sign-out, and password reset.
- Session management uses high-entropy opaque session tokens, hashed token storage, and secure cookie defaults.
- Bearer transport is also supported through JWT access tokens and framework bearer dependencies.
- Social auth is implemented for Google and GitHub using authorization-code flow with PKCE, state validation, and cautious account linking.
- Email verification is implemented with purpose-scoped, single-use verification tokens delivered through the mailer interface.
- `PyAuthRequest` is the normalized request abstraction for framework integrations.
- `PyAuthRouter` is the framework-agnostic integration API, with FastAPI / Starlette as the first shipped adapter.
- The FastAPI adapter supports:
  - `PyAuthRouter(...).for_fastapi()`
  - `PyAuthRouter(...).mount_fastapi(app)`
  - `PyAuthRouter(...).get_current_user()`
  - `PyAuthRouter(...).get_current_user_bearer()`
  - mounted auth endpoints for sign-up, sign-in, sign-out, password reset, email verification, OAuth start, and OAuth callback
- Local development DX includes `PyAuthSettings.for_development(...)` for generated dev JWT keys and `ConsoleMailer` for console-delivered verification and recovery messages.

## MVP Feature Checklist

This checklist reflects the current MVP surface available in the repository today.

| Component | Feature | Details |
| --- | --- | --- |
| Core | `PyAuth` | Main entry point used to initialize settings, auth flows, tokens, and integrations |
| Core | `PyAuthSettings` | Typed configuration for hashing, JWTs, sessions, cookies, OAuth, verification, and mailer settings |
| Core | Errors | Unified `PyAuthError` hierarchy for framework-friendly auth errors |
| Database | `SQLAlchemyAdapter` | Async SQLAlchemy adapter for SQLite and PostgreSQL-style deployments |
| Schema | Auth models | Shared `User`, `Account`, `Session`, and `Verification` schema model |
| Strategy | Email and Password | Sign up, sign in, sign out, password reset, and modern password hashing with Argon2id |
| Strategy | Session Management | Database-backed opaque sessions with hashed token storage and secure cookie defaults |
| Strategy | OAuth2 | Google and GitHub authorization-code login with PKCE, state validation, and account linking |
| Strategy | Email Verification | Single-use verification tokens for email ownership proof |
| Transport | Bearer and Cookie | Cookie auth via `get_current_user()` and bearer auth via `get_current_user_bearer()` |
| Framework | `PyAuthRouter` | Framework-agnostic router API with FastAPI / Starlette as the first shipped adapter |
| Framework | `PyAuthRequest` | Normalized request abstraction for framework integrations |
| DX | Development helpers | `PyAuthSettings.for_development(...)` and built-in `ConsoleMailer` |

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

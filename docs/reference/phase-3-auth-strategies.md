# Phase 3 Auth Strategies

This document explains the standards and implementation guidance behind Phase 3 of PyAuth's MVP:

- Email and password
- Session management
- Social authentication
- Email verification

It is meant to support the shorter summary in `README.md` with stronger references, currentness notes, and concrete guidance for how PyAuth should implement each flow.

## Existing PyAuth Anchors

PyAuth already has the core model boundaries needed for these strategies:

- `schema/models.py` defines `User`, `Account`, `Session`, and `Verification`.
- `schema/models.py` distinguishes `VerificationPurpose.EMAIL_VERIFICATION` from `VerificationPurpose.PASSWORD_RESET`.
- `schema/models.py` stores `Session.token_hash`, which fits opaque server-side sessions.
- `schema/models.py` stores `Account.provider` and `Account.provider_account_id`, which is the correct provider identity boundary for social login.
- `core/config.py` already exposes Argon2id password hashing settings and secure cookie defaults.

Those boundaries let PyAuth follow current guidance without redesigning its data model first.

## Email And Password

### Recommended references

- `NIST SP 800-63B-4`
- `OWASP Authentication Cheat Sheet`
- `OWASP Password Storage Cheat Sheet`
- `OWASP Forgot Password Cheat Sheet`
- Optional: `RFC 9106` for Argon2 guidance

### Keep, replace, or supplement

- Keep the NIST reference, but update it from the older `NIST SP 800-63B` wording to `NIST SP 800-63B-4`.
- Supplement NIST with OWASP guidance because NIST gives the policy direction, while OWASP is more practical about application behavior, recovery UX, and storage.
- Add `OWASP Forgot Password Cheat Sheet` because password reset is a distinct security-sensitive flow and deserves its own reference.
- Add `OWASP Password Storage Cheat Sheet` because PyAuth explicitly uses password hashing and should point to concrete storage guidance.

### Why these references are stronger

`NIST SP 800-63B-4` is the current revision, published in August 2025. It is the strongest high-level standards reference for verifier behavior, password policy, and session expectations. The older README wording pointed at the right standards family, but not the newest revision.

OWASP cheat sheets are living implementation guidance. They are better evidence for application-level choices such as enumeration resistance, reset token handling, and practical password storage defaults than an RFC alone would be.

### PyAuth implementation guidance

PyAuth should implement local credentials with these rules:

- Favor length over composition rules. Do not require uppercase, numeric, or special-character patterns just to satisfy policy theater.
- Allow spaces and Unicode in passwords unless a specific implementation constraint forces a narrower scope.
- Normalize email before lookup so registration and sign-in are consistent with `User.email_normalized`.
- Store local password hashes in `Account.password_hash`, not on the user record, so local credentials remain one account type within a broader multi-provider model.
- Hash passwords with Argon2id using the settings already exposed in `core/config.py`.
- Reject known-compromised or weak passwords if PyAuth later adds a blocklist or breach-checking integration.
- Use generic sign-in and reset-request responses to reduce account enumeration.
- Treat password reset as a verification flow: generate a CSPRNG token, store only its hash, set a short expiry, consume it once, and require the user to authenticate again afterward.
- After a password reset, rotate or invalidate active sessions instead of silently keeping old sessions valid.

### Mapping to current code

- `Account.password_hash` is the natural home for local credential material.
- `VerificationPurpose.PASSWORD_RESET` and `Verification.token_hash` already fit a single-use reset token model.
- `core/config.py` already exposes `PasswordHashSettings` with Argon2id defaults, so the documentation can describe modern hashing without inventing new configuration.

## Session Management

### Recommended references

- `OWASP Session Management Cheat Sheet`
- MDN `Set-Cookie`
- MDN secure cookie configuration guidance
- `NIST SP 800-63B-4`
- `RFC 6265`
- Optional currentness note: `draft-ietf-httpbis-rfc6265bis`

### Keep, replace, or supplement

- Keep `RFC 6265`, but narrow its role to baseline cookie semantics and interoperability.
- Supplement it with OWASP and MDN because `RFC 6265` alone does not explain modern browser deployment expectations or secure session lifecycle rules.
- Add `NIST SP 800-63B-4` because it is the strongest identity-focused reference for session handling expectations.
- Mention `rfc6265bis` only as a currentness signal, not the primary citation, because it is still draft-stage rather than a final RFC.

### Why these references are stronger

`RFC 6265` dates from 2011. It remains relevant for cookie mechanics, but it does not carry the full modern story around `SameSite`, host-only cookie defaults, rotation, logout cleanup, or real browser behavior. OWASP and MDN fill that gap better for a production auth library.

`NIST SP 800-63B-4` also strengthens the story because it covers modern session expectations in the context of digital identity systems, rather than cookies in isolation.

### PyAuth implementation guidance

PyAuth should implement browser sessions with these rules:

- Use opaque random session tokens rather than exposing user data in the cookie value.
- Store only the token hash in persistence so a database leak does not immediately expose bearer tokens.
- Treat the server-side session record as the source of truth for expiry and invalidation, not the cookie alone.
- Default cookie settings to `Secure`, `HttpOnly`, and `SameSite=Lax`, matching the current direction already present in `core/config.py`.
- Prefer host-only cookies and a `__Host-` cookie naming convention when PyAuth exposes a concrete default session-cookie name.
- Require explicit opt-in for `SameSite=None`, and only with `Secure`.
- Rotate session identifiers after sensitive account events such as password reset, email-change completion, or privilege elevation.
- Make logout invalidate both the cookie and the backing session record.
- Avoid URL-carried session identifiers entirely for browser session mode.

### Mapping to current code

- `Session.token_hash` is already aligned with hashed opaque-session storage.
- `Session.expires_at` is the right place to enforce server-side session lifetime.
- `core/config.py` already exposes `CookieSettings` with `secure`, `http_only`, and `same_site`, so the implementation only needs to tighten defaults and behavior around them.

## Social Authentication

### Recommended references

- `RFC 6749`
- `RFC 7636`
- `RFC 9700`
- `RFC 9207`
- Optional: `RFC 8414`
- Google Identity documentation for web server OAuth and ID token verification
- GitHub OAuth documentation for authorization and user identity retrieval

### Keep, replace, or supplement

- Keep `RFC 6749` as the base OAuth 2.0 protocol reference.
- Keep `RFC 7636` as the normative PKCE reference.
- Supplement both with `RFC 9700`, which is the newer security best current practice and the strongest modern citation for OAuth hardening.
- Add `RFC 9207` because PyAuth's MVP is explicitly multi-provider, which makes issuer/provider mix-up defenses materially relevant.
- Add current provider docs because Google and GitHub each have practical rules for redirect matching, identity retrieval, and token validation that matter for implementation quality.

### Why these references are stronger

`RFC 9700` was published in January 2025 as the OAuth 2.0 security BCP. It updates older OAuth security guidance and reflects current attack models more directly than `RFC 6749` alone. `RFC 6749` still matters, but it is not strong enough by itself as a modern evidence citation.

Provider docs also matter because PyAuth's MVP is not building generic OAuth theory. It is implementing real Google and GitHub sign-in flows, and those providers define practical constraints around redirect URIs, supported PKCE behavior, and identity claims.

### PyAuth implementation guidance

PyAuth should implement social login with these rules:

- Use authorization code flow with PKCE `S256` for both Google and GitHub.
- Generate a one-time `state` value for every authorization attempt and consume it after callback verification.
- Identify provider accounts by provider subject, not by email address.
- Map Google users by `sub`, not by email.
- Map GitHub users by durable provider user ID, not by username or profile name.
- Treat email as a linking hint, not the primary identity key.
- Only auto-link a provider login to an existing PyAuth user when the provider supplies a verified email and the trust level is acceptable for that provider.
- Store provider tokens only when they are needed for follow-up API access; otherwise avoid persisting unnecessary third-party secrets.
- Validate the expected provider or issuer context on callback to reduce mix-up risk in multi-provider deployments.
- Require exact redirect URI handling and reject lax callback matching.

### Mapping to current code

- `Account.provider` plus `Account.provider_account_id` already gives PyAuth the correct storage key for external identities.
- The unique constraint on `(provider, provider_account_id)` in `adapters/sqlalchemy.py` is aligned with provider-subject-based identity.
- `User.email_verified` exists today, but social login should treat provider-reported verification carefully so PyAuth does not overstate local trust semantics.

## Email Verification

### Recommended references

- `OWASP Input Validation Cheat Sheet`
- `OWASP Authentication Cheat Sheet`
- `RFC 5321`
- Optional: `RFC 6531` and `RFC 6532` if PyAuth later documents internationalized email support

### Keep, replace, or supplement

- Replace `RFC 5322` as the primary reference for email verification.
- Use `RFC 5321` only as the protocol-level anchor for email delivery semantics and address handling context.
- Use OWASP as the primary practical reference because email verification is an ownership-proof flow, not just an address-format question.
- Only cite `RFC 6531` and `RFC 6532` if PyAuth explicitly claims support for internationalized email addresses.

### Why these references are stronger

`RFC 5322` describes internet message format. It is not the right authority for a mailbox-ownership proof flow. The main question in email verification is not "is this string syntactically email-like?" but "can this user prove control over the mailbox?" OWASP addresses that split directly and is therefore a stronger application-level reference.

### PyAuth implementation guidance

PyAuth should implement email verification with these rules:

- Separate lightweight email syntax validation from mailbox ownership proof.
- Prove ownership by sending a single-use code or link to the mailbox and requiring the user to return that proof.
- Store only a hash of the verification token in `Verification.token_hash`.
- Scope each token by purpose so email verification and password reset are not interchangeable.
- Expire tokens aggressively and consume them once.
- Mark `User.email_verified` only after successful proof of mailbox control.
- Reuse the same verification primitives for sign-up verification and sensitive email-change confirmation, while keeping the purpose explicit.

### Mapping to current code

- `VerificationPurpose.EMAIL_VERIFICATION` already models this flow cleanly.
- `Verification.identifier`, `token_hash`, `expires_at`, and `consumed_at` give PyAuth the core data needed for expiring single-use verification.
- `User.email_verified` is the final state flag that should only be set after token consumption succeeds.

## Currentness Summary

Phase 3 now relies on stronger and more current references than the earlier README version:

- `NIST SP 800-63B-4` replaces the older unspecific `NIST SP 800-63B` wording and reflects the 2025 revision.
- `RFC 9700` supplements older OAuth references with modern OAuth security best current practice.
- `RFC 6265` is retained, but no longer asked to do all the work alone for session guidance.
- `RFC 5322` is removed from the email-verification role because it is not the right standard for ownership proof.

## Practical MVP Outcome After Phase 3

Once Phase 3 is implemented according to this guidance, the MVP should look like this:

- A user can sign up with email and password, sign in, and reset their password using expiring single-use recovery tokens.
- Browser sessions are backed by the database, represented by opaque bearer tokens, and stored server-side as token hashes.
- A user can sign in with Google or GitHub through authorization code flow with PKCE and guarded account linking.
- A user can verify email ownership using a magic link or code backed by the same hashed verification-token system used for password recovery.
- The framework layer in Phase 4 can expose those capabilities without changing the core storage model.

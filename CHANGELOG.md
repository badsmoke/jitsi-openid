# Changelog

## 2.1.0

- Scope Jitsi redirects to the configured `JITSI_URL` host by appending room names as encoded path segments.
- Reject untrusted extra ID token audiences by default; use `TRUSTED_ID_TOKEN_AUDIENCES` for explicit allowlisting.
- Add configurable short-lived Jitsi JWTs via `JWT_MAX_AGE_SECONDS` with a 300 second default.
- Add IdP HTTP client timeouts via `HTTP_TIMEOUT_SECONDS` and `HTTP_CONNECT_TIMEOUT_SECONDS`.
- Add regression tests for room URL handling, JWT room/user claims, and JWT expiry.
- Document this repository as the maintained fork of the archived upstream project.
- Switch Docker image references to `badsmoke/jitsi-openid`.
- Consolidate CI workflows, run locked tests before Docker publishing, and publish the documented `latest` tag.

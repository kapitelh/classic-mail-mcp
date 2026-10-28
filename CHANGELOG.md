# Changelog

## 2.1.0 — 2026-10-28

- Recover readable HTML when a message has an empty plain-text alternative.
- Read large messages via bounded MIME body-part downloads instead of rejecting the entire message at 8 MiB.
- Add `textOffset` / `nextTextOffset` pagination and explicit `bodyLimited` reporting.
- Stream large-message attachments in 128 KiB chunks, with a 128 MiB decoded safety cap. Unknown decoded sizes remain `null` until the final chunk.
- Preserve read-only IMAP selection, UIDVALIDITY checks, account boundaries and sending limits.
- Add regression tests and real local TLS/IMAP tests for MIME-part downloads and byte-exact base64 reconstruction.
- Update compatible dependencies to resolve known npm audit findings.

## 2.0.0 — public preview

- General operator-configured IMAP and SMTP hosts, including mandatory STARTTLS.
- Local Docker/stdio and bearer HTTP modes, without a Google Cloud dependency at runtime.
- SQLite persistence for OAuth state, rate limits and send idempotency; Firestore for Cloud Run.
- Read-only default with six tools; explicit opt-in to all 21 mail tools.
- Google OAuth with browser/redirect/PKCE binding and separate access/refresh token-purpose records.
- Hidden-input configuration wizard, hardened Compose service, service landing page and English/German documentation.
- CI tests, Docker smoke checks and public-source checks.

This release begins a clean public source history. Private configurations and deployment artifacts are not included.

# TrustVault implementation scope

This file records the product and engineering scope used for the current
frontend/backend integration. It is documentation, not a system prompt or a
claim that every production concern is solved.

## Product scope

- Keep the charcoal, teal, and warm-cream design, vanilla frontend, Flask API,
  and SQLite persistence.
- Use actual API responses for login, registration, dashboard values, document
  listing, uploads, sharing, access revocation, and audit history.
- Keep authorization decisions on the server; frontend validation is only a
  usability aid.
- Show loading, empty, validation, API error, and network error states honestly.
- Keep implementation straightforward enough for a student project and explain
  local setup and limitations.

## Verification scope

The automated suite is `python -m unittest -v test_app`. It exercises the API
using isolated temporary SQLite databases and upload directories. Browser
smoke checks have exercised registration, login, dashboard data, upload/list,
two-account sharing, View and Download authorization, permission revocation,
form validation, loading/empty states, registration network failure, and
Documents/Audit network errors. Test outcomes and the limits of manual
verification are recorded in
[REQUIREMENTS.md](./REQUIREMENTS.md); these are local checks, not deployment
verification.

## Dated verification log

- **2026-10-24** — Continued the TrustVault integration verification, added a
  filename traversal regression test, completed the browser permission and
  network-error checks, reviewed security boundaries, and initialized a local
  Git repository. No remote repository was configured, so no hosted commit link
  or push is available.

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

## Dated work log and submission-readiness status

Only **two evidence-backed dated entries** can be documented from the available
project and session records. The assessment requires five, so that requirement
is **not yet met**. Earlier prompts, outputs, and incremental commit links
cannot be reconstructed reliably and are not invented here.

### 2026-10-24 — Integration and security verification

- **Request:** Finish browser checks for permission enforcement, revocation,
  and Documents/Audit network failures, and review the security controls.
- **Work and verification:** Added an upload filename-traversal regression
  test and updated the verification documentation. The API suite passed six
  tests. Manual browser checks observed HTTP 403 for a View-only download,
  HTTP 200 and the expected PDF for Download permission, and loss of shared
  access after revocation (the shared list became empty and a later view
  returned HTTP 404). Aborted Documents and Audit requests displayed the
  server-connection error without success toasts. An initial browser attempt
  did not complete; these outcomes are from the later completed checks.
- **Git evidence:** The repository has one initial local commit,
  `b907faa36ff7ed646dfd54d3e034f18b15c754c5`. It is not an incremental commit
  for this work. No GitHub remote or hosted commit link exists.

### 2026-10-24 — Submission-readiness audit

- **Request:** Check the prompt-entry requirement, documentation, Git state,
  and remote without publishing.
- **Work and verification:** Confirmed that only two evidence-backed dated
  entries were available and that the five-entry requirement remained unmet.
  Reran `python -m unittest -v test_app`; all six tests passed. Inspected the
  documentation, branch, working tree, ignore rules, and remotes.
- **Git evidence:** The latest commit remained
  `b907faa36ff7ed646dfd54d3e034f18b15c754c5`; no remote or hosted commit link
  was configured.

Keep future work entries contemporaneous and include commit links only after
the corresponding commits actually exist.

# TrustVault requirements and verification

Statuses below describe the checked-in local implementation. “Verified” means
covered by the automated API test suite, browser smoke checks, or both as noted;
it does not mean production-certified.

| Requirement | Implementation | Status / verification |
| --- | --- | --- |
| Register and prevent duplicate email | `POST /api/auth/register`; hashes passwords | Verified by `test_registration_duplicate_and_login` |
| Login and current-user session | Server-side random token; HttpOnly cookie; `/api/auth/me` | Verified by registration/login and browser smoke check |
| Logout | CSRF-protected session revocation and cookie clearing | Verified by `test_logout_invalidates_session_and_requires_csrf` |
| Dashboard | Authenticated live counts and recent activity | Browser smoke check returned account-specific values |
| Document listing | Authenticated owner-only query; frontend search/type filtering | Verified by upload/list tests and browser smoke check |
| Upload | 10 MB cap, extension/content checks, CSRF, DB metadata, disk file, audit event | Verified with valid PDF, invalid content, invalid extension, and missing CSRF |
| View details | Owner or active share; logged as an audit event | Verified with View permission |
| Download authorization | Owner or active Download permission only | Verified that View is denied and Download succeeds |
| Sharing | Owner-only; recipient must have an account; View/Download only | Verified by permission integration/security tests |
| Revoke permission | Only document owner can revoke; revoked share no longer grants access | Verified by sharing/revocation regression test |
| Audit history | Filterable history scoped to actor and document owner; no mutation routes | Verified by owner/recipient isolation tests and API method check |
| CSRF and cross-origin mutation defenses | CSRF header/cookie for authenticated writes; mismatched Origin rejected | Verified by missing-token and cross-origin tests |
| Path traversal protection | Frontend paths are constrained to allowed assets; uploads use sanitized display names and random storage names | Verified by traversal-style frontend request and upload filename regression tests |
| Network/empty/error states | API errors surfaced; list pages show loading, empty, and error states | Browser request interception verified Documents/Audit errors, no table rows, and no success toasts; registration network failure and loading/empty states checked manually |
| Frontend script syntax | `node --check` on all five JavaScript files | Passed in local validation |
| Python syntax | `python -m py_compile app.py test_app.py` | Passed in local validation |

## Test result

Latest automated test run:

```text
python -m unittest -v test_app
Ran 6 tests
OK
```

The tests run with temporary SQLite files and temporary upload directories, so
they do not rely on or modify the local application database. Browser smoke
tests covered account creation/login, authenticated dashboard data, document
upload/listing, two-account sharing, View-only download denial (HTTP 403),
Download-permission response (HTTP 200 with a 29-byte PDF body), revocation
through the UI, removal from the recipient's shared list, and denial after
revocation (HTTP 404). Browser request interception on both Documents and Audit
displayed the server-connection error, zero table rows, and no success toasts.
Registration network failure, validation, and loading/empty states were also
checked manually. JavaScript/Python syntax checks passed. These browser checks
are manual, separate from the six automated tests, and do not certify a
production deployment. The local Git repository has no configured remote, so
there is no hosted commit link or push status to report.

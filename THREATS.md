# TrustVault threat notes

This is a practical threat summary for the local student-project implementation,
not a formal penetration-test report.

| Threat | Current mitigation | Remaining limitation |
| --- | --- | --- |
| Password disclosure | Werkzeug password hashes; passwords are not returned by APIs | No password reset or login rate limiting |
| Session theft | Random opaque session token, server-side expiry, HttpOnly and SameSite cookie | Local HTTP does not use Secure cookies; deploy only behind HTTPS and enable secure cookies |
| Cross-site request forgery | CSRF cookie/header check for authenticated mutations; reject mismatched Origin | Login/register rely on JSON requests and same-origin policy; reverse-proxy deployments need careful origin configuration |
| Unauthorized document access | Every document operation checks owner or active permission server-side; revocation is checked against current active permission state | No administrator/organization role model |
| Unauthorized download | View permission cannot download; revoked shares immediately stop authorizing requests | A file already downloaded cannot be recalled |
| Malicious or oversized upload | 10 MB cap, extension allow-list, basic content-signature/Office ZIP checks, `secure_filename` for display names, and random stored filenames | Signature checks are not antivirus or full format parsing; no malware scanner or storage quota |
| SQL injection | SQLite queries use bound parameters | Continue using parameters for all future queries |
| Stored HTML/script injection | Rendered user/document strings use DOM `textContent` or JSON | Add a restrictive Content-Security-Policy before production and continue avoiding unsafe HTML insertion |
| Audit tampering or disclosure | No audit update/delete route; records are scoped to the actor and document owner | Local SQLite file access can alter logs; production needs restricted database access and tamper-evident/central audit storage |
| Network/service failure | API errors are surfaced to users; protected pages redirect on expired sessions | No retries, alerting, or availability guarantees |
| File disclosure through static serving | Backend only serves frontend asset extensions; uploaded files are not public static assets | Production storage should be outside the web root with deployment-level access controls |

## Data and deployment boundaries

Passwords use Werkzeug hashing; raw passwords are only sent over the local
same-origin HTTP connection during development and are not persisted in the
browser. The SQLite database and uploaded files live under ignored `instance/`.
Do not expose the Flask development server to the public internet.

For a real deployment, use HTTPS and secure cookies, configure secrets outside
source control, rate-limit authentication, scan uploads, validate formats with
trusted libraries, use protected persistent storage, back up data, and review
privacy/retention requirements. No production deployment or external security
assessment has been performed. A focused source review on 2026-10-24 found no
confirmed vulnerability in the authentication/session/CSRF, ownership,
permission, upload/path handling, or audit-access paths reviewed. This is not a
penetration test.

The automated regression suite also checks that traversal-style frontend paths
do not expose source files and that a traversal-style upload filename is
sanitized and stored only under the configured upload directory. Browser checks
verified View-only download denial, Download authorization, and immediate loss
of access after revocation.

# TrustVault

TrustVault is a student-project document vault built with vanilla HTML, CSS and
JavaScript, a Flask API, and SQLite. The Flask app serves both the frontend and
API from the same origin.

## Run locally

1. Install Python 3.10 or later.
2. From the project folder, install Flask:

   ```powershell
   python -m pip install -r requirements.txt
   ```

3. Start the local server:

   ```powershell
   python app.py
   ```

4. Open <http://127.0.0.1:5000/>, register an account, and log in. Do not open
   pages using `file://` or a separate static server: the frontend uses
   same-origin API calls and browser session cookies.

The first run creates `instance/trustvault.sqlite3` and `instance/uploads/`.
Both are ignored by Git. Create another account using a different email address
to test document sharing between users.

`.env.example` documents the supported environment settings. The app does not
load `.env` files automatically; set variables in the shell or deployment
environment. Keep real `.env` files and secrets out of version control.

## Features and endpoints

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `POST` | `/api/auth/register` | Register with a unique email and password hash |
| `POST` | `/api/auth/login` | Create a server-side session |
| `GET` | `/api/auth/me` | Return the current session user |
| `POST` | `/api/auth/logout` | Revoke the current session |
| `GET` | `/api/dashboard` | User-specific counts and recent activity |
| `GET` | `/api/documents` | List documents owned by the current user |
| `POST` | `/api/documents/upload` | Validate, store, and audit an upload |
| `POST` | `/api/documents/<id>/view` | Check access and record a view |
| `POST` | `/api/documents/<id>/download` | Download for owner or Download permission |
| `GET` | `/api/shared` | List active shares addressed to the current user |
| `GET` | `/api/permissions` | List active permissions on the current user's documents |
| `POST` | `/api/permissions` | Share with an existing account |
| `DELETE` | `/api/permissions/<id>` | Revoke a permission owned by the current user |
| `GET` | `/api/audit` | Search/filter history visible to the current user |
| `GET` | `/api/health` | Basic server health check |

Search and file-type filtering on document tables is applied to live API results.
The audit filters query the API. An upload is only reported successful after the
server returns a created document record.

## Security notes

- Passwords are stored using Werkzeug's password hashing functions.
- Sessions are random opaque tokens stored hashed in SQLite; the cookie is
  `HttpOnly` and `SameSite=Lax`. The CSRF token is sent in a request header.
- Mutating API requests reject a mismatched browser Origin when supplied.
- The server enforces ownership, active sharing permissions, and View versus
  Download access independently of the UI.
- Uploads are limited to 10 MB and allowed extensions; basic PDF/image signatures
  and Office ZIP contents are checked. Files are stored under random names and
  are not served as public static files.
- Audit history can only be appended by backend events; no user-facing edit or
  delete API exists.

This is an educational local starter, not production-ready. Production use
requires HTTPS with secure cookies, malware scanning, stronger file-content
validation, backups, rate limiting, deployment configuration, and monitoring.

## Validation

Run the backend integration/security tests:

```powershell
python -m unittest -v test_app
```

The tests use temporary databases and files. The latest run on 2026-10-24
passed all 6 tests. They cover registration and duplicate accounts,
login/session/logout, authentication and CSRF requirements, cross-origin
writes, upload validation and filename traversal, owner isolation,
View/Download permissions, revocation, and audit access. JavaScript/Python
syntax validation:

```powershell
node --check js\api.js
node --check js\app.js
node --check js\auth.js
node --check js\documents.js
node --check js\upload.js
python -m py_compile app.py test_app.py
```

Browser verification on 2026-10-24 separately exercised the owner/recipient
permission flow: View permission returned HTTP 403 for a download, Download
permission returned HTTP 200 with the expected PDF body and attachment
filename, and revoking access removed the share and made a subsequent view
return HTTP 404. Aborted API requests on Documents and Audit displayed the
server-connection error with no success notification or table rows. Browser
checks are manual and are not part of the six automated tests.

See [REQUIREMENTS.md](./REQUIREMENTS.md) for feature coverage,
[THREATS.md](./THREATS.md) for boundaries and residual risks, and
[PROMPTS.md](./PROMPTS.md) for the implementation scope.

The project is initialized as a local Git repository. No remote is configured,
so no push or hosted commit link is available; connect the intended GitHub
repository before pushing.

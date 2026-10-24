import io
import sqlite3
import tempfile
import unittest
from pathlib import Path

import app as backend


class TrustVaultApiTests(unittest.TestCase):
    def setUp(self):
        self.original_paths = (backend.INSTANCE_DIR, backend.UPLOAD_DIR, backend.DATABASE_PATH)
        self.temp_dir = tempfile.TemporaryDirectory()
        temp_root = Path(self.temp_dir.name)
        backend.INSTANCE_DIR = temp_root
        backend.UPLOAD_DIR = temp_root / "uploads"
        backend.DATABASE_PATH = temp_root / "trustvault.sqlite3"
        backend.initialize_database()
        backend.app.config.update(TESTING=True)
        self.owner = backend.app.test_client()
        self.recipient = backend.app.test_client()
        self.create_account(self.owner, "Owner", "owner@example.com")
        self.create_account(self.recipient, "Recipient", "recipient@example.com")
        self.login(self.owner, "owner@example.com")

    def tearDown(self):
        backend.INSTANCE_DIR, backend.UPLOAD_DIR, backend.DATABASE_PATH = self.original_paths
        self.temp_dir.cleanup()

    def create_account(self, client, name, email):
        response = client.post(
            "/api/auth/register",
            json={"full_name": name, "email": email, "password": "StrongPass123"},
        )
        self.assertEqual(response.status_code, 201)

    def login(self, client, email):
        response = client.post(
            "/api/auth/login",
            json={"email": email, "password": "StrongPass123"},
        )
        self.assertEqual(response.status_code, 200)
        return client.get_cookie("tv_csrf").value

    def csrf_headers(self, client):
        return {"X-CSRF-Token": client.get_cookie("tv_csrf").value}

    def upload_pdf(self):
        return self.owner.post(
            "/api/documents/upload",
            data={"file": (io.BytesIO(b"%PDF-1.4 test document"), "report.pdf")},
            headers=self.csrf_headers(self.owner),
            content_type="multipart/form-data",
        )

    def test_registration_duplicate_and_login(self):
        self.assertEqual(self.owner.get("/api/health").status_code, 200)
        self.assertEqual(self.owner.get("/app.py").status_code, 404)
        self.assertEqual(self.owner.get("/%2e%2e/app.py").status_code, 404)
        self.assertEqual(self.owner.get("/.gitignore").status_code, 404)
        self.assertEqual(backend.app.test_client().get("/api/documents").status_code, 401)
        self.assertEqual(self.owner.post("/api/auth/register", json=[]).status_code, 400)
        cross_origin = backend.app.test_client().post(
            "/api/auth/register",
            json={"full_name": "Bad Origin", "email": "bad@example.com", "password": "StrongPass123"},
            headers={"Origin": "https://attacker.example"},
        )
        self.assertEqual(cross_origin.status_code, 403)
        duplicate = self.owner.post(
            "/api/auth/register",
            json={"full_name": "Duplicate", "email": "OWNER@example.com", "password": "StrongPass123"},
        )
        self.assertEqual(duplicate.status_code, 409)

        response = self.owner.get("/api/auth/me")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["user"]["email"], "owner@example.com")
        database = sqlite3.connect(backend.DATABASE_PATH)
        password_hash = database.execute(
            "SELECT password_hash FROM users WHERE email = ?",
            ("owner@example.com",),
        ).fetchone()[0]
        database.close()
        self.assertNotEqual(password_hash, "StrongPass123")
        self.assertTrue(self.owner.get_cookie("tv_session").http_only)
        self.assertEqual(self.owner.get_cookie("tv_session").same_site, "Lax")

    def test_logout_invalidates_session_and_requires_csrf(self):
        missing_csrf = self.owner.post("/api/auth/logout")
        self.assertEqual(missing_csrf.status_code, 403)

        logout = self.owner.post("/api/auth/logout", headers=self.csrf_headers(self.owner))
        self.assertEqual(logout.status_code, 200)
        self.assertEqual(self.owner.get("/api/auth/me").status_code, 401)

    def test_ownership_share_revoke_and_audit_boundaries(self):
        uploaded = self.upload_pdf()
        document_id = uploaded.json["document"]["id"]
        self.login(self.recipient, "recipient@example.com")

        self.assertEqual(self.recipient.get("/api/documents").json["documents"], [])
        foreign_share = self.recipient.post(
            "/api/permissions",
            json={
                "document_id": document_id,
                "recipient_email": "owner@example.com",
                "permission": "Download",
            },
            headers=self.csrf_headers(self.recipient),
        )
        self.assertEqual(foreign_share.status_code, 404)
        self.assertEqual(self.recipient.get("/api/audit").json["events"], [])
        self.assertEqual(self.recipient.put("/api/audit").status_code, 405)

        share = self.owner.post(
            "/api/permissions",
            json={
                "document_id": document_id,
                "recipient_email": "recipient@example.com",
                "permission": "View",
            },
            headers=self.csrf_headers(self.owner),
        )
        self.assertEqual(share.status_code, 201)
        permission_id = self.owner.get("/api/permissions").json["permissions"][0]["id"]
        forbidden_revoke = self.recipient.delete(
            f"/api/permissions/{permission_id}",
            headers=self.csrf_headers(self.recipient),
        )
        self.assertEqual(forbidden_revoke.status_code, 404)

        owner_audit = self.owner.get("/api/audit").json["events"]
        self.assertTrue(any(event["action"] == "Share" for event in owner_audit))
        invalid_filter = self.owner.get("/api/audit?action=Delete")
        self.assertEqual(invalid_filter.status_code, 400)

    def test_upload_validates_csrf_type_and_content(self):
        no_csrf = self.owner.post(
            "/api/documents/upload",
            data={"file": (io.BytesIO(b"%PDF-1.4 test document"), "report.pdf")},
            content_type="multipart/form-data",
        )
        self.assertEqual(no_csrf.status_code, 403)

        invalid_content = self.owner.post(
            "/api/documents/upload",
            data={"file": (io.BytesIO(b"not a pdf"), "report.pdf")},
            headers=self.csrf_headers(self.owner),
            content_type="multipart/form-data",
        )
        self.assertEqual(invalid_content.status_code, 400)

        invalid_extension = self.owner.post(
            "/api/documents/upload",
            data={"file": (io.BytesIO(b"not allowed"), "malware.exe")},
            headers=self.csrf_headers(self.owner),
            content_type="multipart/form-data",
        )
        self.assertEqual(invalid_extension.status_code, 400)

        oversized = self.owner.post(
            "/api/documents/upload",
            data={
                "file": (
                    io.BytesIO(b"%PDF-1.4" + (b"x" * backend.MAX_UPLOAD_BYTES)),
                    "oversized.pdf",
                )
            },
            headers=self.csrf_headers(self.owner),
            content_type="multipart/form-data",
        )
        self.assertEqual(oversized.status_code, 413)

        uploaded = self.upload_pdf()
        self.assertEqual(uploaded.status_code, 201)
        self.assertEqual(len(self.owner.get("/api/documents").json["documents"]), 1)

    def test_upload_filename_cannot_escape_storage_directory(self):
        response = self.owner.post(
            "/api/documents/upload",
            data={"file": (io.BytesIO(b"%PDF-1.4 path test"), "../../escaped.pdf")},
            headers=self.csrf_headers(self.owner),
            content_type="multipart/form-data",
        )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json["document"]["name"], "escaped.pdf")
        self.assertEqual(len(list(backend.UPLOAD_DIR.iterdir())), 1)
        self.assertFalse((backend.INSTANCE_DIR / "escaped.pdf").exists())

    def test_sharing_permissions_and_revoke(self):
        uploaded = self.upload_pdf()
        self.assertEqual(uploaded.status_code, 201)
        document_id = uploaded.json["document"]["id"]

        shared = self.owner.post(
            "/api/permissions",
            json={
                "document_id": document_id,
                "recipient_email": "recipient@example.com",
                "permission": "View",
            },
            headers=self.csrf_headers(self.owner),
        )
        self.assertEqual(shared.status_code, 201)
        self.login(self.recipient, "recipient@example.com")

        self.assertEqual(len(self.recipient.get("/api/shared").json["documents"]), 1)
        csrf = self.csrf_headers(self.recipient)
        denied_download = self.recipient.post(f"/api/documents/{document_id}/download", headers=csrf)
        self.assertEqual(denied_download.status_code, 403)
        viewed = self.recipient.post(f"/api/documents/{document_id}/view", headers=csrf)
        self.assertEqual(viewed.status_code, 200)

        upgraded = self.owner.post(
            "/api/permissions",
            json={
                "document_id": document_id,
                "recipient_email": "recipient@example.com",
                "permission": "Download",
            },
            headers=self.csrf_headers(self.owner),
        )
        self.assertEqual(upgraded.status_code, 201)
        download = self.recipient.post(
            f"/api/documents/{document_id}/download",
            headers=self.csrf_headers(self.recipient),
        )
        self.assertEqual(download.status_code, 200)
        download.close()

        permission_id = self.owner.get("/api/permissions").json["permissions"][0]["id"]
        revoked = self.owner.delete(
            f"/api/permissions/{permission_id}",
            headers=self.csrf_headers(self.owner),
        )
        self.assertEqual(revoked.status_code, 200)
        self.assertEqual(self.recipient.get("/api/shared").json["documents"], [])
        revoked_view = self.recipient.post(
            f"/api/documents/{document_id}/view",
            headers=self.csrf_headers(self.recipient),
        )
        self.assertEqual(revoked_view.status_code, 404)


if __name__ == "__main__":
    unittest.main()

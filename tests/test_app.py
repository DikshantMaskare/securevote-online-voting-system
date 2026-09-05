from __future__ import annotations

import os
import re
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path


class SecureVoteFlowTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_directory = tempfile.TemporaryDirectory()
        cls.data_directory = Path(cls.temp_directory.name)

        os.environ.update(
            {
                "DATA_DIR": str(cls.data_directory),
                "FLASK_SECRET_KEY": "test-secret-key-for-securevote",
                "ADMIN_USERNAME": "testadmin",
                "ADMIN_PASSWORD": "test-admin-password",
                "ALLOW_DEV_OTP": "1",
                "SESSION_COOKIE_SECURE": "0",
            }
        )

        repository_root = Path(__file__).resolve().parents[1]
        sys.path.insert(0, str(repository_root))

        import app as securevote

        cls.securevote = securevote
        cls.securevote.app.config.update(
            TESTING=True,
            WTF_CSRF_ENABLED=False,
        )

    @classmethod
    def tearDownClass(cls):
        cls.temp_directory.cleanup()

    def extract_otp(self, response) -> str:
        match = re.search(
            rb"your OTP is (\d{6})",
            response.data,
        )
        self.assertIsNotNone(match)
        return match.group(1).decode("ascii")

    def test_complete_voting_and_admin_flow(self):
        client = self.securevote.app.test_client()

        health = client.get("/health")
        self.assertEqual(health.status_code, 200)
        self.assertEqual(health.get_json()["status"], "healthy")

        registration = client.post(
            "/register",
            data={
                "full_name": "Demo Voter",
                "email": "demo.voter@example.com",
            },
            follow_redirects=True,
        )
        registration_otp = self.extract_otp(registration)

        verified = client.post(
            "/verify-registration-otp",
            data={"otp": registration_otp},
            follow_redirects=True,
        )
        self.assertIn(b"Registration complete", verified.data)

        with sqlite3.connect(
            self.data_directory / "voting.db"
        ) as connection:
            voter_id = connection.execute(
                "SELECT voter_id FROM voters WHERE email = ?",
                ("demo.voter@example.com",),
            ).fetchone()[0]

        self.assertRegex(voter_id, r"^VOT[A-F0-9]{16}$")

        login = client.post(
            "/login",
            data={
                "voter_id": voter_id,
                "email": "demo.voter@example.com",
            },
            follow_redirects=True,
        )
        login_otp = self.extract_otp(login)

        ballot = client.post(
            "/login-otp",
            data={"otp": login_otp},
            follow_redirects=True,
        )
        self.assertIn(b"Cast your vote", ballot.data)

        receipt = client.post(
            "/vote",
            data={"candidate_id": "C2"},
            follow_redirects=True,
        )
        self.assertIn(b"Vote submitted successfully", receipt.data)

        second_vote = client.post(
            "/vote",
            data={"candidate_id": "C1"},
            follow_redirects=True,
        )
        self.assertIn(b"already voted", second_vote.data)

        client.get("/logout")

        dashboard = client.post(
            "/admin/login",
            data={
                "username": "testadmin",
                "password": "test-admin-password",
            },
            follow_redirects=True,
        )
        self.assertIn(b"Administrative Dashboard", dashboard.data)
        self.assertIn(b"Ledger integrity", dashboard.data)

    def test_otp_is_not_exposed_when_dev_fallback_is_disabled(self):
        client = self.securevote.app.test_client()
        previous_value = self.securevote.ALLOW_DEV_OTP
        self.securevote.ALLOW_DEV_OTP = False

        try:
            response = client.post(
                "/register",
                data={
                    "full_name": "Production Demo",
                    "email": "production.demo@example.com",
                },
                follow_redirects=True,
            )

            self.assertNotIn(b"your OTP is", response.data)
            self.assertIn(b"Unable to send the OTP", response.data)

            with sqlite3.connect(
                self.data_directory / "voting.db"
            ) as connection:
                otp_code = connection.execute(
                    "SELECT otp_code FROM voters WHERE email = ?",
                    ("production.demo@example.com",),
                ).fetchone()[0]

            self.assertIsNone(otp_code)

        finally:
            self.securevote.ALLOW_DEV_OTP = previous_value


if __name__ == "__main__":
    unittest.main()

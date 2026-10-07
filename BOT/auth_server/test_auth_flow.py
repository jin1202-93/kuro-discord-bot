import os
from pathlib import Path
import sqlite3
import tempfile
import unittest

from fastapi import HTTPException

from auth_server.app import RedeemRequest, VerifyRequest, health_check, redeem, verify
from auth_server.database import (
    initialize_database,
    register_code,
    reset_device,
    revoke_user,
)


class AuthFlowTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.previous_database_path = os.environ.get("AUTH_DB_PATH")
        os.environ["AUTH_DB_PATH"] = str(Path(self.temp_dir.name) / "auth.sqlite3")
        initialize_database()
        self.user_id = "discord-test-user"
        self.first_device = "device-test-0000000000001"
        self.second_device = "device-test-0000000000002"

    def tearDown(self):
        if self.previous_database_path is None:
            os.environ.pop("AUTH_DB_PATH", None)
        else:
            os.environ["AUTH_DB_PATH"] = self.previous_database_path
        self.temp_dir.cleanup()

    def test_code_is_one_time_and_session_is_device_bound(self):
        first_code = "KURO-TEST-USER-0001"
        register_code(self.user_id, first_code)
        token = redeem(
            RedeemRequest(
                code=first_code,
                device_id=self.first_device,
            )
        )["access_token"]
        result = verify(
            VerifyRequest(device_id=self.first_device),
            f"Bearer {token}",
        )
        self.assertTrue(result["authorized"])
        self.assertEqual(result["discord_user_id"], self.user_id)

        with self.assertRaises(HTTPException) as replay_error:
            second_code = "KURO-TEST-USER-0002"
            register_code(self.user_id, second_code)
            redeem(
                RedeemRequest(
                    code=second_code,
                    device_id=self.second_device,
                )
            )
        self.assertEqual(replay_error.exception.status_code, 403)

        with self.assertRaises(HTTPException) as reuse_error:
            redeem(
                RedeemRequest(
                    code=first_code,
                    device_id=self.first_device,
                )
            )
        self.assertEqual(reuse_error.exception.status_code, 401)

    def test_reset_allows_rebinding_and_revoke_invalidates_session(self):
        first_code = "KURO-RESET-USER-0001"
        register_code(self.user_id, first_code)
        first_token = redeem(
            RedeemRequest(
                code=first_code,
                device_id=self.first_device,
            )
        )["access_token"]
        reset_device(self.user_id)
        second_code = "KURO-RESET-USER-0002"
        register_code(self.user_id, second_code)
        second_token = redeem(
            RedeemRequest(
                code=second_code,
                device_id=self.second_device,
            )
        )["access_token"]
        self.assertTrue(
            verify(
                VerifyRequest(device_id=self.second_device),
                f"Bearer {second_token}",
            )["authorized"]
        )

        revoke_user(self.user_id)
        with self.assertRaises(HTTPException) as revoke_error:
            verify(
                VerifyRequest(device_id=self.second_device),
                f"Bearer {second_token}",
            )
        self.assertEqual(revoke_error.exception.status_code, 401)
        with self.assertRaises(HTTPException):
            verify(
                VerifyRequest(device_id=self.first_device),
                f"Bearer {first_token}",
            )

    def test_unregistered_code_is_rejected(self):
        with self.assertRaises(HTTPException) as error:
            redeem(
                RedeemRequest(
                    code="KURO-NOT-REGISTERED",
                    device_id=self.first_device,
                )
            )
        self.assertEqual(error.exception.status_code, 401)

    def test_codes_are_hashed_and_duplicates_are_rejected(self):
        code = "KURO-PRIVATE-CODE-001"
        register_code(self.user_id, code)
        with self.assertRaises(ValueError):
            register_code("another-user", code.lower())
        with sqlite3.connect(os.environ["AUTH_DB_PATH"]) as connection:
            stored_hash = connection.execute(
                "SELECT code_hash FROM auth_codes"
            ).fetchone()[0]
        self.assertNotEqual(code, stored_hash)

    def test_code_format_and_expiry_are_validated(self):
        with self.assertRaises(ValueError):
            register_code(self.user_id, "SHORT")
        with self.assertRaises(ValueError):
            register_code(self.user_id, "KURO-TOO-LONG-EXPIRY", expires_days=366)

    def test_health_check(self):
        self.assertEqual(health_check(), {"ok": True})


if __name__ == "__main__":
    unittest.main()

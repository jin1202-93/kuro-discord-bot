import base64
import os
from pathlib import Path
import sqlite3
import tempfile
import time
from threading import Event
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from fastapi import HTTPException
import discord
from core.auth_client import (
    AuthenticationError,
    LicenseMonitor,
    license_tier_allows,
)
from core.app_updater import UpdateError, update_state
from auth_server.bot import _is_admin, create_bot

from auth_server.app import RedeemRequest, VerifyRequest, health_check, redeem, verify
from auth_server.database import (
    clear_app_update,
    get_app_update,
    get_pending_code,
    initialize_database,
    get_license_status,
    issue_code,
    reset_device,
    revoke_user,
    resolve_license_id,
    set_license_nickname,
    set_license_tier,
    set_app_update,
)


class AuthFlowTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.previous_database_path = os.environ.get("AUTH_DB_PATH")
        self.previous_code_encryption_key = os.environ.get("CODE_ENCRYPTION_KEY")
        os.environ["AUTH_DB_PATH"] = str(Path(self.temp_dir.name) / "auth.sqlite3")
        os.environ["CODE_ENCRYPTION_KEY"] = base64.urlsafe_b64encode(
            b"0" * 32
        ).decode("ascii")
        initialize_database()
        self.first_device = "device-test-0000000000001"
        self.second_device = "device-test-0000000000002"

    def tearDown(self):
        if self.previous_database_path is None:
            os.environ.pop("AUTH_DB_PATH", None)
        else:
            os.environ["AUTH_DB_PATH"] = self.previous_database_path
        if self.previous_code_encryption_key is None:
            os.environ.pop("CODE_ENCRYPTION_KEY", None)
        else:
            os.environ["CODE_ENCRYPTION_KEY"] = self.previous_code_encryption_key
        self.temp_dir.cleanup()

    def test_code_is_one_time_and_session_is_device_bound(self):
        first_code, license_id = issue_code()
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
        self.assertEqual(result["license_id"], license_id)

        with self.assertRaises(HTTPException) as other_device_error:
            verify(
                VerifyRequest(device_id=self.second_device),
                f"Bearer {token}",
            )
        self.assertEqual(other_device_error.exception.status_code, 401)

        with self.assertRaises(HTTPException) as reuse_error:
            redeem(
                RedeemRequest(
                    code=first_code,
                    device_id=self.first_device,
                )
            )
        self.assertEqual(reuse_error.exception.status_code, 401)

    def test_reset_allows_rebinding_and_revoke_invalidates_session(self):
        first_code, license_id = issue_code()
        first_token = redeem(
            RedeemRequest(
                code=first_code,
                device_id=self.first_device,
            )
        )["access_token"]
        second_code = reset_device(license_id)
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

        revoke_user(license_id)
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
        code, _license_id = issue_code()
        with sqlite3.connect(os.environ["AUTH_DB_PATH"]) as connection:
            stored_hash = connection.execute(
                "SELECT code_hash FROM auth_codes"
            ).fetchone()[0]
        self.assertNotEqual(code, stored_hash)

    def test_verify_updates_online_presence_and_stales_after_90_seconds(self):
        code, license_id = issue_code()
        token = redeem(
            RedeemRequest(code=code, device_id=self.first_device)
        )["access_token"]

        self.assertTrue(get_license_status(license_id)["online"])
        verify(
            VerifyRequest(device_id=self.first_device),
            f"Bearer {token}",
        )
        status = get_license_status(license_id)
        self.assertTrue(status["online"])
        self.assertIsNotNone(status["last_seen_at"])

        with sqlite3.connect(os.environ["AUTH_DB_PATH"]) as connection:
            connection.execute(
                "UPDATE licenses SET last_seen_at = ? WHERE license_id = ?",
                (time.time() - 91, license_id),
            )
        self.assertFalse(get_license_status(license_id)["online"])

    def test_code_format_and_expiry_are_validated(self):
        code, license_id = issue_code()
        self.assertRegex(code, r"^(?:[A-HJ-NP-Z2-9]{4}-){5}[A-HJ-NP-Z2-9]{4}$")
        self.assertRegex(license_id, r"^[A-F0-9]{16}$")
        with self.assertRaises(ValueError):
            issue_code(expires_days=366)

    def test_pending_code_is_retrievable_by_id_or_nickname_only_before_use(self):
        code, license_id = issue_code(nickname="테스터 A")
        self.assertEqual(get_pending_code(license_id)["code"], code)
        self.assertEqual(get_pending_code("테스터 A")["license_id"], license_id)

        token = redeem(
            RedeemRequest(code=code, device_id=self.first_device)
        )["access_token"]
        with self.assertRaisesRegex(ValueError, "미사용 코드"):
            get_pending_code(license_id)
        with sqlite3.connect(os.environ["AUTH_DB_PATH"]) as connection:
            encrypted_code = connection.execute(
                "SELECT code_encrypted FROM auth_codes"
            ).fetchone()[0]
        self.assertIsNone(encrypted_code)
        self.assertTrue(token)

    def test_reset_device_reissues_retrievable_code(self):
        _old_code, license_id = issue_code(nickname="재발급 대상")
        new_code = reset_device(license_id)
        self.assertEqual(get_pending_code("재발급 대상")["code"], new_code)

    def test_license_management_accepts_unique_nickname(self):
        _code, license_id = issue_code(nickname="별명 사용자")
        self.assertEqual(resolve_license_id("별명 사용자"), license_id)
        self.assertEqual(
            set_license_tier("별명 사용자", "premium")["tier"],
            "premium",
        )
        set_license_nickname("별명 사용자", "새 별명")
        new_code = reset_device("새 별명")
        self.assertEqual(get_pending_code("새 별명")["code"], new_code)
        revoke_user("새 별명")
        self.assertFalse(get_license_status("새 별명")["active"])

        issue_code(nickname="중복 별명")
        issue_code(nickname="중복 별명")
        with self.assertRaisesRegex(ValueError, "같은 별명"):
            resolve_license_id("중복 별명")

    def test_tiers_and_admin_nickname_flow(self):
        code, license_id = issue_code(
            tier="premium",
            nickname="테스터 A",
        )
        self.assertEqual(license_tier_allows("basic", "level_hunt_movement"), False)
        self.assertTrue(license_tier_allows("premium", "level_hunt_movement"))
        self.assertTrue(license_tier_allows("basic", "ordinary_boss_move"))

        redeem_result = redeem(
            RedeemRequest(code=code, device_id=self.first_device)
        )
        self.assertEqual(redeem_result["tier"], "premium")
        status = get_license_status(license_id)
        self.assertEqual(status["nickname"], "테스터 A")

        set_license_nickname(license_id, "사람 1")
        status = set_license_tier(license_id, "basic")
        self.assertEqual(status["nickname"], "사람 1")
        self.assertEqual(status["tier"], "basic")

        with self.assertRaises(ValueError):
            set_license_nickname(license_id, " " * 2)
        with self.assertRaises(ValueError):
            set_license_tier(license_id, "gold")

    def test_unlimited_code_and_session_last_until_revoked(self):
        code, license_id = issue_code(expires_days=0)
        token = redeem(
            RedeemRequest(code=code, device_id=self.first_device)
        )["access_token"]

        with sqlite3.connect(os.environ["AUTH_DB_PATH"]) as connection:
            code_expiry, used = connection.execute(
                "SELECT expires_at, used FROM auth_codes"
            ).fetchone()
            session_expiry = connection.execute(
                "SELECT expires_at FROM sessions"
            ).fetchone()[0]
        self.assertIsNone(code_expiry)
        self.assertEqual(used, 1)
        self.assertIsNone(session_expiry)
        self.assertEqual(
            verify(
                VerifyRequest(device_id=self.first_device),
                f"Bearer {token}",
            )["license_id"],
            license_id,
        )

        revoke_user(license_id)
        with self.assertRaises(HTTPException):
            verify(
                VerifyRequest(device_id=self.first_device),
                f"Bearer {token}",
            )

    def test_health_check(self):
        self.assertEqual(health_check(), {"ok": True})

    def test_app_update_policy_is_validated_and_returned_by_verify(self):
        policy = set_app_update(
            "1.2.3",
            "0.0.0",
            "https://example.com/KURO_HELPER.zip",
            "a" * 64,
            "안정성 개선",
        )
        self.assertEqual(policy["version"], "1.2.3")
        self.assertEqual(policy["minimum_version"], "0.0.0")
        self.assertEqual(get_app_update(), policy)

        code, _license_id = issue_code()
        token = redeem(
            RedeemRequest(code=code, device_id=self.first_device)
        )["access_token"]
        result = verify(
            VerifyRequest(device_id=self.first_device),
            f"Bearer {token}",
        )
        self.assertEqual(result["app_update"], policy)

        with self.assertRaises(ValueError):
            set_app_update(
                "1.2.3",
                "2.0.0",
                "https://example.com/KURO_HELPER.zip",
                "a" * 64,
            )
        with self.assertRaises(ValueError):
            set_app_update(
                "1.2.3",
                "0.0.0",
                "http://example.com/KURO_HELPER.zip",
                "a" * 64,
            )

        clear_app_update()
        self.assertIsNone(get_app_update())

    def test_app_update_state_distinguishes_optional_and_required(self):
        policy = {
            "version": "1.2.0",
            "minimum_version": "1.1.0",
            "download_url": "https://example.com/KURO_HELPER.zip",
            "sha256": "a" * 64,
        }
        self.assertEqual(update_state(policy, "1.0.9"), "required")
        self.assertEqual(update_state(policy, "1.1.0"), "optional")
        self.assertIsNone(update_state(policy, "1.2.0"))
        with self.assertRaises(UpdateError):
            update_state({**policy, "download_url": "http://example.com/file.zip"})

    def test_admin_check_reads_member_permissions_and_configured_role(self):
        administrator = SimpleNamespace(
            user=SimpleNamespace(
                guild_permissions=SimpleNamespace(administrator=True),
                roles=[],
            )
        )
        role_admin = SimpleNamespace(
            user=SimpleNamespace(
                guild_permissions=SimpleNamespace(administrator=False),
                roles=[SimpleNamespace(id=42)],
            )
        )
        non_admin = SimpleNamespace(
            user=SimpleNamespace(roles=[])
        )

        self.assertTrue(_is_admin(administrator, 42))
        self.assertTrue(_is_admin(role_admin, 42))
        self.assertFalse(_is_admin(non_admin, 42))

    def test_discord_commands_include_code_retrieval_and_update_management(self):
        with patch.dict(
            os.environ,
            {
                "DISCORD_BOT_TOKEN": "test-token",
                "DISCORD_GUILD_ID": "123456789012345678",
                "DISCORD_ADMIN_ROLE_ID": "234567890123456789",
            },
        ):
            bot, _token = create_bot()
        commands = {
            command.name
            for command in bot.tree.get_commands(
                guild=discord.Object(id=bot.guild_id)
            )
        }
        self.assertIn("getcode", commands)
        self.assertIn("setappupdate", commands)
        self.assertIn("clearappupdate", commands)

    def test_license_monitor_notifies_when_server_revokes_session(self):
        revoked = Event()
        monitor = LicenseMonitor(revoked.set, interval_seconds=0.01)
        with (
            patch("core.auth_client._load_api_url", return_value="https://auth.test"),
            patch("core.auth_client._get_machine_id", return_value=self.first_device),
            patch("core.auth_client._read_saved_token", return_value="saved-token"),
            patch(
                "core.auth_client._request",
                side_effect=AuthenticationError("revoked", status_code=401),
            ),
        ):
            monitor.start()
            try:
                self.assertTrue(revoked.wait(timeout=1))
            finally:
                monitor.stop()

    def test_license_monitor_notifies_when_tier_changes(self):
        tier_changed = Event()
        observed_tiers = []

        def on_tier_changed(tier):
            observed_tiers.append(tier)
            tier_changed.set()

        monitor = LicenseMonitor(
            lambda: None,
            interval_seconds=0.01,
            on_tier_changed=on_tier_changed,
            initial_tier="basic",
        )
        with (
            patch("core.auth_client._load_api_url", return_value="https://auth.test"),
            patch("core.auth_client._get_machine_id", return_value=self.first_device),
            patch("core.auth_client._read_saved_token", return_value="saved-token"),
            patch(
                "core.auth_client._request",
                return_value={"authorized": True, "tier": "premium"},
            ),
        ):
            monitor.start()
            try:
                self.assertTrue(tier_changed.wait(timeout=1))
                self.assertEqual(observed_tiers, ["premium"])
            finally:
                monitor.stop()

    def test_license_monitor_notifies_when_update_becomes_required(self):
        update_required = Event()
        observed_versions = []

        def on_forced_update(version):
            observed_versions.append(version)
            update_required.set()

        monitor = LicenseMonitor(
            lambda: None,
            interval_seconds=0.01,
            on_forced_update=on_forced_update,
        )
        policy = {
            "version": "1.2.0",
            "minimum_version": "1.1.0",
            "download_url": "https://example.com/KURO_HELPER.zip",
            "sha256": "a" * 64,
        }
        with (
            patch("core.auth_client._load_api_url", return_value="https://auth.test"),
            patch("core.auth_client._get_machine_id", return_value=self.first_device),
            patch("core.auth_client._read_saved_token", return_value="saved-token"),
            patch(
                "core.auth_client._request",
                return_value={
                    "authorized": True,
                    "tier": "basic",
                    "app_update": policy,
                },
            ),
        ):
            monitor.start()
            try:
                self.assertTrue(update_required.wait(timeout=1))
                self.assertEqual(observed_versions, ["1.2.0"])
            finally:
                monitor.stop()


if __name__ == "__main__":
    unittest.main()

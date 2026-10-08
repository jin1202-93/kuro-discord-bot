import base64
import os
from pathlib import Path
import sqlite3
import tempfile
import time
import zipfile
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
from core.app_updater import UpdateError, _extract_package, update_state
from core.equipment_window_controls import ensure_equipment_window_open
from core.multi_character_tester import MultiCharacterTester
from pynput.keyboard import Key
from auth_server.bot import _is_admin, create_bot
from ui.main_window import KuroHelper

from auth_server.app import RedeemRequest, VerifyRequest, health_check, redeem, verify
from auth_server.database import (
    clear_app_update,
    get_app_update,
    get_pending_code,
    initialize_database,
    get_license_status,
    issue_code,
    reset_device,
    set_license_session_expiry,
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

    def test_set_license_session_expiry_updates_current_sessions(self):
        code, license_id = issue_code(expires_days=5)
        token = redeem(
            RedeemRequest(code=code, device_id=self.first_device)
        )["access_token"]

        self.assertEqual(set_license_session_expiry(license_id, 90), license_id)
        connection = sqlite3.connect(os.environ["AUTH_DB_PATH"])
        try:
            expires_at = connection.execute(
                "SELECT expires_at FROM sessions WHERE license_id = ?",
                (license_id,),
            ).fetchone()
        finally:
            connection.close()
        self.assertAlmostEqual(expires_at[0], time.time() + 90 * 24 * 60 * 60, delta=2)

        set_license_session_expiry(license_id, 0)
        connection = sqlite3.connect(os.environ["AUTH_DB_PATH"])
        try:
            expires_at = connection.execute(
                "SELECT expires_at FROM sessions WHERE license_id = ?",
                (license_id,),
            ).fetchone()[0]
        finally:
            connection.close()
        self.assertIsNone(expires_at)

        _unused_code, unused_license_id = issue_code()
        with self.assertRaisesRegex(ValueError, "인증 세션이 없습니다"):
            set_license_session_expiry(unused_license_id, 30)
        with self.assertRaises(ValueError):
            set_license_session_expiry(license_id, 366)
        self.assertTrue(
            verify(
                VerifyRequest(device_id=self.first_device),
                f"Bearer {token}",
            )["authorized"]
        )

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

    def test_partial_update_zip_accepts_assets_and_rejects_user_data(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            patch_archive = root / "asset-patch.zip"
            with zipfile.ZipFile(patch_archive, "w") as archive:
                archive.writestr(
                    "KURO_HELPER/assets/boss/new-template.png",
                    b"image",
                )
            payload = _extract_package(patch_archive, root / "extracted")
            self.assertEqual(
                (payload / "assets" / "boss" / "new-template.png").read_bytes(),
                b"image",
            )

            settings_archive = root / "settings-patch.zip"
            with zipfile.ZipFile(settings_archive, "w") as archive:
                archive.writestr("KURO_HELPER/settings.json", "{}")
            with self.assertRaisesRegex(UpdateError, "개인 설정"):
                _extract_package(settings_archive, root / "settings-extracted")

    def test_equipment_window_is_clicked_open_only_when_header_is_missing(self):
        cancel_event = Event()
        frame = object()
        with (
            patch(
                "core.equipment_window_controls._load_template",
                side_effect=[object(), object()],
            ),
            patch(
                "core.equipment_window_controls.capture_window",
                return_value=frame,
            ),
            patch(
                "core.equipment_window_controls._find_template",
                side_effect=[(None, 0.2), ((12, 18), 0.95), ((40, 50), 0.91)],
            ),
            patch(
                "core.equipment_window_controls.win32gui.ClientToScreen",
                return_value=(112, 118),
            ),
            patch("core.equipment_window_controls.click_active_at_screen") as click,
        ):
            opened = ensure_equipment_window_open(
                1,
                "아이템 인벤토리",
                "header.png",
                "inventory.png",
                cancel_event,
                lambda _message: None,
            )
        self.assertTrue(opened)
        click.assert_called_once_with(112, 118)

        with (
            patch(
                "core.equipment_window_controls._load_template",
                return_value=object(),
            ),
            patch(
                "core.equipment_window_controls.capture_window",
                return_value=frame,
            ),
            patch(
                "core.equipment_window_controls._find_template",
                return_value=((20, 30), 0.95),
            ),
            patch("core.equipment_window_controls.click_active_at_screen") as click,
        ):
            opened = ensure_equipment_window_open(
                1,
                "장비 창",
                "header.png",
                "equipment.png",
                cancel_event,
                lambda _message: None,
            )
        self.assertTrue(opened)
        click.assert_not_called()

    def test_inventory_expands_only_when_plus_template_is_visible(self):
        frame = object()
        cancel_event = Event()
        status_messages = []
        with (
            patch(
                "core.equipment_window_controls._load_template",
                side_effect=[object(), object()],
            ),
            patch(
                "core.equipment_window_controls.capture_window",
                return_value=frame,
            ),
            patch(
                "core.equipment_window_controls._find_template",
                side_effect=[((12, 18), 0.95), ((40, 50), 0.91)],
            ),
            patch(
                "core.equipment_window_controls.win32gui.ClientToScreen",
                return_value=(140, 150),
            ),
            patch("core.equipment_window_controls.click_active_at_screen") as click,
        ):
            opened = ensure_equipment_window_open(
                1,
                "아이템 인벤토리",
                "header.png",
                "inventory.png",
                cancel_event,
                status_messages.append,
                expand_button_template="assets/equipment/+.png",
            )

        self.assertTrue(opened)
        click.assert_called_once_with(140, 150)
        self.assertTrue(any("확장" in message for message in status_messages))

    def test_multi_boss_plan_uses_all_equipment_management_storage_counts(self):
        class Entry:
            def __init__(self, value):
                self.value = value

            def get(self):
                return str(self.value)

        app = SimpleNamespace(
            equipment_area=object(),
            equipment_apply_inventory_area=object(),
            equipment_apply_equipment_count=Entry(2),
            equipment_apply_cash_count=Entry(1),
            storage_count_entries={
                "storage_equipment_count": Entry(3),
                "storage_installation_count": Entry(4),
                "storage_cash_count": Entry(2),
            },
            equipment_apply_delay_entry=Entry(100),
            equipment_removal_delay_entry=Entry(200),
            storage_delay_entry=Entry(300),
            storage_command_key=Entry("-"),
            equipment_slot_states={"무기": 1},
            _get_equipment_apply_slot_client_point=lambda _slot, _size: (10, 20),
            _get_equipment_slot_client_point=lambda _slot, _size: (30, 40),
        )
        with (
            patch("ui.main_window.find_hwnd_by_process_name", return_value=1),
            patch(
                "ui.main_window.capture_window",
                return_value=SimpleNamespace(shape=(100, 200, 3)),
            ),
        ):
            plan = KuroHelper._build_multi_boss_equipment_plan(app)

        self.assertEqual(
            plan["storage_counts"],
            {"equipment": 3, "installation": 4, "cash": 2},
        )

    def test_boss_rotation_sets_game_resolution_and_restores_clipboard_text(self):
        tester = MultiCharacterTester.__new__(MultiCharacterTester)
        tester._keyboard = unittest.mock.Mock()
        tester.update_status = unittest.mock.Mock()
        cancel_event = Event()
        with (
            patch("core.multi_character_tester.win32gui.IsIconic", return_value=False),
            patch("core.multi_character_tester.win32gui.SetForegroundWindow"),
            patch("core.multi_character_tester.win32gui.GetForegroundWindow", return_value=7),
            patch("core.multi_character_tester.time.sleep"),
            patch("core.multi_character_tester.win32clipboard.OpenClipboard"),
            patch("core.multi_character_tester.win32clipboard.CloseClipboard"),
            patch(
                "core.multi_character_tester.win32clipboard.IsClipboardFormatAvailable",
                return_value=True,
            ),
            patch(
                "core.multi_character_tester.win32clipboard.GetClipboardData",
                return_value="previous clipboard text",
            ),
            patch("core.multi_character_tester.win32clipboard.SetClipboardText") as set_text,
        ):
            tester._set_game_resolution(7, cancel_event)

        pressed = [call.args[0] for call in tester._keyboard.press.call_args_list]
        released = [call.args[0] for call in tester._keyboard.release.call_args_list]
        self.assertEqual(pressed, [Key.enter, Key.ctrl, "v", Key.enter, Key.enter])
        self.assertEqual(released, [Key.enter, "v", Key.ctrl, Key.enter, Key.enter])
        self.assertEqual(
            [call.args[0] for call in set_text.call_args_list],
            ["@해상도 4", "previous clipboard text"],
        )

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
        self.assertIn("setlicenseexpiry", commands)
        self.assertIn("setappupdate", commands)
        self.assertIn("clearappupdate", commands)
        reset_command = next(
            command for command in bot.tree.get_commands(
                guild=discord.Object(id=bot.guild_id)
            ) if command.name == "resetdevice"
        )
        expires_days = next(
            parameter for parameter in reset_command.parameters
            if parameter.name == "expires_days"
        )
        self.assertTrue(expires_days.required)

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

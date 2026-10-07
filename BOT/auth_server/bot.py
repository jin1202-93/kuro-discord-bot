import asyncio
import logging
import os

import discord
from discord import app_commands
from discord.ext import commands

from auth_server.database import issue_code, reset_device, revoke_user

logger = logging.getLogger(__name__)


class KuroAuthBot(commands.Bot):
    def __init__(self, guild_id, admin_role_id):
        intents = discord.Intents.none()
        intents.guilds = True
        super().__init__(command_prefix="!", intents=intents)
        self.guild_id = guild_id
        self.admin_role_id = admin_role_id

    async def setup_hook(self):
        guild = discord.Object(id=self.guild_id)
        await self.tree.sync(guild=guild)


def _has_role(interaction, role_id):
    member_roles = getattr(interaction.user, "roles", ())
    return any(role.id == role_id for role in member_roles)


def _expiry_text(expires_days):
    return "무제한" if expires_days == 0 else f"{expires_days}일"


def create_bot():
    token = (
        os.environ.get("DISCORD_BOT_TOKEN")
        or os.environ.get("DISCORD_TOKEN", "")
    ).strip()
    guild_id = os.environ.get("DISCORD_GUILD_ID", "").strip()
    admin_role_id = os.environ.get("DISCORD_ADMIN_ROLE_ID", "").strip()
    if not all((token, guild_id, admin_role_id)):
        raise RuntimeError(
            "DISCORD_BOT_TOKEN, DISCORD_GUILD_ID, DISCORD_ADMIN_ROLE_ID를 설정하세요."
        )

    bot = KuroAuthBot(
        int(guild_id),
        int(admin_role_id),
    )
    guild = discord.Object(id=bot.guild_id)

    @bot.tree.error
    async def on_app_command_error(
        interaction: discord.Interaction,
        error: app_commands.AppCommandError,
    ):
        logger.error(
            "Discord application command failed",
            exc_info=(type(error), error, error.__traceback__),
        )
        message = "명령 처리 중 오류가 발생했습니다. Render 로그를 확인하세요."
        try:
            if interaction.response.is_done():
                await interaction.followup.send(message, ephemeral=True)
            else:
                await interaction.response.send_message(message, ephemeral=True)
        except discord.HTTPException:
            logger.exception("Could not send the command error to Discord")

    @bot.tree.command(name="issuecode", description="KURO HELPER 인증 코드를 발급합니다.", guild=guild)
    @app_commands.describe(expires_days="인증 코드 유효기간(일, 0=무제한, 1~365)")
    async def issuecode(
        interaction: discord.Interaction,
        expires_days: app_commands.Range[int, 0, 365] = 30,
    ):
        if interaction.guild_id != bot.guild_id:
            await interaction.response.send_message(
                "등록된 인증 서버에서만 사용할 수 있습니다.",
                ephemeral=True,
            )
            return
        is_admin = interaction.guild_permissions.administrator or _has_role(
            interaction,
            bot.admin_role_id,
        )
        if not is_admin:
            await interaction.response.send_message(
                "관리자만 인증 코드를 발급할 수 있습니다.",
                ephemeral=True,
            )
            return
        await interaction.response.defer(ephemeral=True, thinking=True)
        try:
            code, license_id = await asyncio.to_thread(issue_code, expires_days)
        except Exception:
            logger.exception("Failed to issue an authentication code")
            await interaction.followup.send(
                "인증 코드 발급에 실패했습니다. Render 로그를 확인하세요.",
                ephemeral=True,
            )
            return
        await interaction.followup.send(
            f"인증 코드 발급 완료 (유효기간 {_expiry_text(expires_days)})\n"
            f"코드: `{code}`\n관리 ID: `{license_id}`\n"
            "코드는 이 메시지를 볼 수 있는 관리자만 확인할 수 있습니다. "
            "코드를 테스터에게 전달하고 관리 ID는 안전하게 보관하세요.",
            ephemeral=True,
        )

    @bot.tree.command(
        name="resetdevice",
        description="사용자의 등록 PC를 초기화합니다.",
        guild=guild,
    )
    @app_commands.describe(
        license_id="코드 발급 시 함께 표시된 관리 ID",
        expires_days="새 인증 코드 유효기간(일, 0=무제한, 1~365)",
    )
    async def resetdevice(
        interaction: discord.Interaction,
        license_id: str,
        expires_days: app_commands.Range[int, 0, 365] = 30,
    ):
        if interaction.guild_id != bot.guild_id:
            await interaction.response.send_message(
                "등록된 인증 서버에서만 사용할 수 있습니다.",
                ephemeral=True,
            )
            return
        is_admin = interaction.guild_permissions.administrator or _has_role(
            interaction,
            bot.admin_role_id,
        )
        if not is_admin:
            await interaction.response.send_message(
                "관리자만 등록 PC를 초기화할 수 있습니다.",
                ephemeral=True,
            )
            return
        await interaction.response.defer(ephemeral=True, thinking=True)
        try:
            code = await asyncio.to_thread(reset_device, license_id, expires_days)
        except Exception:
            logger.exception("Failed to reset an authentication license")
            await interaction.followup.send(
                "초기화에 실패했습니다. 관리 ID와 Render 로그를 확인하세요.",
                ephemeral=True,
            )
            return
        await interaction.followup.send(
            f"기기 연결을 초기화했고 유효기간 {_expiry_text(expires_days)} 새 코드를 발급했습니다.\n"
            f"새 코드: `{code}`\n관리 ID: `{license_id.upper()}`",
            ephemeral=True,
        )

    @bot.tree.command(
        name="revokeuser",
        description="사용자의 KURO HELPER 인증을 취소합니다.",
        guild=guild,
    )
    @app_commands.describe(license_id="코드 발급 시 함께 표시된 관리 ID")
    async def revokeuser(
        interaction: discord.Interaction,
        license_id: str,
    ):
        if interaction.guild_id != bot.guild_id:
            await interaction.response.send_message(
                "등록된 인증 서버에서만 사용할 수 있습니다.",
                ephemeral=True,
            )
            return
        is_admin = interaction.guild_permissions.administrator or _has_role(
            interaction,
            bot.admin_role_id,
        )
        if not is_admin:
            await interaction.response.send_message(
                "관리자만 인증을 취소할 수 있습니다.",
                ephemeral=True,
            )
            return
        await interaction.response.defer(ephemeral=True, thinking=True)
        try:
            await asyncio.to_thread(revoke_user, license_id)
        except Exception:
            logger.exception("Failed to revoke an authentication license")
            await interaction.followup.send(
                "인증 취소에 실패했습니다. 관리 ID와 Render 로그를 확인하세요.",
                ephemeral=True,
            )
            return
        await interaction.followup.send(
            f"관리 ID `{license_id.upper()}`의 인증을 취소했습니다. "
            "실행 중인 앱은 다음 서버 확인 때 종료됩니다.",
            ephemeral=True,
        )

    return bot, token

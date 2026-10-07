import asyncio
import os

import discord
from discord import app_commands
from discord.ext import commands

from auth_server.database import register_code, reset_device, revoke_user


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


class CodeRegistrationModal(discord.ui.Modal, title="인증 코드 등록"):
    def __init__(self, bot, member, expires_days):
        super().__init__()
        self.bot = bot
        self.member = member
        self.expires_days = expires_days
        self.code_input = discord.ui.TextInput(
            label="직접 정한 인증 코드",
            placeholder="영문 대문자·숫자·하이픈, 16~64자",
            min_length=16,
            max_length=64,
            required=True,
        )
        self.add_item(self.code_input)

    async def on_submit(self, interaction: discord.Interaction):
        if interaction.guild_id != self.bot.guild_id:
            await interaction.response.send_message(
                "등록된 인증 서버에서만 사용할 수 있습니다.",
                ephemeral=True,
            )
            return
        is_admin = interaction.guild_permissions.administrator or _has_role(
            interaction,
            self.bot.admin_role_id,
        )
        if not is_admin:
            await interaction.response.send_message(
                "관리자만 인증 코드를 등록할 수 있습니다.",
                ephemeral=True,
            )
            return
        try:
            await asyncio.to_thread(
                register_code,
                self.member.id,
                str(self.code_input.value),
                self.expires_days,
            )
        except ValueError as error:
            await interaction.response.send_message(str(error), ephemeral=True)
            return
        await interaction.response.send_message(
            f"{self.member.mention} 전용 코드 등록 완료. "
            f"{self.expires_days}일 동안 유효합니다. 코드는 서버에 해시로 저장됩니다.",
            ephemeral=True,
        )


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

    @bot.tree.command(
        name="registercode",
        description="직접 정한 KURO HELPER 인증 코드를 등록합니다.",
        guild=guild,
    )
    @app_commands.describe(
        member="이 코드를 사용할 테스터",
        expires_days="코드 유효기간(일, 1~365)",
    )
    async def registercode(
        interaction: discord.Interaction,
        member: discord.Member,
        expires_days: app_commands.Range[int, 1, 365] = 30,
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
                "관리자만 인증 코드를 등록할 수 있습니다.",
                ephemeral=True,
            )
            return
        await interaction.response.send_modal(
            CodeRegistrationModal(bot, member, expires_days)
        )

    @bot.tree.command(
        name="resetdevice",
        description="사용자의 등록 PC를 초기화합니다.",
        guild=guild,
    )
    @app_commands.describe(member="등록 PC를 초기화할 사용자")
    async def resetdevice(
        interaction: discord.Interaction,
        member: discord.Member,
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
        await asyncio.to_thread(reset_device, member.id)
        await interaction.response.send_message(
            f"{member.mention}의 등록 PC와 기존 인증을 초기화했습니다.\n"
            "새 PC용 코드를 `/registercode`로 등록해 테스터에게 다시 전달하세요.",
            ephemeral=True,
        )

    @bot.tree.command(
        name="revokeuser",
        description="사용자의 KURO HELPER 인증을 취소합니다.",
        guild=guild,
    )
    @app_commands.describe(member="인증을 취소할 사용자")
    async def revokeuser(
        interaction: discord.Interaction,
        member: discord.Member,
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
        await asyncio.to_thread(revoke_user, member.id)
        await interaction.response.send_message(
            f"{member.mention}의 KURO HELPER 인증을 취소했습니다.",
            ephemeral=True,
        )

    return bot, token

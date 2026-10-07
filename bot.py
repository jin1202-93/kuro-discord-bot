import os
import discord
from discord.ext import commands

intents = discord.Intents.default()
intents.message_content = True

bot = commands.Bot(command_prefix="!", intents=intents)


@bot.event
async def on_ready():
    print(f"성공적으로 로그인했습니다: {bot.user.name}")


@bot.command()
async def 안녕(ctx):
    await ctx.send("안녕하세요! 반갑습니다.")


# Koyeb 환경변수에서 토큰을 불러옵니다
token = os.getenv("DISCORD_TOKEN")
bot.run(token)

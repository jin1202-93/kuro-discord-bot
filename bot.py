import os
import threading
from flask import Flask
import discord
from discord.ext import commands

# 1. Render/Koyeb 등 포트 감지용 웹 서버 설정
app = Flask(__name__)

@app.route('/')
def home():
    return "Bot is alive!"

def run_flask():
    # 클라우드 서비스가 제공하는 PORT 환경변수를 읽고, 없으면 8080 사용
    port = int(os.environ.get("PORT", 8080))
    app.run(host='0.0.0.0', port=port)

# 웹 서버를 별도 스레드로 비동기 실행
threading.Thread(target=run_flask, daemon=True).start()

# 2. 디스코드 봇 설정
intents = discord.Intents.default()
intents.message_content = True

bot = commands.Bot(command_prefix="!", intents=intents)

@bot.event
async def on_ready():
    print(f"성공적으로 로그인했습니다: {bot.user.name}")

@bot.command()
async def 안녕(ctx):
    await ctx.send("안녕하세요! 반갑습니다.")

# 3. 환경변수에서 디스코드 토큰을 불러와 봇 실행
token = os.getenv("DISCORD_TOKEN")
bot.run(token)

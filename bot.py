import os
import threading
from flask import Flask
import discord
from discord.ext import commands
from supabase import create_client, Client

# 1. Flask 웹 서버
app = Flask(__name__)

@app.route('/')
def home():
    return "Bot is alive!"

def run_flask():
    port = int(os.environ.get("PORT", 8080))
    app.run(host='0.0.0.0', port=port)

threading.Thread(target=run_flask, daemon=True).start()

# 2. Supabase DB 연결 설정
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

# 환경변수가 등록되어 있을 때만 Supabase 클라이언트 생성
supabase: Client = None
if SUPABASE_URL and SUPABASE_KEY:
    supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# 3. 디스코드 봇 설정
intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix="!", intents=intents)

@bot.event
async def on_ready():
    print(f"성공적으로 로그인했습니다: {bot.user.name}")

@bot.command()
async def 안녕(ctx):
    await ctx.send("안녕하세요! 반갑습니다.")

# 4. 봇 실행
token = os.getenv("DISCORD_TOKEN")
bot.run(token);./////////

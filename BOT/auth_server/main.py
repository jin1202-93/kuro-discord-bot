import asyncio
import os

import uvicorn

from auth_server.app import app
from auth_server.bot import create_bot
from auth_server.database import initialize_database


async def run():
    initialize_database()
    bot, token = create_bot()
    port = int(os.environ.get("PORT", "8000"))
    server = uvicorn.Server(
        uvicorn.Config(
            app,
            host="0.0.0.0",
            port=port,
            log_level="info",
            proxy_headers=True,
            forwarded_allow_ips="*",
        )
    )
    try:
        await asyncio.gather(bot.start(token), server.serve())
    finally:
        await bot.close()


def main():
    asyncio.run(run())


if __name__ == "__main__":
    main()

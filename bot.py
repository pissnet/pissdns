import asyncio
import sys

from ircrobots import Bot as BaseBot
from ircrobots import ConnectionParams
from ircrobots.security import TLS_NOVERIFY

try:
    import config
except ImportError:
    print("You forgot to move the config.py file")
    sys.exit()

if config.DNS_SERVER == 'powerdns':
    from zonebot.powerdns import PowerDNSZoneBot as Server
elif config.DNS_SERVER == 'tinydns':
    from zonebot.tinydns import TinyDNSZoneBot as Server
elif config.DNS_SERVER == 'hellomouse':
    from zonebot.hellomouse import HellomouseZoneBot as Server


SERVERS = [
    ("piss", config.SERVER),
]


class Bot(BaseBot):
    def create_server(self, name: str):
        return Server(self, name, config=config)


async def main():
    bot = Bot()
    for name, host in SERVERS:
        params = ConnectionParams(config.NICK, host, 6697, tls=TLS_NOVERIFY)
        await bot.add_server(name, params)

    await bot.run()

if __name__ == "__main__":
    asyncio.run(main())

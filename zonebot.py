import asyncio
import re
import sys
import time
from ipaddress import IPv4Address, AddressValueError, IPv6Address

import aiohttp
from irctokens import build, Line
from ircrobots import Bot as BaseBot
from ircrobots import Server as BaseServer
from ircrobots import ConnectionParams
import sqlalchemy
from sqlalchemy import insert

try:
    import config
except ImportError:
    print("You forgot to move the config.py file")
    sys.exit()

SERVERS = [
    ("piss", config.SERVER),
]

metadata = sqlalchemy.MetaData()

domains = sqlalchemy.Table(
    "domains",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("name", sqlalchemy.String(255)),
    sqlalchemy.Column("master", sqlalchemy.String(128)),
    sqlalchemy.Column("last_check", sqlalchemy.Integer),
    sqlalchemy.Column("type", sqlalchemy.String(6)),
    sqlalchemy.Column("notified_serial", sqlalchemy.Integer),
    sqlalchemy.Column("account", sqlalchemy.String(40)),
)

records = sqlalchemy.Table(
    "records",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("domain_id", sqlalchemy.Integer),
    sqlalchemy.Column("name", sqlalchemy.String(255)),
    sqlalchemy.Column("type", sqlalchemy.String(10)),
    sqlalchemy.Column("content", sqlalchemy.String(64000)),
    sqlalchemy.Column("ttl", sqlalchemy.Integer),
    sqlalchemy.Column("prio", sqlalchemy.Integer),
    sqlalchemy.Column("disabled", sqlalchemy.Integer),
    sqlalchemy.Column("ordername", sqlalchemy.Integer),
    sqlalchemy.Column("auth", sqlalchemy.Integer),
)

engine = sqlalchemy.create_engine(
    config.DATABASE_URL,
)


class Server(BaseServer):
    pingcount = 0

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        loop = asyncio.get_event_loop()
        loop.create_task(self.periodic_bg_task())

    async def periodic_bg_task(self):
        while True:
            await asyncio.sleep(300)  # 5 mins
            await self.update_dns()

    async def line_read(self, line: Line):
        print(f"{self.name} < {line.format()}")
        if line.command == "001":
            await self.send(build("JOIN", ["#pisswiki"]))
        elif line.command == "PRIVMSG" and line.hostmask.nickname == "Pisswiki":  # TODO: Validate that Pisswiki is the real one?
            message = line.params[-1].strip()
            if message.startswith("\00314[[\00307Domain:"):
                await self.update_dns()

    def insert_dns_record(self, domain_id, name, record_type, content, ttl=3600):
        new_r = insert(records).values(
            domain_id=domain_id,
            name=name,
            type=record_type,
            content=content,
            ttl=ttl,
            prio=0,
            disabled=0,
            ordername=None,
            auth=1
        )
        engine.execute(new_r)

    async def update_dns(self):
        async with aiohttp.ClientSession() as session:
            async with session.get("https://api.shitposting.space/piss/dns") as resp:
                data = await resp.json()

        # check if the data is newer than what we already got...
        with open("last_data_ts", 'r') as f:
            last_data = f.read().strip()

        if data['last_modified'] == last_data:
            print("Data not stale. I die")
            return
        print("Fresh data, updating...")

        # Transaction in case we fuck up....
        with engine.begin():
            # Start inserting the new stuff
            for dom in data['domains']:
                print(f"Updating {dom['name']}... ")
                # Check if domain exists.
                query = domains.select().where(domains.c.name == dom['name'])  # noqa
                result = engine.execute(query)
                record = result.fetchone()
                if not record:
                    # New domain, do the insertion
                    new_d = insert(domains).values(
                        name=dom['name'],
                        master='',
                        last_check=None,
                        type="MASTER",
                        notified_serial=None,
                        account=''
                    )
                    result = engine.execute(new_d)
                    domain_id = result.inserted_primary_key
                    if not isinstance(domain_id, int) and not isinstance(domain_id, str):
                        domain_id = domain_id[0]
                else:
                    domain_id = int(record[0])

                # Check if we need to update records by comparing the timestamp in the SOA record
                query = records.select().where((records.c.domain_id == domain_id) & (records.c.type == 'SOA'))
                result = engine.execute(query)
                soa_ts = ""
                if record := result.fetchone():
                    soa_ts = record[4].split(" ")[2]

                if soa_ts == dom['last_modified']:
                    print("  - Skipping, not modified")
                    continue

                # Delete all old records and creete em new
                query = records.delete().where(records.c.domain_id == domain_id)
                engine.execute(query)

                self.insert_dns_record(
                    domain_id=domain_id,
                    name=dom['name'],
                    record_type='SOA',
                    content=f"{config.SOA_NS} {config.SOA_EMAIL} {dom['last_modified']} 300 60 691200 3600",
                    ttl=7200
                )

                for ns in config.NAMESERVERS:
                    self.insert_dns_record(
                        domain_id=domain_id,
                        name=dom['name'],
                        record_type='NS',
                        content=ns
                    )

                # Insert dem records
                for rec in dom['records']:
                    # Ignore invalid stuff
                    if rec['type'] not in ('A', 'AAAA', 'CNAME', 'TXT', 'NS'):
                        continue
                    # Validations:
                    # Name must be valid dns
                    if not re.match(r"[a-zA-Z0-9.-]+$", rec['name']):
                        print(f"Got an invalid record! (Bad label) {rec}")
                        continue

                    if len(rec['value']) > 255:
                        print(f"Got an invalid record! (Value too long) {rec}")
                        continue

                    if rec['type'] == 'A':
                        try:
                            IPv4Address(rec['value'])
                        except AddressValueError:
                            print(f"Got an invalid record! (Bad IPv4) {rec}")
                            continue
                    elif rec['type'] == 'AAAA':
                        try:
                            IPv6Address(rec['value'])
                        except AddressValueError:
                            print(f"Got an invalid record! (Bad IPv6) {rec}")
                            continue
                    elif rec['type'] in ('CNAME', 'NS'):
                        if not re.match(r"[a-zA-Z0-9.-]+$", rec['value']):
                            print(f"Got an invalid record! (Bad value) {rec}")
                            continue

                    rec_name = f"{rec['name']}.{dom['name']}" if rec['name'] != "@" else dom['name']
                    if rec_name > 255:
                        print(f"Got an invalid record! (Name too long) {rec}")
                        continue

                    self.insert_dns_record(
                        domain_id=domain_id,
                        name=rec_name,
                        record_type=rec['type'],
                        content=rec['value'],
                        ttl=60  # TODO: Configurable TTL (wiki task)
                    )

        with open("last_data_ts", 'w') as f:
            f.write(data['last_modified'])


class Bot(BaseBot):
    def create_server(self, name: str):
        return Server(self, name)


async def main():
    bot = Bot()
    for name, host in SERVERS:
        params = ConnectionParams(config.NICK, host, 6697, True, tls_verify=False)
        await bot.add_server(name, params)

    await bot.run()

if __name__ == "__main__":
    asyncio.run(main())

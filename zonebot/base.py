import asyncio
import re
import subprocess
from ipaddress import IPv4Address, AddressValueError, IPv6Address

import aiohttp
from irctokens import build, Line
from ircrobots import Server as BaseServer


class BaseZoneBot(BaseServer):
    pingcount = 0

    def __init__(self, bot, name: str, config):
        super().__init__(bot, name)
        self.config = config
        loop = asyncio.get_event_loop()
        loop.create_task(self.periodic_bg_task())

    async def periodic_bg_task(self):
        while True:
            await asyncio.sleep(300)  # 5 mins
            await self.update_dns()

    async def msg(self, line, msg):
        source = line.params[0]
        if "#" not in line.params[0]:
            source = line.hostmask.nickname
        await self.send(build("PRIVMSG", [source, msg]))

    async def line_read(self, line: Line):
        print(f"{self.name} < {line.format()}")
        if line.command == "001":
            await self.send(build("JOIN", ["#pisswiki", "#pissdns"]))
        elif line.command == "PRIVMSG":
            message = line.params[-1].strip()
            if line.hostmask.nickname == "Pisswiki":  # TODO: Validate that Pisswiki is the real one?
                if message.startswith("\00314[[\00307Domain:"):
                    await self.update_dns()

            if not message.startswith("!"):
                return

            message = message.replace("!", '')
            command = message.split(" ")[0].lower()

            if command == "version":
                ver_date = subprocess.check_output(['git', 'show', '-s', '--format=format:%cd']).decode()
                tag = subprocess.check_output(['git', 'describe', '--always', '--dirty']).decode().strip()
                await self.msg(line, f"Version: \002{tag}\002 ({ver_date})")

    def insert_dns_record(self, domain_id, name, record_type, content, ttl=3600):
        raise NotImplementedError

    def get_zone(self, zone_name: str):
        """ Returns a zone identifier if using a database, or just the zone name if not """
        raise NotImplementedError

    def needs_updating(self, domain_id, last_modified: int) -> bool:
        """ Whether we should update this zone or not """
        raise NotImplementedError

    def pre_update(self, domain_id, domain_data):
        """ Executed just before we start inserting records for a domain we are going to update. """
        raise NotImplementedError

    async def update_dns(self):
        async with aiohttp.ClientSession() as session:
            async with session.get("https://api.shitposting.space/piss/dns") as resp:
                data = await resp.json()

        # check if the data is newer than what we already got...
        last_data = ''
        try:
            with open("last_data_ts", 'r') as f:
                last_data = f.read().strip()
        except FileNotFoundError:
            pass  # first run

        if data['last_modified'] == last_data:
            return
        print("Fresh data, updating...")

        # Start inserting the new stuff
        for dom in data['domains']:
            print(f"Updating {dom['name']}... ")
            # Check if domain exists.

            domain_id = self.get_zone(dom['name'])

            if not self.needs_updating(domain_id, dom['last_modified']):
                print("  - Skipping, not modified")
                continue

            self.pre_update(domain_id, dom)

            self.insert_dns_record(
                domain_id=domain_id,
                name=dom['name'],
                record_type='SOA',
                content=f"{self.config.SOA_NS} {self.config.SOA_EMAIL} {dom['last_modified']} 300 60 691200 3600",
                ttl=7200
            )

            for ns in self.config.NAMESERVERS:
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
                    if not re.match(r"^[a-zA-Z0-9.-_]+$", rec['value']):
                        print(f"Got an invalid record! (Bad value) {rec}")
                        continue

                if rec['name'] == '@' and rec['type'] in ('CNAME', 'NS'):
                    print(f"Got an invalid record! (CNAME or NS on root not allowed) {rec}")
                    continue

                # Name must be valid dns
                if not re.match(r"^[a-zA-Z0-9._-]+$", rec['name']) and rec['name'] != '@':
                    print(f"Got an invalid record! (Bad label) {rec}")
                    continue

                rec_name = f"{rec['name']}.{dom['name']}" if rec['name'] != "@" else dom['name']
                if len(rec_name) > 255:
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

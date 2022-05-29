import asyncio
import hashlib
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

    async def msg(self, line_or_channel, msg):
        if not isinstance(line_or_channel, str):
            source = line_or_channel.params[0]
            if "#" not in line_or_channel.params[0]:
                source = line_or_channel.hostmask.nickname
        else:
            source = line_or_channel
        await self.send(build("PRIVMSG", [source, msg]))

    async def line_read(self, line: Line):
        print(f"{self.name} < {line.format()}")
        if line.command == "001":
            await self.send(build("JOIN", ["#pisswiki,#pissdns"]))
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
            elif command == "force_update":
                await self.update_dns(force=True)

    def insert_dns_record(self, domain_id, name, record_type, content, prio=0, ttl=3600):
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

    def post_update(self, domain_id):
        """ Executed after all records have been inserted for a domain we have updated. """
        raise NotImplementedError

    def pre_db_update(self):
        """ Executed before inserting any records at all """
        pass

    async def update_dns(self, force=False):
        async with aiohttp.ClientSession() as session:
            async with session.get("https://api.shitposting.space/piss/dns") as resp:
                raw_data = await resp.read()
                data = await resp.json()

        # check if the data is newer than what we already got...
        last_data = ''
        try:
            with open("last_data_ts", 'r') as f:
                last_data = f.read().strip()
        except FileNotFoundError:
            pass  # first run

        if not force and data['last_modified'] == last_data:
            return
        print("Fresh data, updating...")
        souce_hash = hashlib.sha1(raw_data).hexdigest()[:10]
        await self.msg("#pissdns", f"Deploying zone. Source hash: \002{souce_hash}\002.")
        self.pre_db_update()

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

            self.insert_dns_record(
                domain_id=domain_id,
                name=dom['name'],
                record_type='TXT',
                content=f"Zone managed by the pissnet wiki DNS system. "
                        f"Contact #pisswiki on ircs://irc.letspiss.net/#pisswiki for abuse with full logs.",
                ttl=300
            )

            for ns in self.config.NAMESERVERS:
                self.insert_dns_record(
                    domain_id=domain_id,
                    name=dom['name'],
                    record_type='NS',
                    content=ns
                )

            records_to_insert = []
            domains_with_cnames = []

            # Insert dem records
            for rec in dom['records']:
                # Ignore invalid stuff
                if rec['type'] not in ('A', 'AAAA', 'CNAME', 'TXT', 'NS', 'CAA', 'MX'):
                    continue

                prio = 0

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
                elif rec['type'] == 'CAA':
                    if not re.match(r"^(\d{1,3}) ([a-z0-9]+) \"([a-zA-Z0-9\-._@:;/= ]+)\"$", rec['value']):
                        print(f"Got an invalid record! (Bad value) {rec}")
                        continue
                elif rec['type'] == 'MX':
                    splt = rec['value'].split(" ")
                    if len(splt) == 2:  # We got a prio!
                        prio = splt[0]
                        rec['value'] = splt[1]
                    elif len(splt) > 2:
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

                if rec['type'] == "CNAME":
                    domains_with_cnames.append(rec_name)

                records_to_insert.append({
                    'domain_id': domain_id,
                    'name': rec_name,
                    'record_type': rec['type'],
                    'content': rec['value'],
                    'prio': prio,
                    'ttl': 60  # TODO: Configurable TTL (wiki task)
                })

            domains_with_cnames_inserted = []
            for record in records_to_insert:
                # Check for CNAME violations
                if record['name'] in domains_with_cnames:
                    if record['record_type'] != "CNAME":
                        print(f"Got a non-CNAME record for an entry that already has a CNAME! {record}")
                        continue
                    else:
                        if record['name'] in domains_with_cnames_inserted:
                            print(f"Got a CNAME record for an entry that already has a CNAME! {record}")
                            continue
                        domains_with_cnames_inserted.append(record['name'])

                self.insert_dns_record(**record)

                self.post_update(domain_id)

        with open("last_data_ts", 'w') as f:
            f.write(data['last_modified'])

import ipaddress
import os
from datetime import datetime

from .base import BaseZoneBot


class TinyDNSZoneBot(BaseZoneBot):
    def pre_update(self, domain_id, domain_data):
        with open("output-zones", "a") as f:
            f.write(f"\n# Zone: {domain_id}\n")
            f.write(f"# Owner: {domain_data['owner']}\n")  # I bet you want to sanitize this

    def insert_dns_record(self, domain_id, name, record_type, content, prio=0, ttl=3600):
        f = open("output-zones", "a")
        if record_type == "SOA":
            content = content.split(" ")
            f.write(f"Z{name}:{content[0].strip('.')}:{content[1].strip('.')}:{content[2]}\n")
        elif record_type == "NS":
            f.write(f".{name}::{content}:{ttl}\n")
        elif record_type == "A":
            f.write(f"+{name}:{content}:{ttl}\n")
        elif record_type == "AAAA":
            content = "".join(map(lambda x: '\\' + oct(x)[2:].zfill(3), ipaddress.ip_address(content).packed))
            f.write(f":{name}:28:{content}:{ttl}\n")
        elif record_type == "TXT":
            f.write(f"'{name}:{self.sane_txt(content)}:{ttl}\n")
        elif record_type == "CNAME":
            f.write(f"C{name}:{content}:{ttl}\n")
        elif record_type == "MX":
            f.write(f"@{name}::{content}:{prio}\n")
        f.close()

    def sane_txt(self, x):
        if '#' in x:
            x = x.split('#')[0]
        items = []
        for c in x:
            items.append("\\" + oct(ord(c))[2:].zfill(3))
        return "".join(items)

    def get_zone(self, zone_name: str):
        return zone_name

    def pre_db_update(self):
        try:
            os.remove("output-zones")
        except FileNotFoundError:
            pass
        with open("output-zones", "w") as f:
            f.write(f"# Last-modified: {datetime.utcnow().isoformat()}\n")

    def needs_updating(self, domain_id, last_modified: int) -> bool:
        return True

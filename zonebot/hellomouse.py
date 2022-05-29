from typing import Literal, Optional, TypedDict
from .base import BaseZoneBot
import json
from os.path import exists

def recursive_items(dictionary: dict[str]):
    for key, value in dictionary.items():
        if type(value) is dict:
            yield from recursive_items(value)
        else:
            yield (key, value)

class CAARecord(TypedDict):
    flags: int
    tag: str
    value: str
class ANYRecord(TypedDict):
    type: str
    content: str
class CNAMERecord(ANYRecord):
    type: Literal['CNAME']

class MXRecord(TypedDict):
    preference: Optional[int]
    exchange: str
class SSHFPRecord(TypedDict):
    algorithm: str
    fingerprint: str
    fingerprintType: int

class ZoneDataFormat(TypedDict):
    child: Optional[dict[str, "ZoneDataFormat"]]
    CAA: Optional[list[CAARecord]]
    ANY: Optional[CNAMERecord]
    MX: Optional[list[MXRecord]]
    SSHFP: Optional[list[SSHFPRecord]]
    TXT: Optional[list[str] | list[list[str]]]
    A: Optional[list[str]]
    AAAA: Optional[list[str]]

class ZoneData(TypedDict):
    last_modified: int
    soa: dict[str, int | str]
    zone: ZoneDataFormat


class HellomouseZoneBot(BaseZoneBot):
    def __init__(self, bot, name: str, config):
        super().__init__(bot, name, config)
        # List of records that accept multiple values, and thus are arrays in the data structure
        self.arrayRecords = ['TXT', 'A', 'AAAA', 'CNAME', 'MX', 'NS', 'SRV', 'SSHFP', 'URI']
        self.corednsTemplate = '\n'.join([
            '{',
            '  grpc . 127.0.0.1:5353',
            '  log',
            f'  bind 127.0.0.1 ::1 {self.config.IPV6_ADDR} {self.config.IPV4_ADDR}',
            '}'
        ])


    def get_zone(self, zone_name: str) -> str:
        return zone_name

    def needs_updating(self, domain_id: str, last_modified: int) -> bool:
        # Check if we need to update records by comparing the timestamp in the SOA record
        try:
            with open(f'{self.config.ZONEFILE_LOCATION}/{domain_id}/zone_data.json', 'r') as f:
                data = json.load(f)
                if data['last_modified'] != last_modified:
                    return True
        except FileNotFoundError:
            data = { 'last_modified': last_modified, 'zone': {} }
            with open(f'{self.config.ZONEFILE_LOCATION}/{domain_id}/zone_data.json', 'w+') as f:
                json.dump(data, f, indent=2)
            return True

        return False

    def _handleRecords(self, tree: ZoneDataFormat, record_type: str, content: str, prio=0):
        """ Handle all necessary transformations on the records """
        if record_type in self.arrayRecords:
            self._handleArrayRecords(tree, record_type, content, prio)
        else:
            if record_type == 'CNAME':
                tree['ANY'] = {
                    'type': 'CNAME',
                    'data': content
                }
            elif record_type == 'SRV':
                values = content.split(' ')
                tree[record_type] = {
                    'type': 'static',
                    'data': {
                        'priority': int(values[0]),
                        'weight': int(values[1]),
                        'port': int(values[2]),
                        'target': values[3]
                    }
                }
            else:
                tree[record_type] = content

    def _handleArrayRecords(self, tree: ZoneDataFormat, record_type: str, content: str, prio=0):
        """ Handle all necessary transformations on the records that are arrays (that accept multiple values) """
        if tree[record_type] is None:
            tree[record_type] = []
        match record_type:
            case 'CAA':
                values = content.split(' ')
                tree[record_type].append({
                    'flags': int(values[0]),
                    'tag': values[1],
                    'value': values[2].replace('"', ''),
                    'issuerCritical': True
                })
            case 'MX':
                if prio != 0:
                    tree[record_type].append({
                        'preference': prio,
                        'exchange': content
                    })
                else:
                    tree[record_type].append({
                        'exchange': content
                    })
            case 'SSHFP':
                values = content.split(' ')
                tree[record_type].append({
                    'algorithm': int(values[0]),
                    'fingerprintType': int(values[1]),
                    'fingerprint': values[2]
                })
            case 'TXT':
                if len(tree[record_type]) == 1:
                    tree[record_type] = [tree[record_type], [content]]
                elif len(tree[record_type]) > 1:
                    tree[record_type].append([content])
                else:
                    tree[record_type].append(content)
            case 'URI':
                values = content.split(' ')
                if len(values) != 3:
                    print(f'Got an invalid record! (Bad value) {record_type} {content}')
                else:
                    tree[record_type].append({
                        'priority': int(values[0]),
                        'weight': int(values[1]),
                        'target': values[2]
                    })
            case 'AAAA' | 'A':
                tree[record_type].append(content)

            case _:
                tree[record_type].append(content)


    def insert_dns_record(self, domain_id: str, name: str, record_type: str, content: str, prio=0, ttl=3600):
        with open(f'{self.config.ZONEFILE_LOCATION}/{domain_id}/zone_data.json', 'w+') as f:
            try:
                data = json.load(f)
            except json.decoder.JSONDecodeError:
                data = { 'zone': {}}
            zone: ZoneDataFormat = data['zone']

            # The SOA record is not handled in the DNS records by us, it's handled by the system itself
            if record_type == 'SOA':
                data['soa'] = {
                    'mname': self.config.SOA_NS,
                    'rname': self.config.SOA_EMAIL,
                    'serial': content.split(' ')[2],
                    'refresh': 300,
                    'retry': 60,
                    'expire': 691200,
                    'minimum': 3600
                }
            else:
                # Handle apex records
                if name == '@':
                    self._handleRecords(zone)
                # Handle child (subdomain) records
                else:
                    if zone['child'] is None:
                        zone['child'] = {}

                    # Handle multi-level subdomains
                    if '.' in name:
                        # Split the name into a list of subdomains, and reverse it to get the correct order (by depth)
                        names = name.split('.')[::-1]
                        current = zone

                        # Iterate over all levels of the subdomains to create the data structure, and get to the last one
                        for i in range(len(names) - 1):
                            if names[i] not in current['child']:
                                current['child'][names[i]] = {}
                            if i != len(names) - 1:
                                current['child'][names[i]]['child'] = {}
                            current = current['child'][names[i]]

                        self._handleRecords(current['child'][names[-1]], record_type, content, prio)
                    # Handle single-level subdomains
                    else:
                        if zone['child'][name] is None:
                            zone['child'][name] = {}

                        self._handleRecords(zone['child'][name], record_type, content, prio)
            json.dump(data, f, indent=2)

    def post_update(self, domain_id: str):
        # Create the JavaScipt module to be loaded by the DNS server
        if not exists(f'{self.config.ZONEFILE_LOCATION}/{domain_id}/index.js'):
            # Why yes, we are writing javascript in Python
            with open(f'{self.config.ZONEFILE_LOCATION}/{domain_id}/index.js', 'w+') as f:
                f.write('const { zone, soa } = require("./zone_data.json");\n')
                f.write('const Zone = require("../../src/module").Zone;\n')
                f.write('\n')
                f.write(f'module.exports = new Zone({domain_id}, zone, soa);\n')

        # Apply some final transformations to the zone file
        with open(f'{self.config.ZONEFILE_LOCATION}/{domain_id}/zone_data.json', 'w+') as f:
            data = json.load(f)
            dataItems = list(recursive_items(data['zone']))

            for i in range(len(dataItems)):
                (key, value) = dataItems[i]
                if key in self.arrayRecords:
                    if type(value) is list:
                        value = map(lambda x: { 'data': x }, value)
                    else:
                        value = { 'data': value }
                    dataItems[i] = (key, {
                        'type': 'static',
                        'data': [value]
                    })

            json.dump(dict(dataItems), f, indent=2)

        # Add the domain to the CoreDNS config, only if it is not already there
        with open(f'{self.config.COREDNS_LOCATION}/Corefile', 'w+') as f:
            contents = f.read()

            if 'name' not in contents:
                f.write('\n')
                f.write(f'{domain_id} {self.corednsTemplate}')
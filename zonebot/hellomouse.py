from .base import BaseZoneBot
import json

def recursive_items(dictionary: dict[str]):
    for key, value in dictionary.items():
        if type(value) is dict:
            yield from recursive_items(value)
        else:
            yield (key, value)

class HellomouseZoneBot(BaseZoneBot):
    def __init__(self, bot, name: str, config):
        super().__init__(bot, name, config)
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
            with open(f'{self.config.ZONEFILE_LOCATION}/{domain_id}.zone.json', 'r') as f:
                data = json.load(f)
                if data['last_modified'] != last_modified:
                    return True
        except FileNotFoundError:
            data = { 'last_modified': last_modified, 'zone': {} }
            with open(f'{self.config.ZONEFILE_LOCATION}/{domain_id}.zone', 'w+') as f:
                json.dump(data, f, indent=2)
            return True

        return False

    def handleRecords(self, tree: dict[str, list[dict[str, int | str | bool] | str] | list[str] | dict[str, str | int]], record_type: str, content: str, prio=0):
        if record_type in self.arrayRecords:
            self.handleArrayRecords(tree, record_type, content, prio)
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

    def handleArrayRecords(self, tree: dict[str, list[dict[str, int | str | bool] | str] | list[str]], record_type: str, content: str, prio=0):
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
        with open(f'{self.config.ZONEFILE_LOCATION}/{domain_id}.zone', 'w+') as f:
            try:
                data = json.load(f)
            except json.decoder.JSONDecodeError:
                data = { 'zone': {}}
            zone: dict[str, list[dict[str, int | str | bool] | str] | list[str]] = data['zone'] 

            if record_type == 'SOA':
                data['SOA'] = {
                    'mname': self.config.SOA_NS,
                    'rname': self.config.SOA_EMAIL,
                    'serial': content.split(' ')[2],
                    'refresh': 300,
                    'retry': 60,
                    'expire': 691200,
                    'minimum': 3600
                }
            else:
                if name == '@':
                    self.handleRecords(zone)
                else:
                    if zone['child'] is None:
                        zone['child'] = {}
                    
                    # Handle multi-level subdomains
                    if '.' in name:
                        names = name.split('.')[::-1]
                        current = zone

                        for i in range(len(names) - 1):
                            if names[i] not in current['child']:
                                current['child'][names[i]] = {}
                            if i != len(names) - 1:
                                current['child'][names[i]]['child'] = {}
                            current = current['child'][names[i]]
                        
                        self.handleRecords(current['child'][names[-1]], record_type, content, prio)
                    else:
                        if zone['child'][name] is None:
                            zone['child'][name] = {}

                        self.handleRecords(zone['child'][name], record_type, content, prio)
            json.dump(data, f, indent=2)

    def post_update(self, domain_id: str):
        with open(f'{self.config.ZONEFILE_LOCATION}/{domain_id}.json', 'w+') as f:
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

        with open(f'{self.config.COREDNS_LOCATION}/Corefile', 'w+') as f:
            contents = f.read()

            if 'name' not in contents:
                f.write('\n')
                f.write(f'{domain_id} {self.corednsTemplate}')

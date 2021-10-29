from .base import BaseZoneBot


class TinyDNSZoneBot(BaseZoneBot):
    def insert_dns_record(self, domain_id, name, record_type, content, ttl=3600):
        # This func should write a record to a file
        pass

    def pre_update(self, domain_id, domain_data):
        # If you want to write a header of some sorts for a zone, you can do it here I guess
        # This will be executed before the first insert_dns_record is called
        pass

    def get_zone(self, zone_name: str):
        return zone_name

    def needs_updating(self, domain_id, last_modified: int) -> bool:
        return True

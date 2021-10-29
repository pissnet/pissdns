import sqlalchemy

from .base import BaseZoneBot


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


class PowerDNSZoneBot(BaseZoneBot):
    def __init__(self, bot, name: str, config):
        super().__init__(bot, name, config)
        self.engine = sqlalchemy.create_engine(
            config.DATABASE_URL,
        )

    def insert_dns_record(self, domain_id, name, record_type, content, ttl=3600):
        new_r = sqlalchemy.insert(records).values(
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
        self.engine.execute(new_r)

    def get_zone(self, zone_name: str):
        query = domains.select().where(domains.c.name == zone_name)  # noqa
        result = self.engine.execute(query)
        record = result.fetchone()
        if not record:
            # New domain, do the insertion
            new_d = sqlalchemy.insert(domains).values(
                name=zone_name,
                master='',
                last_check=None,
                type="MASTER",
                notified_serial=None,
                account=''
            )
            result = self.engine.execute(new_d)
            domain_id = result.inserted_primary_key
            if not isinstance(domain_id, int) and not isinstance(domain_id, str):
                domain_id = domain_id[0]
        else:
            domain_id = int(record[0])

        return domain_id

    def needs_updating(self, domain_id, last_modified: int) -> bool:
        # Check if we need to update records by comparing the timestamp in the SOA record
        query = records.select().where((records.c.domain_id == domain_id) & (records.c.type == 'SOA'))
        result = self.engine.execute(query)
        soa_ts = ""
        if record := result.fetchone():
            soa_ts = record[4].split(" ")[2]

        return soa_ts == last_modified

    def pre_update(self, domain_id, _):
        # Delete all old records
        query = records.delete().where(records.c.domain_id == domain_id)
        self.engine.execute(query)

# Either powerdns or tinydns
DNS_SERVER = "powerdns"

# IRC Nick
NICK = "Pissco_ns1"
# IRC Server
SERVER = "irc.shitposting.space"

# Powerdns database
DATABASE_URL = "mysql://foo:bar@127.0.0.1/powerdns"

# Hellomouse dns zone locations
ZONEFILE_LOCATION = "/home/pissdns/zones"
COREDNS_LOCATION = "/home/pissdns/coredns"
IPV6_ADDR = "2a02:6b8::"
IPV4_ADDR = "1.1.1.1"

# Domain_id of the stuff we should not delete!
DO_NOT_DELETE_DOMAINS = [1, 2]


# for the SOA records
SOA_NS = "ns1.pissnet.cc."
SOA_EMAIL = "hostmaster.piss.domains."

# We will add these nameservers to the zone
NAMESERVERS = [
    'a.piss.domains', 'b.piss.domains', 'c.piss.domains'
]

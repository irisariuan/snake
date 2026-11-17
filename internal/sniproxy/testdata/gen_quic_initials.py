# Generates real client Initial datagrams with aioquic for snake's tests.
import sys
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.packet import QuicProtocolVersion

def initial(name, version):
    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"], server_name=name)
    cfg.supported_versions = [version]
    conn = QuicConnection(configuration=cfg)
    conn.connect(("203.0.113.9", 443), now=0.0)
    return [d for d, _ in conn.datagrams_to_send(now=0.0)]

for name, ver, label in [("www.netflix.com", QuicProtocolVersion.VERSION_1, "v1"),
                         ("video.example.org", QuicProtocolVersion.VERSION_2, "v2")]:
    for i, d in enumerate(initial(name, ver)):
        print(f"{label} {name} {i} {d.hex()}")

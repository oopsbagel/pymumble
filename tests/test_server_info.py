from mumble import MumbleServerInfo, MumbleUDP_pb2
from tests.server import Server
import time


def test_ping_send_and_response():
    server_response = MumbleUDP_pb2.Ping(  # captured from mumble-server:v1.5.735-0
        timestamp=7407666477802775930,
        server_version_v2=281496499716096,
        user_count=1,
        max_user_count=100,
        max_bandwidth_per_user=558000,
    )
    with Server([server_response], 0.01) as server:
        with MumbleServerInfo() as m:
            print(server.host, server.udp_port)
            srv = m.add_server(server.host, server.udp_port)
            time.sleep(1)  # XXX find a faster way to wait for ping & response

    assert len(m.servers) == 1
    assert m.servers[srv].version is not None
    assert m.servers[srv].user_count == 1
    assert m.servers[srv].max_user_count == 100
    assert m.servers[srv].max_bandwidth_per_user == 558000
    assert m.servers[srv].latency >= 10  # ms
    assert len(server.udp_received_msgs) == 1
    assert int(m.servers[srv].last_ping_sent) == server.udp_received_msgs[0].timestamp
    assert type(server.udp_received_msgs[0]) is MumbleUDP_pb2.Ping
    assert type(server.udp_received_msgs[0].timestamp) is int
    assert server.udp_received_msgs[0].request_extended_information

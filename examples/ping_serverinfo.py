#!/usr/bin/python3

import mumble
import time

mumble_server_info = mumble.MumbleUDPServerInfo(debug=True)
mumble_server_info.add_server("127.0.0.1", 64738)
mumble_server_info.add_server("::1")
time.sleep(20)
for server in mumble_server_info.servers.values():
    print(f"{server.host} {server.port} {server.latency} ms")
mumble_server_info.delete_server("localhost")
time.sleep(10)
mumble_server_info.stop()
for server in mumble_server_info.servers.values():
    print(f"{server.host} {server.port} {server.latency} ms")

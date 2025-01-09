#!/usr/bin/python3

import pymumble
import time

mumble_server_info = pymumble.mumble.MumbleUDPServerInfo(debug=True)
mumble_server_info.add_server("127.0.0.1", 6666)
mumble_server_info.add_server("::1", 6666)
time.sleep(20)
mumble_server_info.delete_server("::1", 6666)
mumble_server_info.join()

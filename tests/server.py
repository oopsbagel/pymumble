import selectors
import socket
import threading
import time

from tests.msgs import udp_decode, udp_encode

ADDR = ("127.0.0.1", 0)


class Server(threading.Thread):
    def __init__(self, udp_responses: list, latency: float = None):
        threading.Thread.__init__(self, name="MumbleTestServerThread", daemon=True)
        self._active = True
        self.latency = latency
        self.ready_event = threading.Event()
        self.udp_responses = udp_responses
        self.udp_received_msgs = []
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_socket.bind(ADDR)
        self.host, self.udp_port = self.udp_socket.getsockname()

    def receive_udp(self, sock):
        data, addr = sock.recvfrom(1024)
        response = udp_encode(self.udp_responses.pop())
        if sock.sendto(response, addr) != len(response):
            raise RuntimeError("Unable to send test response to client.")
        received_msg = udp_decode(data)
        self.udp_received_msgs.append(received_msg)
        return received_msg

    def run(self):
        sel = selectors.DefaultSelector()
        sel.register(self.udp_socket, selectors.EVENT_READ, self.receive_udp)
        self.ready_event.set()
        while self._active:
            events = sel.select(1)
            for key, mask in events:
                if self.latency:
                    time.sleep(self.latency)
                key.data(key.fileobj)

    def __enter__(self):
        self.start()
        if not self.ready_event.wait(1):
            raise RuntimeError("Timeout waiting for server thread to be ready.")
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self._active = False
        self.join()

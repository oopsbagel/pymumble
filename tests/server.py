import selectors
import socket
import ssl
import threading
import time
from collections import deque
from mumble.Mumble_pb2 import Ping

from tests.msgs import tcp_decode, tcp_encode, udp_decode, udp_encode

ADDR = ("127.0.0.1", 0)


class Server(threading.Thread):
    def __init__(
        self, udp_responses: list = [], tls_responses: list = [], latency: float = None
    ):
        threading.Thread.__init__(self, name="MumbleTestServerThread", daemon=True)
        self._active = True
        self.latency = latency
        self.ready_event = threading.Event()

        self.udp_responses = deque(udp_responses)
        self.udp_received_msgs = []
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_socket.bind(ADDR)
        self.host, self.udp_port = self.udp_socket.getsockname()

        self.tls_responses = deque(tls_responses)
        self.tls_received_msgs = []
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain("tests/cert.pem", "tests/key.pem")
        self.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_socket.bind(ADDR)
        _, self.tls_port = self.tcp_socket.getsockname()
        self.tls_socket = context.wrap_socket(self.tcp_socket, server_side=True)

        self.selector = selectors.DefaultSelector()
        self.selector.register(self.udp_socket, selectors.EVENT_READ, self.receive_udp)
        self.selector.register(self.tls_socket, selectors.EVENT_READ, self.accept_tls)

    def receive_udp(self, sock):
        data, addr = sock.recvfrom(1024)
        received_msg = udp_decode(data)
        self.udp_received_msgs.append(received_msg)

        if len(self.udp_responses) != 0:
            response = udp_encode(self.udp_responses.popleft())
            if response is not None:
                if sock.sendto(response, addr) != len(response):
                    raise RuntimeError("Unable to send test response to client.")

        return received_msg

    def accept_tls(self, sock):
        conn, addr = sock.accept()
        self.selector.register(conn, selectors.EVENT_READ, self.receive_tls)

    def receive_tls(self, sock):
        data = sock.recv(1024)
        if len(data) == 0:
            return  # the socket is closed XXX gracefully handle otherwise
        received_msgs = tcp_decode(data)
        self.tls_received_msgs.append(received_msgs)

        if len(received_msgs) == 1 and type(received_msgs[0]) is Ping:
            pong = tcp_encode([Ping(timestamp=received_msgs[0].timestamp)])
            if sock.send(pong) != len(pong):
                raise RuntimeError("Unable to send ping response to client.")

        elif len(self.tls_responses) != 0:
            response_msgs = self.tls_responses.popleft()
            if response_msgs is not None:
                responses = tcp_encode(response_msgs)
                if sock.send(responses) != len(responses):
                    raise RuntimeError("Unable to send test responses to client.")

        return received_msgs

    def run(self):
        self.tls_socket.listen()
        self.ready_event.set()
        while self._active:
            events = self.selector.select(1)
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

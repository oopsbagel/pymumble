# -*- coding: utf-8 -*-
from __future__ import annotations
import threading
import logging
import time
import select
import socket
import ssl
import struct
import google.protobuf.message as protobuf_message
from typing import Optional

from .errors import ConnectionRejectedError
from .constants import (
    CONN_STATE,
    CALLBACK,
    CMD,
    TCP_MSG_TYPE,
    UDP_MSG_TYPE,
    PING_INTERVAL,
    PROTOCOL_VERSION,
    VERSION_STRING,
    OS_STRING,
    OS_VERSION_STRING,
    TCP_READ_BUFFER_SIZE,
    AUDIO_CODEC,
    BANDWIDTH,
    AUDIO_PER_PACKET,
    MAX_UDP_PACKET_SIZE,
    CLIENT_TYPE,
    CONNECTION_RETRY_INTERVAL,
    OPUS_PROFILE,
)
from .crypto import CryptStateOCB2, DecryptFailedException
from . import users
from . import channels
from . import blobs
from . import commands
from . import callbacks

from . import Mumble_pb2
from . import MumbleUDP_pb2


def _wrap_socket(
    sock, keyfile=None, certfile=None, verify_mode=ssl.CERT_NONE, server_hostname=None
):
    try:
        ssl_context = ssl.create_default_context()
        if certfile:
            ssl_context.load_cert_chain(certfile, keyfile)
        ssl_context.check_hostname = (verify_mode != ssl.CERT_NONE) and (
            server_hostname is not None
        )
        ssl_context.verify_mode = verify_mode
        return ssl_context.wrap_socket(sock, server_hostname=server_hostname)
    except AttributeError:
        try:
            return ssl.wrap_socket(
                sock,
                keyfile,
                certfile,
                cert_reqs=verify_mode,
                ssl_version=ssl.PROTOCOL_TLS,
            )
        except AttributeError:
            return ssl.wrap_socket(
                sock,
                keyfile,
                certfile,
                cert_reqs=verify_mode,
                ssl_version=ssl.PROTOCOL_TLSv1,
            )


class ServerInfo:
    "Store latency and extended server information for unauthenticated servers"

    host: str
    port: int
    socket: socket.socket
    latency: int
    version: str
    max_user_count: int
    max_bandwidth_per_user: int
    user_count: int
    last_ping_sent: float
    last_ping_recv: float

    def __init__(self, host, port):
        self.host = host
        self.port = port
        server_family = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)[0][0]
        self.socket = socket.socket(server_family, socket.SOCK_DGRAM)
        self.socket.connect((host, port))
        self.latency = None
        self.last_ping_sent = 0
        self.last_ping_recv = None
        self.user_count = None
        self.version = None
        self.max_user_count = None
        self.max_bandwidth_per_user = None


class MumbleServerInfo(threading.Thread):
    """Manage unencrypted pings to retrieve server latency and extendend information.

    Sends an unencrypted UDP ping every ping_interval seconds.
    Records server information in servers dict indexed by (host, port) tuples.
    Remove servers with delete_server(host, port).

    :param ping_interval: Time between pings in seconds.
    :param loop_rate: Client tick rate in seconds.
    :param debug: Send debugging messages to `stdout`.
    """

    def __init__(self, ping_interval=PING_INTERVAL, loop_rate=0.01, debug=False):
        threading.Thread.__init__(self, name="MumbleUDPServerInfoThread", daemon=True)
        self._active = True  # semaphore for whether to allow run() to terminate
        self._loop_rate = loop_rate
        self._ping_interval = ping_interval
        self.ready_event = threading.Event()
        self.servers = {}

        self.Log = logging.getLogger("PyMumbleUDPServerInfo")
        if debug:
            self.Log.setLevel(logging.DEBUG)
        sh = logging.StreamHandler()
        sh.setLevel(logging.DEBUG)
        formatter = logging.Formatter("%(asctime)s-%(name)s-%(levelname)s-%(message)s")
        sh.setFormatter(formatter)
        self.Log.addHandler(sh)

    def __enter__(self) -> MumbleServerInfo:
        self.start()
        if not self.ready_event.wait(1):
            raise RuntimeError("Timed out waiting for MumbleServerInfo to start.")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> False:
        self.stop()
        self.join()
        return False  # completed successfully, do not suppress the raised exception

    def add_server(self, host: str, port: int = 64738) -> tuple[str, int]:
        """Register a server to continuously ping every `self._ping_interval` seconds.

        The return value's `host` field may differ than the provided parameter based on
        the return value of ``socket.getpeername()``.

        :param host: The Mumble server domain name or IP address.
        :param port: The Mumble server port.
        :return: A tuple in the form ``(host, port)`` used as the `.servers` key.
        """
        server = ServerInfo(host, port)
        peername = server.socket.getpeername()
        self.servers[peername] = server
        return peername

    def delete_server(self, host: str, port: int = 64738) -> ServerInfo | None:
        """Stop pinging a server. Removes the :class:`ServerInfo` object from `.servers`.

        Does nothing if the server is not found.

        :param host: The Mumble server domain name or IP address.
        :param port: The Mumble server port.
        :return: The server's :class:`ServerInfo` object.
        """
        addrinfo = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)[0][4]
        server_info = self.servers.get(addrinfo)
        if addrinfo in self.servers:
            del self.servers[addrinfo]
        return server_info

    def stop(self) -> None:
        "Stop the thread without deleting the recorded data."
        self._active = False

    def _ping_server(self, server: ServerInfo) -> None:
        """Send an unencrypted :class:`MumbleUDP_pb2.Ping` message to `server` requesting
        extended information.

        :param server: The :class:`ServerInfo` object containing an active :type:`socket.socket`.
        """
        ping = MumbleUDP_pb2.Ping(
            timestamp=int(time.time()), request_extended_information=True
        )
        msg = struct.pack("!B", UDP_MSG_TYPE.Ping) + ping.SerializeToString()
        self.Log.debug("pinging %s %s" % (server.host, server.port))
        server.socket.sendto(msg, (server.host, server.port))

    def _receive_ping(self, ping: MumbleUDP_pb2.Ping, server: ServerInfo) -> None:
        """Record server information contained in `ping` in `server`.

        :param ping: The received :class:`MumbleUDP_pb2.Ping` from the server.
        :param server: The :class:`ServerInfo` object to record data into.
        """
        server.last_ping_recv = int(time.time() * 1000)
        server.latency = server.last_ping_recv - int(server.last_ping_sent * 1000)
        server.version = ping.server_version_v2
        server.user_count = ping.user_count
        server.max_user_count = ping.max_user_count
        server.max_bandwidth_per_user = ping.max_bandwidth_per_user

    def run(self):
        """Send periodic pings to servers and read responses until `self._active` is False.
        Set `self.ready_event` when starting.
        """
        self.ready_event.set()
        while self._active:
            sockets = []
            for server in self.servers.values():
                sockets.append(server.socket)
                if server.last_ping_sent + self._ping_interval <= time.time():
                    self._ping_server(server)
                    server.last_ping_sent = time.time()

            (rlist, wlist, xlist) = select.select(sockets, [], sockets, self._loop_rate)
            for sock in rlist:
                self._read_udp_message(sock)
            for sock in xlist:
                for server in self.servers.values():
                    if server.socket is sock:
                        self.delete_server(server.host, server.port)

    def _read_udp_message(self, sock: socket.socket) -> None:
        """Read a message from `sock` and attempt to decode as a `MumbleUDP_pb2`
        protocol buffer message. Ignores Audio type messages, and dispatches
        Ping type messages to :func:`_receive_ping:`.

        :param sock: The socket to read from.
        """
        try:
            buffer = sock.recv(MAX_UDP_PACKET_SIZE)
        except socket.error as e:
            self.Log.warn("error reading from socket: %s" % e)
            return

        if len(buffer) < 2:  # This datagram is too short to be a MumbleUDP.Ping.
            return

        header, message = (
            buffer[0],
            buffer[1:],
        )  # No need to unpack the header as a single byte is automatically cast to int in Python.
        try:
            msgtype = UDP_MSG_TYPE(header)
        except ValueError:
            self.Log.warn("received UDP message of unknown type, ignoring")
            return

        match msgtype:
            case UDP_MSG_TYPE.Audio:
                self.Log.debug("message: UDP Audio : must be encrypted")

            case UDP_MSG_TYPE.Ping:
                ping = MumbleUDP_pb2.Ping()
                try:
                    ping.ParseFromString(message)
                except protobuf_message.DecodeError as e:
                    self.Log.warn("unable to decode message as UDP Ping: %s" % e)
                    return
                self.Log.debug("message: UDP Ping : %s" % ping)
                server = self.servers[sock.getpeername()]
                self._receive_ping(ping, server)


class MumbleUDP(threading.Thread):
    def __init__(
        self,
        mumble: Mumble,
        key: bytes,
        client_nonce: bytearray,
        server_nonce: bytearray,
        host: str,
        port: int = 64738,
        debug=False,
    ):
        threading.Thread.__init__(self, name="MumbleUDPThread", daemon=True)
        self._host = host
        self._port = port
        self._active = True  # semaphore for whether to allow run() to terminate
        self._last_ping_sent = 0
        self._mumble = mumble
        self._loop_rate = mumble.loop_rate
        self._socket = None
        self._crypt = CryptStateOCB2()
        self._crypt.set_key(key, client_nonce, server_nonce)

        self.log = logging.getLogger("PyMumbleUDP")
        formatter = logging.Formatter("%(asctime)s-%(name)s-%(levelname)s-%(message)s")
        if debug:
            self.log.setLevel(logging.DEBUG)
        sh = logging.StreamHandler()
        sh.setLevel(logging.DEBUG)
        sh.setFormatter(formatter)
        self.log.addHandler(sh)

    def _ping(self):
        ping = MumbleUDP_pb2.Ping(timestamp=int(time.time()))
        msg = struct.pack("!B", UDP_MSG_TYPE.Ping) + ping.SerializeToString()
        self.log.debug("sending encrypted ping: %s", msg.hex)
        self.encrypt_and_send(msg)

    def _read_message(self):
        try:
            buffer = self._socket.recv(MAX_UDP_PACKET_SIZE)
        except socket.error as e:
            self.log.warn("error reading from udp encrypted socket: %s" % e)
            return
        if len(buffer) < 4:
            self.log.debug("udp encrypted message is too short: %i", len(buffer))
            return
        try:
            plaintext = self._crypt.decrypt(
                buffer, len(buffer) - 4
            )  # OCB2 header is 4 bytes
        except DecryptFailedException as e:
            self.log.warn("error decrypting udp packet: %s" % e)
            return
        msg = MumbleUDP.decode_message(self.log, plaintext)
        match type(msg):
            case MumbleUDP_pb2.Audio:
                if self._mumble.enable_audio:
                    MumbleUDP.receive_audio(self._mumble, msg)
            case MumbleUDP_pb2.Ping:
                return

    def run(self):
        server_family = socket.getaddrinfo(
            self._host, self._port, type=socket.SOCK_DGRAM
        )[0][0]
        self._socket = socket.socket(server_family, socket.SOCK_DGRAM)
        self._socket.connect((self._host, self._port))

        while self._active:
            if self._last_ping_sent + PING_INTERVAL <= time.time():
                self._ping()
                self._last_ping_sent = time.time()

            (rlist, _, xlist) = select.select(
                [self._socket], [], [self._socket], self._loop_rate
            )
            if self._socket in rlist:
                self._read_message()
            elif self._socket in xlist:
                self.log.warn("socket in xlist")

    def encrypt_and_send(self, plaintext: bytes) -> int:
        """Encrypt message with the server's AES key in OCB2 mode and send the ciphertext via the UDP socket.

        :param plaintext: Bytes containing the protobuf encoded message.

        :return: Number of bytes written to socket.
        """
        ciphertext = self._crypt.encrypt(plaintext)
        return self._socket.send(ciphertext)

    @staticmethod
    def decode_message(
        log: logging.Logger, plaintext: bytes
    ) -> Optional[MumbleUDP_pb2.Audio | MumbleUDP_pb2.Ping]:
        """Decode an unencrypted MumbleUDP protobuf message.

        :param log: Configured logging.Logger object.
        :param plaintext: Bytes containing a decrypted MumbleUDP protobuf message.

        :return: A decoded protobuf message object ``Audio``, ``Ping``, or ``None``.
        """
        header, message = plaintext[0], plaintext[1:]
        try:
            msgtype = UDP_MSG_TYPE(header)
        except ValueError:
            log.warn("received UDP message of unknown type, ignoring")
            return

        MsgClass = getattr(MumbleUDP_pb2, msgtype.name)
        decoded_msg = MsgClass()
        try:
            decoded_msg.ParseFromString(message)
        except protobuf_message.DecodeError as e:
            log.warn("unable to decode message as UDP %s: %s" % (msgtype.name, e))
            return
        log.debug(f"message: UDP {msgtype.name} : {decoded_msg}")
        return decoded_msg

    @staticmethod
    def receive_audio(mumble: Mumble, audio: MumbleUDP_pb2.Audio):
        """Add received audio to sending user's receivedaudioqueue and call SOUNDRECEIVED callback.

        :param mumble: The ``mumble.Mumble`` object containing the users dict and callback table.
        :param audio: The decoded protobuf message containing opus encoded audio and metadata.
        """
        newsound = mumble.users[audio.sender_session].sound.add(
            audio.opus_data, audio.frame_number, AUDIO_CODEC.OPUS, audio.context
        )
        if newsound is None:  # audio has been disabled for this user
            return
        mumble.callbacks(
            CALLBACK.SOUND_RECEIVED, mumble.users[audio.sender_session], newsound
        )


class Mumble(threading.Thread):
    """
    Mumble client library main object.

    :param host: The Mumble server domain name or IP address.
    :param user: The username to display when connected to the Mumble server.
    :param port: The Mumble server port.
    :param password: The Mumble server password.
    :param certfile: Path to a Mumble client certificate in `.pem` format.
    :param keyfile: Path to a private key for the Mumble client certificate in `.pem` format.
    :param application: Application name to send to the server.
    :param reconnect: Reconnect if disconnected.
    :param tokens: List of channel access tokens.
    :param stereo: Send stereo audio.
    :param client_type: 0 = regular, 1 = bot.
    :param enable_audio: Send/receive audio.
    :param force_tcp_only: Disable UDP audio/pings and tunnel audio messages through the TCP control channel.
    :param loop_rate: Client tick rate in seconds.
    :param debug: Send debugging messages to `stdout`.
    """

    def __init__(
        self,
        host: str,
        user: str,
        port: int = 64738,
        password: Optional[str] = None,
        certfile: Optional[str] = None,
        keyfile: Optional[str] = None,
        application: str = VERSION_STRING,
        client_type: int = 0,
        tokens: Optional[list[str]] = None,
        enable_audio: bool = True,
        stereo: bool = False,
        reconnect: bool = False,
        force_tcp_only: bool = False,
        loop_rate: float = 0.01,
        debug: bool = False,
    ):
        threading.Thread.__init__(self)

        self.client_type = CLIENT_TYPE(
            client_type
        )  # raise ValueError on invalid client type

        self.Log = logging.getLogger(
            "PyMumble"
        )  # logging object for errors and debugging
        if debug:
            self.Log.setLevel(logging.DEBUG)
        else:
            self.Log.setLevel(logging.ERROR)

        ch = logging.StreamHandler()
        ch.setLevel(logging.DEBUG)
        formatter = logging.Formatter("%(asctime)s-%(name)s-%(levelname)s-%(message)s")
        ch.setFormatter(formatter)
        self.Log.addHandler(ch)

        self.parent_thread = (
            threading.current_thread()
        )  # main thread of the calling application
        self.mumble_thread = None  # thread of the mumble client library

        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.certfile = certfile
        self.keyfile = keyfile
        self.reconnect = reconnect
        self.tokens = tokens
        self.__opus_profile = OPUS_PROFILE
        self.stereo = stereo
        self.client_type = client_type
        self.enable_audio = enable_audio
        self.loop_rate = loop_rate
        self.application = application
        self.debug = debug
        self.force_tcp_only = force_tcp_only
        self.udp_thread = None

        if stereo:
            self.Log.debug("Working in STEREO mode.")
        else:
            self.Log.debug("Working in MONO mode.")

        self.callbacks = callbacks.CallBacks()  # callbacks management

        self.ready_lock = (
            threading.Lock()
        )  # released when the connection is fully established with the server
        self.ready_lock.acquire()

        self.positional = None

    def init_connection(self):
        """Initialize variables that are local to a connection, (needed if the client automatically reconnect)"""
        self.ready_lock.acquire(
            False
        )  # reacquire the ready-lock in case of reconnection

        self.connected = CONN_STATE.NOT_CONNECTED
        self.control_socket = None
        self.media_socket = None  # Not implemented - for UDP media

        self.bandwidth = (
            BANDWIDTH  # reset the outgoing bandwidth to its default before connecting
        )
        self.server_max_bandwidth = None
        self.udp_active = False

        # defaults according to https://wiki.mumble.info/wiki/Murmur.ini
        self.server_allow_html = True
        self.server_max_message_length = 5000
        self.server_max_image_message_length = 131072

        self.users = users.Users(
            self, self.callbacks
        )  # contains the server's connected users information
        self.channels = channels.Channels(
            self, self.callbacks
        )  # contains the server's channels information
        self.blobs = blobs.Blobs(self)  # manage the blob objects
        if self.enable_audio:
            from .sendaudio import SendAudio

            self.send_audio = SendAudio(
                self,
                AUDIO_PER_PACKET,
                self.bandwidth,
                stereo=self.stereo,
                opus_profile=self.__opus_profile,
            )  # manage the outgoing sounds
        else:
            self.send_audio = None
        self.commands = (
            commands.Commands()
        )  # manage commands sent between the main and the mumble threads

        self.receive_buffer = bytes()  # initialize the control connection input buffer
        self.ping_stats = {
            "last_rcv": 0,
            "time_send": 0,
            "nb": 0,
            "avg": 40.0,
            "var": 0.0,
        }  # Set / reset ping stats

    def run(self):
        """Connect to the server and start the loop in its thread.  Retry if requested"""
        self.mumble_thread = threading.current_thread()

        # loop if auto-reconnect is requested
        while True:
            self.init_connection()  # reset the connection-specific object members

            if self.connect() >= CONN_STATE.FAILED:  # some error occurred, exit here
                self.ready_lock.release()
                if not self.reconnect or not self.parent_thread.is_alive():
                    raise ConnectionRejectedError(
                        "Connection error with the Mumble (murmur) Server"
                    )
                else:
                    time.sleep(CONNECTION_RETRY_INTERVAL)
                    continue

            try:
                self.loop()
            except socket.error:
                self.connected = CONN_STATE.NOT_CONNECTED

            if not self.reconnect or not self.parent_thread.is_alive():
                self.callbacks(CALLBACK.DISCONNECTED)
                break

            self.callbacks(CALLBACK.DISCONNECTED)
            time.sleep(CONNECTION_RETRY_INTERVAL)

    def connect(self):
        """Connect to the server"""
        try:
            # Get IPv4/IPv6 server address
            server_info = socket.getaddrinfo(
                self.host, self.port, type=socket.SOCK_STREAM
            )

            # Connect the SSL tunnel
            self.Log.debug(
                "connecting to %s (%s) on port %i.",
                self.host,
                server_info[0][1],
                self.port,
            )
            std_sock = socket.socket(server_info[0][0], socket.SOCK_STREAM)
            std_sock.settimeout(10)
        except socket.error:
            self.connected = CONN_STATE.FAILED
            return self.connected

        # FIXME: Default verify_mode and server_hostname are not safe, as no
        #        certificate checks are performed.
        self.control_socket = _wrap_socket(std_sock, self.keyfile, self.certfile)
        try:
            self.control_socket.connect((self.host, self.port))
            self.control_socket.setblocking(False)

            # Perform the Mumble authentication
            version = Mumble_pb2.Version()
            if PROTOCOL_VERSION[2] > 255:
                version.version_v1 = (
                    (PROTOCOL_VERSION[0] << 16) + (PROTOCOL_VERSION[1] << 8) + 255
                )
            else:
                version.version_v1 = (
                    (PROTOCOL_VERSION[0] << 16)
                    + (PROTOCOL_VERSION[1] << 8)
                    + (PROTOCOL_VERSION[2])
                )
            version.version_v2 = (
                (PROTOCOL_VERSION[0] << 48)
                + (PROTOCOL_VERSION[1] << 32)
                + (PROTOCOL_VERSION[2] << 16)
            )
            version.release = self.application
            version.os = OS_STRING
            version.os_version = OS_VERSION_STRING
            self.Log.debug("sending: version: %s", version)
            self.send_message(TCP_MSG_TYPE.Version, version)

            authenticate = Mumble_pb2.Authenticate()
            authenticate.username = self.user
            if self.password:
                authenticate.password = self.password
            if self.tokens:
                authenticate.tokens.extend(self.tokens)
            authenticate.opus = True
            authenticate.client_type = self.client_type
            self.Log.debug("sending: authenticate: %s", authenticate)
            self.send_message(TCP_MSG_TYPE.Authenticate, authenticate)
        except socket.error:
            self.connected = CONN_STATE.FAILED
            return self.connected

        self.connected = CONN_STATE.AUTHENTICATING
        return self.connected

    def loop(self):
        """
        Main loop
        waiting for a message from the server for maximum self.loop_rate time
        take care of sending the ping
        take care of sending the queued commands to the server
        check on every iteration for outgoing sound
        check for disconnection
        """
        self.Log.debug("entering loop")
        self.exit = False

        last_ping = time.time()  # keep track of the last ping time

        # loop as long as the connection and the parent thread are alive
        while (
            self.connected not in (CONN_STATE.NOT_CONNECTED, CONN_STATE.FAILED)
            and self.parent_thread.is_alive()
            and not self.exit
        ):
            if (
                last_ping + PING_INTERVAL <= time.time()
            ):  # when it is time, send the ping
                self.ping()
                last_ping = time.time()

            if self.connected == CONN_STATE.CONNECTED:
                while self.commands.is_cmd():
                    self.treat_command(
                        self.commands.pop_cmd()
                    )  # send the commands coming from the application to the server

                if self.send_audio:
                    self.send_audio.send_audio()  # send outgoing audio if available

            (rlist, wlist, xlist) = select.select(
                [self.control_socket], [], [self.control_socket], self.loop_rate
            )  # wait for a socket activity

            if (
                self.control_socket in rlist
            ):  # something to be read on the control socket
                self.read_control_messages()
            elif self.control_socket in xlist:  # socket was closed
                self.control_socket.close()
                self.connected = CONN_STATE.NOT_CONNECTED

    def ping(self):
        """Send the keepalive through available channels"""
        ping = Mumble_pb2.Ping()
        ping.timestamp = int(time.time())
        ping.tcp_ping_avg = self.ping_stats["avg"]
        ping.tcp_ping_var = self.ping_stats["var"]
        ping.tcp_packets = self.ping_stats["nb"]

        self.Log.debug("sending: ping: %s", ping)
        self.send_message(TCP_MSG_TYPE.Ping, ping)
        self.ping_stats["time_send"] = int(time.time() * 1000)
        self.Log.debug(self.ping_stats["last_rcv"])
        if self.ping_stats["last_rcv"] != 0 and int(
            time.time() * 1000
        ) > self.ping_stats["last_rcv"] + (60 * 1000):
            self.Log.debug("Ping too long ! Disconnected ?")
            self.connected = CONN_STATE.NOT_CONNECTED

    def ping_response(self, mess):
        self.ping_stats["last_rcv"] = int(time.time() * 1000)
        ping = int(time.time() * 1000) - self.ping_stats["time_send"]
        old_avg = self.ping_stats["avg"]
        nb = self.ping_stats["nb"]
        new_avg = ((self.ping_stats["avg"] * nb) + ping) / (nb + 1)

        try:
            self.ping_stats["var"] = (
                self.ping_stats["var"]
                + pow(old_avg - new_avg, 2)
                + (1 / nb) * pow(ping - new_avg, 2)
            )
        except ZeroDivisionError:
            pass

        self.ping_stats["avg"] = new_avg
        self.ping_stats["nb"] += 1

    def send_message(self, type, message):
        """Send a control message to the server"""
        packet = (
            struct.pack("!HL", type, message.ByteSize()) + message.SerializeToString()
        )

        while len(packet) > 0:
            self.Log.debug("sending message")
            sent = self.control_socket.send(packet)
            if sent < 0:
                raise socket.error("Server socket error")
            packet = packet[sent:]

    def read_control_messages(self):
        """Read control messages coming from the server"""

        try:
            buffer = self.control_socket.recv(TCP_READ_BUFFER_SIZE)
            self.receive_buffer += buffer
        except socket.error:
            pass

        while len(self.receive_buffer) >= 6:  # header is present (type + length)
            self.Log.debug("read control connection")
            header = self.receive_buffer[0:6]

            if len(header) < 6:
                break

            (type, size) = struct.unpack("!HL", header)  # decode header

            if len(self.receive_buffer) < size + 6:  # if not length data, read further
                break

            # self.Log.debug("message received : " + self.receive_buffer[0:size+6].hex())  # for debugging

            message = self.receive_buffer[6 : size + 6]  # get the control message
            self.receive_buffer = self.receive_buffer[
                size + 6 :
            ]  # remove from the buffer the read part

            self.dispatch_control_message(type, message)

    def dispatch_control_message(self, type, message):
        """Dispatch control messages based on their type"""
        self.Log.debug("dispatch control message")
        if type == TCP_MSG_TYPE.UDPTunnel:  # audio encapsulated in control message
            self.Log.debug("message: UDPTunnel : %s", message)
            if self.enable_audio and self.send_audio:
                self.sound_received(message)

        elif type == TCP_MSG_TYPE.Version:
            mess = Mumble_pb2.Version()
            mess.ParseFromString(message)
            self.Log.debug("message: Version : %s", mess)

        elif type == TCP_MSG_TYPE.Authenticate:
            mess = Mumble_pb2.Authenticate()
            mess.ParseFromString(message)
            self.Log.debug("message: Authenticate : %s", mess)

        elif type == TCP_MSG_TYPE.Ping:
            mess = Mumble_pb2.Ping()
            mess.ParseFromString(message)
            self.Log.debug("message: Ping : %s", mess)
            self.ping_response(mess)

        elif type == TCP_MSG_TYPE.Reject:
            mess = Mumble_pb2.Reject()
            mess.ParseFromString(message)
            self.Log.debug("message: reject : %s", mess)
            self.connected = CONN_STATE.FAILED
            self.ready_lock.release()
            raise ConnectionRejectedError(mess.reason)

        elif (
            type == TCP_MSG_TYPE.ServerSync
        ):  # this message finish the connection process
            mess = Mumble_pb2.ServerSync()
            mess.ParseFromString(message)
            self.Log.debug("message: serversync : %s", mess)
            self.users.set_myself(mess.session)
            self.server_max_bandwidth = mess.max_bandwidth
            self.set_bandwidth(mess.max_bandwidth)

            if self.connected == CONN_STATE.AUTHENTICATING:
                self.connected = CONN_STATE.CONNECTED
                self.ready_lock.release()  # release the ready-lock
                self.callbacks(CALLBACK.CONNECTED)

        elif type == TCP_MSG_TYPE.ChannelRemove:
            mess = Mumble_pb2.ChannelRemove()
            mess.ParseFromString(message)
            self.Log.debug("message: ChannelRemove : %s", mess)

            self.channels.remove(mess.channel_id)

        elif type == TCP_MSG_TYPE.ChannelState:
            mess = Mumble_pb2.ChannelState()
            mess.ParseFromString(message)
            self.Log.debug("message: channelstate : %s", mess)

            self.channels.update(mess)

        elif type == TCP_MSG_TYPE.UserRemove:
            mess = Mumble_pb2.UserRemove()
            mess.ParseFromString(message)
            self.Log.debug("message: UserRemove : %s", mess)

            self.users.remove(mess)

        elif type == TCP_MSG_TYPE.UserState:
            mess = Mumble_pb2.UserState()
            mess.ParseFromString(message)
            self.Log.debug("message: userstate : %s", mess)

            self.users.update(mess)

        elif type == TCP_MSG_TYPE.BanList:
            mess = Mumble_pb2.BanList()
            mess.ParseFromString(message)
            self.Log.debug("message: BanList : %s", mess)

        elif type == TCP_MSG_TYPE.TextMessage:
            mess = Mumble_pb2.TextMessage()
            mess.ParseFromString(message)
            self.Log.debug("message: TextMessage : %s", mess)

            self.callbacks(CALLBACK.TEXT_MESSAGE_RECEIVED, mess)

        elif type == TCP_MSG_TYPE.PermissionDenied:
            mess = Mumble_pb2.PermissionDenied()
            mess.ParseFromString(message)
            self.Log.debug("message: PermissionDenied : %s", mess)

            self.callbacks(CALLBACK.PERMISSION_DENIED, mess)

        elif type == TCP_MSG_TYPE.ACL:
            mess = Mumble_pb2.ACL()
            mess.ParseFromString(message)
            self.Log.debug("message: ACL : %s", mess)
            self.channels[mess.channel_id].update_acl(mess)
            self.callbacks(CALLBACK.ACL_RECEIVED, mess)

        elif type == TCP_MSG_TYPE.QueryUsers:
            mess = Mumble_pb2.QueryUsers()
            mess.ParseFromString(message)
            self.Log.debug("message: QueryUsers : %s", mess)

        elif type == TCP_MSG_TYPE.CryptSetup:
            mess = Mumble_pb2.CryptSetup()
            mess.ParseFromString(message)
            self.Log.debug("message: CryptSetup : %s", mess)
            if not self.force_tcp_only:
                self.udp_thread = MumbleUDP(
                    self,
                    mess.key,
                    bytearray(mess.client_nonce),
                    bytearray(mess.server_nonce),
                    host=self.host,
                    port=self.port,
                    debug=self.debug,
                )
                self.udp_thread.start()

        elif type == TCP_MSG_TYPE.ContextActionModify:
            mess = Mumble_pb2.ContextActionModify()
            mess.ParseFromString(message)
            self.Log.debug("message: ContextActionModify : %s", mess)

            self.callbacks(CALLBACK.CONTEXT_ACTION_RECEIVED, mess)

        elif type == TCP_MSG_TYPE.ContextAction:
            mess = Mumble_pb2.ContextAction()
            mess.ParseFromString(message)
            self.Log.debug("message: ContextAction : %s", mess)

        elif type == TCP_MSG_TYPE.UserList:
            mess = Mumble_pb2.UserList()
            mess.ParseFromString(message)
            self.Log.debug("message: UserList : %s", mess)

        elif type == TCP_MSG_TYPE.VoiceTarget:
            mess = Mumble_pb2.VoiceTarget()
            mess.ParseFromString(message)
            self.Log.debug("message: VoiceTarget : %s", mess)

        elif type == TCP_MSG_TYPE.PermissionQuery:
            mess = Mumble_pb2.PermissionQuery()
            mess.ParseFromString(message)
            self.Log.debug("message: PermissionQuery : %s", mess)

        elif type == TCP_MSG_TYPE.CodecVersion:
            mess = Mumble_pb2.CodecVersion()
            mess.ParseFromString(message)
            self.Log.debug("message: CodecVersion : %s", mess)
            if self.send_audio:
                self.send_audio.set_default_codec(mess)

        elif type == TCP_MSG_TYPE.UserStats:
            mess = Mumble_pb2.UserStats()
            mess.ParseFromString(message)
            self.Log.debug("message: UserStats : %s", mess)

        elif type == TCP_MSG_TYPE.RequestBlob:
            mess = Mumble_pb2.RequestBlob()
            mess.ParseFromString(message)
            self.Log.debug("message: RequestBlob : %s", mess)

        elif type == TCP_MSG_TYPE.ServerConfig:
            mess = Mumble_pb2.ServerConfig()
            mess.ParseFromString(message)
            self.Log.debug("message: ServerConfig : %s", mess)
            for line in str(mess).split("\n"):
                items = line.split(":")
                if len(items) != 2:
                    continue
                if items[0] == "allow_html":
                    self.server_allow_html = items[1].strip() == "true"
                elif items[0] == "message_length":
                    self.server_max_message_length = int(items[1].strip())
                elif items[0] == "image_message_length":
                    self.server_max_image_message_length = int(items[1].strip())

    def set_bandwidth(self, bandwidth):
        """Set the total allowed outgoing bandwidth"""
        if (
            self.server_max_bandwidth is not None
            and bandwidth > self.server_max_bandwidth
        ):
            self.bandwidth = self.server_max_bandwidth
        else:
            self.bandwidth = bandwidth

        if self.send_audio:
            self.send_audio.set_bandwidth(
                self.bandwidth
            )  # communicate the update to the outgoing audio manager

    def sound_received(self, plaintext):
        """Receive a plaintext UDPTunneled MumbleUDP message"""
        msg = MumbleUDP.decode_message(self.Log, plaintext)
        match type(msg):
            case MumbleUDP_pb2.Audio:
                audio = msg
                self.Log.debug(
                    "audio packet received from %i, sequence %i, type:%i, target:%i, length:%i, terminator:%s",
                    audio.sender_session,
                    audio.frame_number,
                    AUDIO_CODEC.OPUS,
                    audio.context,
                    len(audio.opus_data),
                    audio.is_terminator,
                )
                MumbleUDP.receive_audio(self, audio)
            case MumbleUDP_pb2.Ping:
                return

    def set_codec_profile(self, profile):
        """set the audio profile"""
        if profile in ["audio", "voip", "restricted_lowdelay"]:
            self.__opus_profile = profile
        else:
            raise ValueError("Unknown profile: " + str(profile))

    def get_codec_profile(self):
        """return the audio profile string"""
        return self.__opus_profile

    def is_ready(self):
        """Wait for the connection to be fully completed.  To be used in the main thread"""
        self.ready_lock.acquire()
        self.ready_lock.release()

    def execute_command(self, cmd, blocking=True):
        """Create a command to be sent to the server.  To be used in the main thread"""
        self.is_ready()

        lock = self.commands.new_cmd(cmd)
        if blocking and self.mumble_thread is not threading.current_thread():
            lock.acquire()
            lock.release()

        return lock

    # TODO: manage a timeout for blocking commands.  Currently, no command actually waits for the server to execute
    # The result of these commands should actually be checked against incoming server updates

    def treat_command(self, cmd):
        """Send the awaiting commands to the server.  Used in the pymumble thread."""
        if cmd.cmd == CMD.MOVE:
            userstate = Mumble_pb2.UserState()
            userstate.session = cmd.parameters["session"]
            userstate.channel_id = cmd.parameters["channel_id"]
            self.Log.debug("Moving to channel")
            self.send_message(TCP_MSG_TYPE.UserState, userstate)
            cmd.response = True
            self.commands.answer(cmd)
        elif cmd.cmd == CMD.TEXT_MESSAGE:
            textmessage = Mumble_pb2.TextMessage()
            textmessage.session.append(cmd.parameters["session"])
            textmessage.channel_id.append(cmd.parameters["channel_id"])
            textmessage.message = cmd.parameters["message"]
            self.send_message(TCP_MSG_TYPE.TextMessage, textmessage)
            cmd.response = True
            self.commands.answer(cmd)
        elif cmd.cmd == CMD.TEXT_PRIVATE_MESSAGE:
            textprivatemessage = Mumble_pb2.TextMessage()
            textprivatemessage.session.append(cmd.parameters["session"])
            textprivatemessage.message = cmd.parameters["message"]
            self.send_message(TCP_MSG_TYPE.TextMessage, textprivatemessage)
            cmd.response = True
            self.commands.answer(cmd)
        elif cmd.cmd == TCP_MSG_TYPE.ChannelState:
            channelstate = Mumble_pb2.ChannelState()
            channelstate.parent = cmd.parameters["parent"]
            channelstate.name = cmd.parameters["name"]
            channelstate.temporary = cmd.parameters["temporary"]
            self.send_message(TCP_MSG_TYPE.ChannelState, channelstate)
            cmd.response = True
            self.commands.answer(cmd)
        elif cmd.cmd == TCP_MSG_TYPE.ChannelRemove:
            channelremove = Mumble_pb2.ChannelRemove()
            channelremove.channel_id = cmd.parameters["channel_id"]
            self.send_message(TCP_MSG_TYPE.ChannelRemove, channelremove)
            cmd.response = True
            self.commands.answer(cmd)
        elif cmd.cmd == CMD.UPDATE_CHANNEL:
            channelstate = Mumble_pb2.ChannelState()
            for key, value in cmd.parameters.items():
                setattr(channelstate, key, value)
            self.send_message(TCP_MSG_TYPE.ChannelState, channelstate)
            cmd.response = True
            self.commands.answer(cmd)
        elif cmd.cmd == CMD.LINK_CHANNEL:
            channelstate = Mumble_pb2.ChannelState()
            channelstate.channel_id = cmd.parameters["channel_id"]
            channelstate.links_add.append(cmd.parameters["add_id"])
            self.send_message(TCP_MSG_TYPE.ChannelState, channelstate)
            cmd.response = True
            self.commands.answer(cmd)
        elif cmd.cmd == CMD.UNLINK_CHANNEL:
            channelstate = Mumble_pb2.ChannelState()
            channelstate.channel_id = cmd.parameters["channel_id"]
            for remove_id in cmd.parameters["remove_ids"]:
                channelstate.links_remove.append(remove_id)
            self.send_message(TCP_MSG_TYPE.ChannelState, channelstate)
            cmd.response = True
            self.commands.answer(cmd)
        elif cmd.cmd == TCP_MSG_TYPE.VoiceTarget:
            textvoicetarget = Mumble_pb2.VoiceTarget()
            textvoicetarget.id = cmd.parameters["id"]
            targets = []
            if cmd.parameters["id"] == 1:
                voicetarget = Mumble_pb2.VoiceTarget.Target()
                voicetarget.channel_id = cmd.parameters["targets"][0]
                targets.append(voicetarget)
            else:
                for target in cmd.parameters["targets"]:
                    voicetarget = Mumble_pb2.VoiceTarget.Target()
                    voicetarget.session.append(target)
                    targets.append(voicetarget)
            textvoicetarget.targets.extend(targets)
            self.send_message(TCP_MSG_TYPE.VoiceTarget, textvoicetarget)
            cmd.response = True
            self.commands.answer(cmd)
        elif cmd.cmd == CMD.MOD_USER_STATE:
            userstate = Mumble_pb2.UserState()
            userstate.session = cmd.parameters["session"]

            if "mute" in cmd.parameters:
                userstate.mute = cmd.parameters["mute"]
            if "self_mute" in cmd.parameters:
                userstate.self_mute = cmd.parameters["self_mute"]
            if "deaf" in cmd.parameters:
                userstate.deaf = cmd.parameters["deaf"]
            if "self_deaf" in cmd.parameters:
                userstate.self_deaf = cmd.parameters["self_deaf"]
            if "suppress" in cmd.parameters:
                userstate.suppress = cmd.parameters["suppress"]
            if "recording" in cmd.parameters:
                userstate.recording = cmd.parameters["recording"]
            if "comment" in cmd.parameters:
                userstate.comment = cmd.parameters["comment"]
            if "texture" in cmd.parameters:
                userstate.texture = cmd.parameters["texture"]
            if "user_id" in cmd.parameters:
                userstate.user_id = cmd.parameters["user_id"]
            if "plugin_context" in cmd.parameters:
                userstate.plugin_context = cmd.parameters["plugin_context"]
            if "listening_channel_add" in cmd.parameters:
                userstate.listening_channel_add.extend(
                    cmd.parameters["listening_channel_add"]
                )
            if "listening_channel_remove" in cmd.parameters:
                userstate.listening_channel_remove.extend(
                    cmd.parameters["listening_channel_remove"]
                )

            self.send_message(TCP_MSG_TYPE.UserState, userstate)
            cmd.response = True
            self.commands.answer(cmd)
        elif cmd.cmd == CMD.REMOVE_USER:
            userremove = Mumble_pb2.UserRemove()
            userremove.session = cmd.parameters["session"]
            userremove.reason = cmd.parameters["reason"]
            userremove.ban = cmd.parameters["ban"]
            self.send_message(TCP_MSG_TYPE.UserRemove, userremove)
            cmd.response = True
            self.commands.answer(cmd)
        elif cmd.cmd == CMD.QUERY_ACL:
            acl = Mumble_pb2.ACL()
            acl.channel_id = cmd.parameters["channel_id"]
            acl.query = True
            self.send_message(TCP_MSG_TYPE.ACL, acl)
            cmd.response = True
            self.commands.answer(cmd)
        elif cmd.cmd == CMD.UPDATE_ACL:
            acl = Mumble_pb2.ACL()
            acl.channel_id = cmd.parameters["channel_id"]
            acl.inherit_acls = cmd.parameters["inherit_acls"]

            for msg_group in cmd.parameters["chan_group"]:
                chan_group = Mumble_pb2.ACL.ChanGroup()
                chan_group.name = msg_group["name"]
                if msg_group["inherited"] is not None:
                    chan_group.inherited = msg_group["inherited"]
                if msg_group["inherit"] is not None:
                    chan_group.inherit = msg_group["inherit"]
                if msg_group["inheritable"] is not None:
                    chan_group.inheritable = msg_group["inheritable"]
                for add_id in msg_group["add"]:
                    chan_group.add.append(add_id)
                for remove_id in msg_group["remove"]:
                    chan_group.remove.append(remove_id)
                acl.groups.append(chan_group)

            for msg_acl in cmd.parameters["chan_acl"]:
                chan_acl = Mumble_pb2.ACL.ChanACL()
                if msg_acl["apply_here"] is not None:
                    chan_acl.apply_here = msg_acl["apply_here"]
                if msg_acl["apply_subs"] is not None:
                    chan_acl.apply_subs = msg_acl["apply_subs"]
                if msg_acl["inherited"] is not None:
                    chan_acl.inherited = msg_acl["inherited"]
                if msg_acl["user_id"] is not None:
                    chan_acl.user_id = msg_acl["user_id"]
                if msg_acl["group"] is not None:
                    chan_acl.group = msg_acl["group"]
                if msg_acl["grant"] is not None:
                    chan_acl.grant = msg_acl["grant"]
                if msg_acl["deny"] is not None:
                    chan_acl.deny = msg_acl["deny"]

                if not chan_acl.inherited:
                    acl.acls.append(chan_acl)

            acl.query = False
            self.send_message(TCP_MSG_TYPE.ACL, acl)
            cmd.response = True
            self.commands.answer(cmd)

    def get_max_message_length(self):
        return self.server_max_message_length

    def get_max_image_length(self):
        return self.server_max_image_message_length

    def my_channel(self):
        return self.channels[self.users.myself["channel_id"]]

    def denial_type(self, n):
        return Mumble_pb2.PermissionDenied.DenyType.Name(n)

    def stop(self):
        self.reconnect = None
        self.exit = True
        self.control_socket.close()

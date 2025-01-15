import struct
from mumble import Mumble_pb2, MumbleUDP_pb2
from mumble.constants import TCP_MSG_TYPE, UDP_MSG_TYPE


def tcp_decode(msg: bytes) -> list:
    offset = 0
    messages = []
    while offset < len(msg):
        msgtype = int.from_bytes(msg[offset : offset + 2])
        length = int.from_bytes(msg[offset + 2 : offset + 6])
        content = msg[offset + 6 : offset + 6 + length]

        mt = TCP_MSG_TYPE(msgtype).name
        print(f"msgtype: {mt}, length: {length}, content: {content.hex()}")
        MsgClass = getattr(Mumble_pb2, mt)
        decoded_msg = MsgClass()
        decoded_msg.ParseFromString(content)
        messages.append(decoded_msg)
        print(decoded_msg)

        offset = offset + 6 + length
    return messages


def udp_decode(msg: bytes) -> MumbleUDP_pb2.Audio | MumbleUDP_pb2.Ping:
    msgtype = msg[0]
    content = msg[1:]

    mt = UDP_MSG_TYPE(msgtype).name
    print(f"msgtype: {mt}, content: {content.hex()}")
    MsgClass = getattr(MumbleUDP_pb2, mt)
    decoded_msg = MsgClass()
    decoded_msg.ParseFromString(content)
    print(decoded_msg)
    return decoded_msg


def udp_encode(msg: MumbleUDP_pb2.Audio | MumbleUDP_pb2.Ping) -> bytes:
    match type(msg):
        case MumbleUDP_pb2.Audio:
            msgtype = UDP_MSG_TYPE.Audio
        case MumbleUDP_pb2.Ping:
            msgtype = UDP_MSG_TYPE.Ping
    return struct.pack("!B", msgtype) + msg.SerializeToString()

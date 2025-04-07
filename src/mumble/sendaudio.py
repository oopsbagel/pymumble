# -*- coding: utf-8 -*-

from time import time
import struct
import threading
import socket
import opuslib

from .constants import (
    AUDIO_CODEC,
    OPUS_PROFILE,
    SAMPLE_RATE,
    SEQUENCE_DURATION,
    SEQUENCE_RESET_INTERVAL,
    TCP_MSG_TYPE,
    UDP_MSG_TYPE,
)
from .errors import CodecNotSupportedError
from .messages import VoiceTarget

from . import MumbleUDP_pb2
from .Mumble_pb2 import CodecVersion


class SendAudio:
    """Manage encoding, packetising and sending 16-bit 48kHz little endian
    linear PCM audio to the server. Buffering is the responsibility of the
    caller. Sound is sent immediately upon receipt.

    Sets the :attr:`queue_empty` event when all audio has been sent to the
    server, and clears the event when new audio is added.

    :param audio_per_packet: Packet audio duration in seconds.
    :param bandwidth: Maximum total outgoing bandwidth.
    :param stereo: Whether to send stereo audio.
    :param opus_profile: The Opus encoder's `intended application`_

    .. _intended application: https://opus-codec.org/docs/opus_api-1.5/group__opus__encoderctls.html#ga18fa17dae52ff8f3eaea314204bf1a36
    """

    audio_per_packet: float  #: Packet audio duration in fractional seconds.
    bandwidth: int  #: Maximum total outgoing bandwidth (including header data).
    queue_empty: (
        threading.Event
    )  #: Set when the unsent audio queue is empty, cleared when the queue is populated.

    def __init__(
        self,
        mumble_object,
        audio_per_packet: float,
        bandwidth: int,
        stereo: bool = False,
        opus_profile: OPUS_PROFILE = OPUS_PROFILE.AUDIO,
    ):
        self.mumble_object = mumble_object

        self.Log = self.mumble_object.Log

        self.pcm = []
        self.lock = threading.Lock()
        self.queue_empty = threading.Event()

        self.codec = None  # codec currently requested by the server
        self.encoder = None  # codec instance currently used to encode
        self.encoder_framesize = None  # size of an audio frame for the current codec (OPUS=audio_per_packet, CELT=0.01s)
        self.opus_profile = opus_profile
        self.channels = 1 if not stereo else 2

        self.set_audio_per_packet(audio_per_packet)
        self.set_bandwidth(bandwidth)

        self.codec_type = None  # codec type number to be used in audio packets
        self.target = 0  # target is not implemented yet, so always 0

        self.sequence_start_time = 0  # time of sequence 1
        self.sequence_last_time = 0  # time of the last emitted packet
        self.sequence = 0  # current sequence

    def send_audio(self):
        """Send all available audio to the server, taking care of the timing."""
        if (
            not self.encoder or len(self.pcm) == 0
        ):  # no codec configured or no audio sent
            self.queue_empty.set()
            return ()

        samples = int(
            self.encoder_framesize * SAMPLE_RATE * 2 * self.channels
        )  # number of samples in an encoder frame

        while (
            len(self.pcm) > 0
            and self.sequence_last_time + self.audio_per_packet <= time()
        ):  # audio to send and time to send it (since last packet)
            current_time = time()
            if (
                self.sequence_last_time + SEQUENCE_RESET_INTERVAL <= current_time
            ):  # waited enough, resetting sequence to 0
                self.sequence = 0
                self.sequence_start_time = current_time
                self.sequence_last_time = current_time
            elif (
                self.sequence_last_time + (self.audio_per_packet * 2) <= current_time
            ):  # give some slack (2*audio_per_frame) before interrupting a continuous sequence
                # calculating sequence after a pause
                self.sequence = int(
                    (current_time - self.sequence_start_time) / SEQUENCE_DURATION
                )
                self.sequence_last_time = self.sequence_start_time + (
                    self.sequence * SEQUENCE_DURATION
                )
            else:  # continuous sound
                self.sequence += int(self.audio_per_packet / SEQUENCE_DURATION)
                self.sequence_last_time = self.sequence_start_time + (
                    self.sequence * SEQUENCE_DURATION
                )

            payload = (
                bytearray()
            )  # content of the whole packet, without tcptunnel header
            audio_encoded = 0  # audio time already in the packet

            while (
                len(self.pcm) > 0 and audio_encoded < self.audio_per_packet
            ):  # more audio to be sent and packet not full
                self.lock.acquire()
                to_encode = self.pcm.pop(0)
                self.lock.release()

                if (
                    len(to_encode) != samples
                ):  # pad to_encode if needed to match sample length
                    to_encode += b"\x00" * (samples - len(to_encode))

                try:
                    encoded = self.encoder.encode(
                        to_encode, len(to_encode) // (2 * self.channels)
                    )
                except opuslib.exceptions.OpusError:
                    encoded = b""

                audio_encoded += self.encoder_framesize

                payload += encoded  # add the frame to the packet

            self.Log.debug(
                "audio packet to send: sequence:{sequence}, type:{type}, length:{len}".format(
                    sequence=self.sequence, type=self.codec_type, len=len(payload)
                )
            )

            audio_pb = MumbleUDP_pb2.Audio()
            audio_pb.target = self.target
            audio_pb.frame_number = self.sequence
            audio_pb.opus_data = bytes(payload)
            if self.mumble_object.positional:
                audio_pb.positional_data = self.mumble_object.positional
            msg = struct.pack("!B", UDP_MSG_TYPE.Audio) + audio_pb.SerializeToString()

            if self.mumble_object.force_tcp_only:
                tcppacket = struct.pack("!HL", TCP_MSG_TYPE.UDPTunnel, len(msg)) + msg
                while len(tcppacket) > 0:
                    sent = self.mumble_object.control_socket.send(tcppacket)
                    if sent < 0:
                        raise socket.error("Server socket error")
                    tcppacket = tcppacket[sent:]
            else:
                self.mumble_object.udp_thread.encrypt_and_send_message(msg)

    def set_audio_per_packet(self, audio_per_packet: float):
        """Set the duration of one packet of audio in seconds. Allowed frame
        durations are 2.5, 5, 10, 20, 40 or 60 ms per the `Opus
        specification`_.

        :param audio_per_packet: The duration of one audio packet in seconds.

        .. _Opus specification: https://datatracker.ietf.org/doc/html/rfc6716#section-3.1
        """
        if audio_per_packet not in (0.0025, 0.005, 0.01, 0.02, 0.04, 0.06):
            raise ValueError(
                "Invalid frame duration. Must be 2.5, 5, 10, 20, 40 or 60 ms."
            )
        self.audio_per_packet = audio_per_packet
        self._create_encoder()

    def set_bandwidth(self, bandwidth: int):
        """Set the outgoing bandwidth. Calculates the header overhead and
        configures the encoder's actual bitrate.

        :param bandwidth: Total outgoing bitrate in bits/second.

        """
        self.bandwidth = bandwidth
        if self.encoder:
            overhead_per_packet = 20  # IP header in bytes
            overhead_per_packet += 3 * int(
                self.audio_per_packet / self.encoder_framesize
            )  # overhead per frame
            if self.mumble_object.udp_active:
                overhead_per_packet += 12  # UDP header
            else:
                overhead_per_packet += 20  # TCP header
                overhead_per_packet += 6  # TCPTunnel encapsulation

            overhead_per_second = int(
                overhead_per_packet * 8 / self.audio_per_packet
            )  # in bits

            self.Log.debug(
                "Bandwidth is {bandwidth}, downgrading to {bitrate} due to the protocol overhead".format(
                    bandwidth=self.bandwidth,
                    bitrate=self.bandwidth - overhead_per_second,
                )
            )

            self.encoder.bitrate = self.bandwidth - overhead_per_second

    def add_sound(self, pcm: list[bytes]) -> threading.Event:
        """Add sound to send to the server to the unsent audio queue.

        :param pcm: Audio encoded in Linear PCM 16-bit 48kHz little endian signed format"""
        if len(pcm) % 2 != 0:  # check that the data is aligned on 2 bytes
            raise Exception("pcm data must be 16 bits")

        self.queue_empty.clear()

        samples = int(
            self.encoder_framesize * SAMPLE_RATE * 2 * self.channels
        )  # number of samples in an encoder frame

        self.lock.acquire()
        if len(self.pcm) and len(self.pcm[-1]) < samples:
            initial_offset = samples - len(self.pcm[-1])
            self.pcm[-1] += pcm[:initial_offset]
        else:
            initial_offset = 0
        for i in range(initial_offset, len(pcm), samples):
            self.pcm.append(pcm[i : i + samples])
        self.lock.release()
        return self.queue_empty

    def clear_buffer(self):
        """Clear the unsent audio buffer."""
        self.lock.acquire()
        self.pcm = []
        self.lock.release()

    def get_buffer_size(self) -> float:
        """:return: The size of the unsent buffer in seconds."""
        return sum(len(chunk) for chunk in self.pcm) / 2.0 / SAMPLE_RATE / self.channels

    def set_default_codec(self, codecversion: CodecVersion):
        """Set the default codec to be used to encode packets.

        :param codecversion: A MumbleProto.CodecVersion protobuf message.
        """
        self.codec = codecversion
        self._create_encoder()

    def _create_encoder(self):
        """Create the encoder instance, and set related constants."""
        if not self.codec:
            return ()

        if self.codec.opus:
            self.encoder = opuslib.Encoder(
                SAMPLE_RATE, self.channels, self.opus_profile
            )
            self.encoder_framesize = self.audio_per_packet
            self.codec_type = AUDIO_CODEC.OPUS
        else:
            raise CodecNotSupportedError("")

        self.set_bandwidth(self.bandwidth)

    def set_whisper(self, target_id: list[int] | int, channel=False):
        """Set whisper target to a specific user, list of users, or channel.

        :param target_id: A session_id or list of session_ids.
        :param channel: Whether the target session_id is a channel."""
        if not target_id:
            return
        if type(target_id) is int:
            target_id = [target_id]
        self.target = 2
        if channel:
            self.target = 1
        cmd = VoiceTarget(self.target, target_id)
        self.mumble_object.execute_command(cmd)

    def remove_whisper(self):
        """Remove the whisper target."""
        self.target = 0
        cmd = VoiceTarget(self.target, [])
        self.mumble_object.execute_command(cmd)

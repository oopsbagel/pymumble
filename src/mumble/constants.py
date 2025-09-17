# -*- coding: utf-8 -*-

import platform
from enum import Enum, IntEnum, StrEnum, auto

VERSION = "2.0.0"

# ============================================================================
# Tunable parameters
# ============================================================================
CONNECTION_RETRY_INTERVAL = 10  # in sec
AUDIO_PER_PACKET = float(20) / 1000  # size of one audio packet in sec
BANDWIDTH = 50 * 1000  # total outgoing bitrate in bit/seconds

# ============================================================================
# Constants
# ============================================================================
PROTOCOL_VERSION = (1, 5, 735)
VERSION_STRING = "pymumble %s" % VERSION
OS_STRING = platform.system() + " " + platform.machine()
OS_VERSION_STRING = "Python %s" % platform.python_version()

TRACE = 9  # custom logging level for Ping messages

PING_INTERVAL = 10  # interval between 2 pings in sec

SAMPLE_RATE = 48000  # in hz

SEQUENCE_DURATION = float(10) / 1000  # in sec
SEQUENCE_RESET_INTERVAL = 5  # in sec
TCP_READ_BUFFER_SIZE = (
    4096  # how much bytes to read at a time from the control socket, in bytes
)
MAX_UDP_PACKET_SIZE = 1024  # from the official C++ implementation


class OPUS_PROFILE(StrEnum):
    """Defines the encoder's `intended application`_.

    .. _intended application: https://opus-codec.org/docs/opus_api-1.5/group__opus__encoderctls.html#ga18fa17dae52ff8f3eaea314204bf1a36
    """

    VOIP = "voip"  #: Process signal for improved speech intelligibility.
    AUDIO = "audio"  #: Favor faithfulness to the original input.
    RESTRICTED_LOWDELAY = "restricted_lowdelay"  #: Configure the minimum possible coding delay by disabling certain modes of operation.


# client connection state
class CONN_STATE(IntEnum):
    NOT_CONNECTED = 0
    AUTHENTICATING = 1
    CONNECTED = 2
    FAILED = 3


class TCP_MSG_TYPE(IntEnum):
    "Mumble control message types. These names must exactly match the Protocol Buffer Message names."

    Version = 0
    UDPTunnel = 1
    Authenticate = 2
    Ping = 3
    Reject = 4
    ServerSync = 5
    ChannelRemove = 6
    ChannelState = 7
    UserRemove = 8
    UserState = 9
    BanList = 10
    TextMessage = 11
    PermissionDenied = 12
    ACL = 13
    QueryUsers = 14
    CryptSetup = 15
    ContextActionModify = 16
    ContextAction = 17
    UserList = 18
    VoiceTarget = 19
    PermissionQuery = 20
    CodecVersion = 21
    UserStats = 22
    RequestBlob = 23
    ServerConfig = 24
    SuggestConfig = 25
    PluginDataTransmission = 26


class UDP_MSG_TYPE(IntEnum):
    "Mumble data message types. These names must exactly match the Protocol Buffer Message names."

    Audio = 0
    Ping = 1


class CLIENT_TYPE(IntEnum):
    REGULAR = 0
    BOT = 1


class AUDIO_CODEC(IntEnum):
    CELT_ALPHA = 0
    PING = 1
    SPEEX = 2
    CELT_BETA = 3
    OPUS = 4


class CMD(Enum):
    "pymumble command types, used as keys when dispatching commands. See :mod:`messages`."

    MOVE = auto()
    MOD_USER_STATE = auto()
    TEXT_MESSAGE = auto()
    TEXT_PRIVATE_MESSAGE = auto()
    LINK_CHANNEL = auto()
    UNLINK_CHANNEL = auto()
    QUERY_ACL = auto()
    UPDATE_ACL = auto()
    REMOVE_USER = auto()
    UPDATE_CHANNEL = auto()

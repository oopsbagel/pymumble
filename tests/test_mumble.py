from mumble import Mumble, Mumble_pb2 as mpb
from tests.server import Server
from pytest import fixture


@fixture
def server_connect():
    yield [  # some values captured from mumble-server:v1.5.735-0
        [
            mpb.Version(
                version_v2=123, release="interesting", os="python", os_version="1"
            )
        ],
        [
            mpb.CryptSetup(
                key=bytes.fromhex(
                    "ba83026a9b443e51232cd0437c6396a2000000000000000070111d00006000000410000ddad37209000000000000000020436f646563"
                ),
                client_nonce=bytes.fromhex(
                    "1f6b6ad1ad79cf43526cfc8490ff5ca3000000000000000001000000000000000b0000000000000032002e0035003200370036003400"
                ),
                server_nonce=bytes.fromhex(
                    "0a03f62b1862072ccdeef8ccfbc191f3000000000000000080101d000060000004100013ae81e4b8000000000000000069735f656e74"
                ),
            ),
            mpb.CodecVersion(
                beta=0,
                prefer_alpha=True,
                alpha=-2147483637,
                opus=True,
            ),
            mpb.ChannelState(
                can_enter=True,
                name="Root",
                channel_id=0,
                max_users=0,
                position=0,
                is_enter_restricted=False,
            ),
            mpb.PermissionQuery(
                channel_id=0,
                permissions=134744846,
            ),
            mpb.UserState(
                name="pi",
                session=11,
                channel_id=0,
            ),
            mpb.ServerSync(
                welcome_text="<br />Welcome to this fake server...<br />",
                max_bandwidth=558000,
                permissions=134744846,
                session=11,
            ),
            mpb.ServerConfig(
                message_length=5000,
                max_users=100,
                image_message_length=131072,
                recording_allowed=True,
                allow_html=True,
            ),
        ],
    ]


def test_connect_disconnect(server_connect):
    with Server(tls_responses=server_connect, latency=0.01) as server:
        m = Mumble(server.host, "pi", port=server.tls_port, debug=True)
        m.start()
        m.wait_until_connected()
        assert m.my_channel()["name"] == "Root"
        m.stop()


def test_context_manager(server_connect):
    with Server(tls_responses=server_connect, latency=0.01) as server:
        with Mumble(server.host, "pi", port=server.tls_port, debug=True) as m:
            assert m.my_channel()["name"] == "Root"


def test_send_text_message_to_channel(server_connect):
    with Server(tls_responses=server_connect, latency=0.01) as server:
        with Mumble(server.host, "pi", port=server.tls_port, debug=True) as m:
            m.my_channel().send_text_message("free luigi!")
    assert len(server.tls_received_msgs) == 3  # Version, Authenticate, TextMessage
    txt = server.tls_received_msgs[-1][0]
    assert type(txt) is mpb.TextMessage
    assert txt.message == "free luigi!"
    assert txt.session == [11]  # from UserState
    assert txt.channel_id == [0]  # from UserState


def test_send_text_message_to_user(server_connect):
    # other_user_connects = mpb.UserState(name="orbital", session=12, channel_id=0)
    # server_connect[-1].extend([other_user_connects])
    with Server(tls_responses=server_connect, latency=0.01) as server:
        with Mumble(server.host, "pi", port=server.tls_port, debug=True) as m:
            m.my_channel().send_text_message("free luigi!")
    assert len(server.tls_received_msgs) == 3  # Version, Authenticate, TextMessage
    txt = server.tls_received_msgs[-1][0]
    assert type(txt) is mpb.TextMessage
    assert txt.message == "free luigi!"
    assert txt.session == [11]  # from UserState
    assert txt.channel_id == [0]  # from UserState

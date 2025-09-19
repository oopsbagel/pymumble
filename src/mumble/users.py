from dataclasses import dataclass, field
from .constants import TCP_MSG_TYPE
from .errors import TextTooLongError, ImageTooBigError
from threading import Lock
from . import messages
from . import Mumble_pb2


class Users:
    """
    Stores a list of User objects, as sent by the server.

    Lookup Users by their name or session ID like a dictionary. Return the
    entire user list as a dictionary with ``.by_name()`` or ``.by_session()``.

    .. code-block:: python

        >>> m.users["console"]
        <User 93 "console" in channel 0>

        >>> m.users[28]
        <User 28 "user" id 1 in channel 0>

        >>> m.users.by_name()
        {'console': <User 93 "console" in channel 0>,
         'user': <User 28 "user" id 1 in channel 1>}

        >>> m.users.by_session()
        {'console': <User 93 "console" in channel 0>,
         'user': <User 28 "user" id 1 in channel 1>}

        # .myself is an alias for your own user session
        >>> m.users.myself == m.users["console"] == m.users[93]
        True
    """

    def __init__(self, connection):
        self.connection = connection
        self.myself = None  # User object of the pymumble thread itself
        self.my_session = None  # session number of the pymumble thread itself
        self.lock = Lock()
        self._users = dict()

    def __getitem__(self, key):
        if type(key) == str:
            return {user.name: user for user in self._users.values()}[key]
        elif type(key) == int:
            return self._users[key]

    def by_name(self):
        "Return a dictionary of User objects indexed by their username."
        return {user.name: user for user in self._users.values()}

    def by_session(self):
        "Return a dictionary of User objects indexed by their session ID."
        return {user.session: user for user in self._users.values()}

    def remove(self, message: Mumble_pb2.UserRemove):
        "Remove a User based on a UserRemove message from the server."
        self.lock.acquire()
        if message.session in self._users:
            user = self._users[message.session]
            del self._users[message.session]
            self.connection.callbacks.user_removed(user, message)
        self.lock.release()

    def set_myself(self, session: int):
        "Mark `session` as this connection's own session ID."
        self.my_session = session
        if session in self._users:
            self.myself = self._users[session]

    def update(self, message: Mumble_pb2.UserState):
        "Create or update a User based on a UserState message from the server."
        self.lock.acquire()
        if message.session not in self._users:
            self._users[message.session] = User(self.connection, message)
            self.connection.callbacks.user_created(self._users[message.session])
            if message.session == self.my_session:
                self.myself = self._users[message.session]
        else:
            actions = self._users[message.session].update(message)
            self.connection.callbacks.user_updated(
                self._users[message.session], actions
            )
        self.lock.release()


class User:
    """
    Tracks a User's state as sent by the server in UserState messages.

    Attributes should be considered read only. Assigning to a documented field
    attribute will send a UserState message to the server requesting the change.
    Changes will be reflected in this instance when the server confirms the
    state change with its own UserState message.

    .. code-block:: python

        >>> m.users.by_name()
        {'console': <User 93 "console" in channel 0>,
         'user': <User 28 "user" id 1 in channel 1>}

        # Sends a TextMessage protobuf message with the contents "hi user!".
        >>> m.users[28].send_text_message(f"hi {m.users[28].name}!")

        # Request the server mark you as self_deaf and self_mute.
        >>> m.users.myself.self_deaf = True
        >>> m.users.myself.self_mute = True

        # Check if "user" is a priority speaker:
        >>> m.users["user"].priority_speaker

        # Attempt to set another user's comment:
        >>> m.users["user"].comment = "no comment"
    """

    session: int  #: User session ID whose state this is.
    name: str  #: utf8 username
    channel_id: int  #: The user's current channel ID.
    #: Registered user ID, if the user is registered on the server.
    user_id: int | None = None
    mute: bool = False  #: If the user is muted by admin.
    deaf: bool = False  #: If the user is deafened by admin.
    suppress: bool = False  #: If the user has been suppressed from talking by a reason other than being muted.
    self_mute: bool = False  #: If the user has self muted.
    self_deaf: bool = False  #: If the user has self deafened.
    priority_speaker: bool = False  #: If the user is a priority speaker.
    recording: bool = False  #: If the user is currently recording.
    comment: str | None = None  #: User comment if it is less than 128 bytes.
    texture: bytes | None = None  #: User image if it is less than 128 bytes.
    cert_hash: str | None = None  #: SHA1 hash of the user certificate.
    #: SHA1 hash of the user comment if it is more than 128 bytes.
    comment_hash: bytes | None = None
    #: SHA1 hash of the user picture if it is more than 128 bytes.
    texture_hash: bytes | None = None
    listening_channels: set[int]  #: The channels the user is listening to.
    #: A list of volume adjustments the user has applied to listeners.
    listening_volume_adjustment: list[tuple[int, float]] | None = None

    def __init__(self, connection, message):
        self.connection = connection
        self.__dict__["listening_channels"] = set()
        # Remote users' channel_id will not be set if they are in the root channel when the client connects.
        self.__dict__["channel_id"] = 0
        self.sound = None
        if self.connection.enable_audio:
            self.create_audio_queue()
        self.update(message)

    def __repr__(self):
        name = f'"{self.name}"'
        if self.user_id:
            name += f" id {self.user_id}"
        return f"<User {self.session} {name} in channel {self.channel_id}>"

    def create_audio_queue(self):
        from .audio import ReceivedAudioQueue

        self.sound = ReceivedAudioQueue(self.connection)

    def update(self, message):
        """
        Update a user's information from a UserState message.
        Returns a dictionary of changed values.
        """
        changes = dict()

        for channel in message.listening_channel_add:
            self.listening_channels.add(channel)
        for channel in message.listening_channel_remove:
            self.listening_channels.remove(channel)

        if message.HasField("comment_hash"):
            if message.HasField("comment"):
                self.connection.blobs[message.comment_hash] = message.comment
            else:
                self.connection.blobs.get_user_comment(message.comment_hash)
        if message.HasField("texture_hash"):
            if message.HasField("texture"):
                self.connection.blobs[message.texture_hash] = message.texture
            else:
                self.connection.blobs.get_user_texture(message.texture_hash)

        for field, value in message.ListFields():
            if field.name in (
                "actor",
                "listening_channel_add",
                "listening_channel_remove",
            ):
                continue
            if getattr(self, field.name, None) != value:
                changes[field.name] = value
            self.__dict__[field.name] = value

        return changes

    def _send(self, params):
        p = {"session": self.session} | params
        cmd = messages.ModUserState(self.connection.users.my_session, p)
        self.connection.execute_command(cmd)

    def __setattr__(self, attr, val):
        FIELDS = [
            "channel_id",
            "user_id",
            "mute",
            "deaf",
            "suppress",
            "self_mute",
            "self_deaf",
            "priority_speaker",
            "recording",
            "comment",
            "texture",
            "plugin_context",
        ]
        if attr in FIELDS:
            return self._send({attr: val})
        elif attr == "listening_channels":
            to_add = val - self.listening_channels
            to_remove = self.listening_channels - val
            if to_add:
                self._send({"listening_channel_add": list(to_add)})
            if to_remove:
                self._send({"listening_channel_remove": list(to_remove)})
        else:
            self.__dict__[attr] = val

    def register(self):
        """Register the user (mostly for myself)"""  # what?
        self._send({"user_id": 0})

    def kick(self, reason=""):
        params = {"session": self.session, "reason": reason, "ban": False}
        cmd = messages.RemoveUser(self.connection.users.my_session, params)
        self.connection.execute_command(cmd)

    def ban(self, reason=""):
        params = {"session": self.session, "reason": reason, "ban": True}
        cmd = messages.RemoveUser(self.connection.users.my_session, params)
        self.connection.execute_command(cmd)

    def move_in(self, channel_id, token=None):
        if token:
            authenticate = Mumble_pb2.Authenticate()
            authenticate.username = self.connection.user
            authenticate.password = self.connection.password
            authenticate.tokens.extend(self.connection.tokens)
            authenticate.tokens.extend([token])
            authenticate.opus = True
            self.connection.Log.debug("sending: authenticate: %s", authenticate)
            self.connection.send_message(TCP_MSG_TYPE.Authenticate, authenticate)

        session = self.connection.users.my_session
        cmd = messages.MoveCmd(session, channel_id)
        self.connection.execute_command(cmd)

    def send_text_message(self, message):
        """Send a text message to the user."""

        if len(message) > self.connection.get_max_image_length() != 0:
            raise ImageTooBigError(self.connection.get_max_image_length())

        if not ("<img" in message and "src" in message):
            if len(message) > self.connection.get_max_message_length() != 0:
                raise TextTooLongError(self.connection.get_max_message_length())

        cmd = messages.TextPrivateMessage(self.session, message)
        self.connection.execute_command(cmd)

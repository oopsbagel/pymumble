from dataclasses import dataclass, field


class Callback:
    """
    Certain Mumble session events may call back to user defined functions.
    Callbacks may pass data to these handler functions. See :class:`Callbacks`
    for a list of parameters per callback type.

    .. note:: Handlers are executed within the main loop thread, so it's
              important to keep processing short to avoid delays with audio
              processing. Handlers that expect a long runtime should spawn a
              new thread.

    .. code-block:: python

        import mumble

        m = mumble.Mumble("127.0.0.1", user="echobot")

        def echo_soundchunk(user, soundchunk):
            "Echo all received sounds."
            m.send_audio.add_sound(soundchunk.pcm)

        m.callbacks.sound_received.set_handler(echo_soundchunk)
        m.start()
        m.join()
    """

    def __init__(self):
        self.handler = None

    def __call__(self, *pos_parameters):
        "Call the registered handler function for this callback."
        if self.handler:
            self.handler(*pos_parameters)

    def get_handler(self):
        "Return the handler function assigned to this callback."
        return self.handler

    def set_handler(self, function):
        "Register the handler function for this callback."
        if not callable(function):
            raise ValueError("Callback handler must be callable.")
        self.handler = function

    def clear_handler(self):
        "Remove the handler function for this callback."
        self.handler = None


@dataclass(slots=True)
class Callbacks:
    #: Called when the client has finished connecting. Sends no parameters.
    connected: Callback = field(default_factory=Callback)
    #: Called when the client has disconnected. Sends no parameters.
    disconnected: Callback = field(default_factory=Callback)
    #: Called when the client detects a new channel.
    #: Sends the channel object as the only parameter.
    channel_created: Callback = field(default_factory=Callback)
    #: Called when the client receives a channel update. Sends the updated
    #: channel object and a dict with all the modified fields as two parameters.
    channel_updated: Callback = field(default_factory=Callback)
    #: Called when a channel is removed.
    #: Sends the removed channel object as the only parameter.
    channel_removed: Callback = field(default_factory=Callback)
    #: Called when a new user connects.
    #: Sends the added user object as the only parameter.
    user_created: Callback = field(default_factory=Callback)
    #: Called when a user's state is updated. Sends the updated user object and
    #: a dict with all the modified fields as two parameters.
    user_updated: Callback = field(default_factory=Callback)
    #: Called when a user is removed. Sends the removed User object and the
    #: mumble message as two parameters.
    user_removed: Callback = field(default_factory=Callback)
    #: Called when a sound is received. Sends the User object that received the
    #: sound and the SoundChunk object itself as two parameters.
    sound_received: Callback = field(default_factory=Callback)
    #: Called when a text message is received.
    #: Sends the received TextMessage protobuf message as the only parameter.
    text_message_received: Callback = field(default_factory=Callback)
    #: Called when a custom context menu is added or removed. Sends the
    #: received ContextActionModify protobuf message as the only parameter.
    context_action_received: Callback = field(default_factory=Callback)
    #: Called when an ACL message is received.
    #: Sends the received ACL protobuf message as the only parameter.
    acl_received: Callback = field(default_factory=Callback)
    #: Called when the PermissionDenied message is received.
    #: Sends the PermissionDenied protobuf message as the only parameter.
    permission_denied: Callback = field(default_factory=Callback)

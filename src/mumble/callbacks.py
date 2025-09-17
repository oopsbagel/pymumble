from dataclasses import dataclass


class Callback:
    """
    Certain Mumble session events may call back to user defined functions.
    More than one handler per callback may be defined with :func:`add_handler`.
    These callbacks may pass data to these handler functions. See
    :class:`Callbacks` for a list of parameters per callback type.

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

        def print_sender_name(user, soundchunk):
            print(f"Received sound from {user['name']}")

        m.callbacks.SOUND_RECEIVED.add_handler(echo_soundchunk)
        m.callbacks.SOUND_RECEIVED.add_handler(print_sender_name)
        m.start()
        m.join()
    """

    def __init__(self):
        self.handlers = list()

    def call_handlers(self, *pos_parameters):
        "Call the registered handler functions for this callback."
        for function in self.handlers:
            function(*pos_parameters)

    def get_handlers(self):
        "Return the handler functions assigned to this callback."
        return self.handlers

    def set_handler(self, function):
        """
        Register the _only_ handler function to call for this callback.
        Removes all other handler functions for this callback.
        """
        if not callable(function):
            raise ValueError("Callback handler must be callable.")
        self.handlers = [function]

    def clear_handlers(self):
        "Remove all handler functions for this callback."
        self.handlers = list()

    def add_handler(self, function):
        "Append a handler function to the list for this callback."
        if not callable(function):
            raise ValueError("Callback handler must be callable.")
        self.handlers.append(function)

    def remove_handler(self, function):
        "Remove all instances of the provided handler function from this callback."
        if not callable(function):
            raise ValueError("Callback handler must be callable.")
        while function in self.handlers:
            self.handlers.remove(function)


@dataclass(slots=True)
class Callbacks:
    CONNECTED = (
        Callback()
    )  #: Called when the client has finished connecting. Sends no parameters.
    DISCONNECTED = (
        Callback()
    )  #: Called when the client has disconnected. Sends no parameters.
    CHANNEL_CREATED = Callback()  #: Called when the client detects a new channel. Sends the channel object as the only parameter.
    CHANNEL_UPDATED = Callback()  #: Called when the client receives a channel update. Sends the updated channel object and a dict with all the modified fields as two parameters.
    CHANNEL_REMOVED = Callback()  #: Called when a channel is removed. Sends the removed channel object as the only parameter.
    USER_CREATED = Callback()  #: Called when a new user connects. Sends the added user object as the only parameter.
    USER_UPDATED = Callback()  #: Called when a user's state is updated. Sends the updated user object and a dict with all the modified fields as two parameters.
    USER_REMOVED = Callback()  #: Called when a user is removed. Sends the removed User object and the mumble message as the only parameter.
    SOUND_RECEIVED = Callback()  #: Called when a sound is received. Sends the User object that received the sound and the SoundChunk object itself as two parameters.
    TEXT_MESSAGE_RECEIVED = Callback()  #: Called when a text message is received. Sends the received TextMessage protobuf message as the only parameter.
    CONTEXT_ACTION_RECEIVED = Callback()  #: Called when a custom context menu is added or removed. Sends the received ContextActionModify protobuf message as the only parameter.
    ACL_RECEIVED = Callback()  #: Called when an ACL message is received. Sends the received ACL protobuf message as the only parameter.
    PERMISSION_DENIED = Callback()  #: Called when the PermissionDenied message is received. Sends the PermissionDenied protobuf message as the only parameter.

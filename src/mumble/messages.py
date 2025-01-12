# -*- coding: utf-8 -*-
from .constants import TCP_MSG_TYPE, CMD
from threading import Lock


class Cmd:
    """
    Define a command object, used to ask an action from the pymumble thread,
    usually to forward to the murmur server
    """

    def __init__(self):
        self.cmd_id = None
        self.lock = Lock()

        self.cmd = None
        self.parameters = None
        self.response = None


class MoveCmd(Cmd):
    """Command to move a user from channel"""

    def __init__(self, session, channel_id):
        Cmd.__init__(self)

        self.cmd = CMD.MOVE
        self.parameters = {"session": session, "channel_id": channel_id}


class TextMessage(Cmd):
    """Command to send a text message"""

    def __init__(self, session, channel_id, message):
        Cmd.__init__(self)

        self.cmd = CMD.TEXT_MESSAGE
        self.parameters = {
            "session": session,
            "channel_id": channel_id,
            "message": message,
        }


class TextPrivateMessage(Cmd):
    """Command to send a private text message"""

    def __init__(self, session, message):
        Cmd.__init__(self)

        self.cmd = CMD.TEXT_PRIVATE_MESSAGE
        self.parameters = {"session": session, "message": message}


class ModUserState(Cmd):
    """Command to change a user state"""

    def __init__(self, session, params):
        Cmd.__init__(self)

        self.cmd = CMD.MOD_USER_STATE
        self.parameters = params


class RemoveUser(Cmd):
    """Command to kick (ban=False) or ban (ban=True) a user"""

    def __init__(self, session, params):
        Cmd.__init__(self)

        self.cmd = CMD.REMOVE_USER
        self.parameters = params


class CreateChannel(Cmd):
    """Command to create channel"""

    def __init__(self, parent, name, temporary):
        Cmd.__init__(self)

        self.cmd = TCP_MSG_TYPE.ChannelState
        self.parameters = {"parent": parent, "name": name, "temporary": temporary}


class RemoveChannel(Cmd):
    """Command to create channel"""

    def __init__(self, channel_id):
        Cmd.__init__(self)

        self.cmd = TCP_MSG_TYPE.ChannelRemove
        self.parameters = {"channel_id": channel_id}


class UpdateChannel(Cmd):
    """Command to update channel"""

    def __init__(self, params):
        Cmd.__init__(self)

        self.cmd = CMD.UPDATE_CHANNEL
        self.parameters = params


class VoiceTarget(Cmd):
    """Command to create a whisper"""

    def __init__(self, voice_id, targets):
        Cmd.__init__(self)

        self.cmd = TCP_MSG_TYPE.VoiceTarget
        self.parameters = {"id": voice_id, "targets": targets}


class LinkChannel(Cmd):
    """Command to link channel"""

    def __init__(self, params):
        Cmd.__init__(self)

        self.cmd = CMD.LINK_CHANNEL
        self.parameters = params


class UnlinkChannel(Cmd):
    """Command to unlink channel"""

    def __init__(self, params):
        Cmd.__init__(self)

        self.cmd = CMD.UNLINK_CHANNEL
        self.parameters = params


class QueryACL(Cmd):
    """Command to query ACL information for channel"""

    def __init__(self, channel_id):
        Cmd.__init__(self)

        self.cmd = CMD.QUERY_ACL
        self.parameters = {"channel_id": channel_id}


class UpdateACL(Cmd):
    """Command to Update ACL information for channel"""

    def __init__(self, channel_id, inherit_acls, chan_group, chan_acl):
        Cmd.__init__(self)

        self.cmd = CMD.UPDATE_ACL
        self.parameters = {
            "channel_id": channel_id,
            "inherit_acls": inherit_acls,
            "chan_group": chan_group,
            "chan_acl": chan_acl,
        }

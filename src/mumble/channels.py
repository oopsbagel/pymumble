# -*- coding: utf-8 -*-
from .constants import CALLBACK
from threading import Lock
from .errors import UnknownChannelError, TextTooLongError, ImageTooBigError
from .acl import ACL
from . import messages


class Channels(dict):
    """
    Object that Stores all channels and their properties.
    """

    def __init__(self, mumble_object, callbacks):
        self.mumble_object = mumble_object
        self.callbacks = callbacks

        self.lock = Lock()

    def update(self, message):
        """Update the channel information based on an incoming message"""
        self.lock.acquire()

        if message.channel_id not in self:  # create the channel
            self[message.channel_id] = Channel(self.mumble_object, message)
            self.callbacks(CALLBACK.CHANNEL_CREATED, self[message.channel_id])
        else:  # update the channel
            actions = self[message.channel_id].update(message)
            self.callbacks(CALLBACK.CHANNEL_UPDATED, self[message.channel_id], actions)

        self.lock.release()

    def remove(self, id):
        """Delete a channel when server signal the channel is removed"""
        self.lock.acquire()

        if id in self:
            channel = self[id]
            del self[id]
            self.callbacks(CALLBACK.CHANNEL_REMOVED, channel)

        self.lock.release()

    def find_by_tree(self, tree):
        """Find a channel by its full path (a list with an element for each leaf)"""
        if not getattr(tree, "__iter__", False):
            tree = tree  # function use argument as a list

        current = self[0]

        for name in tree:  # going up the tree
            found = False
            for subchannel in self.get_childs(current):
                if subchannel["name"] == name:
                    current = subchannel
                    found = True
                    break

            if not found:  # channel not found
                err = "Cannot find channel %s" % str(tree)
                raise UnknownChannelError(err)

        return current

    def get_childs(self, channel):
        """Get the child channels of a channel in a list"""
        childs = list()

        for item in self.values():
            if (
                item.get("parent") is not None
                and item["parent"] == channel["channel_id"]
            ):
                childs.append(item)

        return childs

    def get_descendants(self, channel):
        """Get all the descendant of a channel, in nested lists"""
        descendants = list()

        for subchannel in self.get_childs(channel):
            descendants.append(self.get_childs(subchannel))

        return descendants

    def get_tree(self, channel):
        """Get the whole list of channels, in a multidimensional list"""
        tree = list()

        current = channel

        while current["channel_id"] != 0:
            tree.insert(0, current)
            current = self[current["channel_id"]]

        tree.insert(0, self[0])

        return tree

    def find_by_name(self, name):
        """Find a channel by name.  Stop on the first that match"""
        if name == "":
            return self[0]

        for obj in list(self.values()):
            if obj["name"] == name:
                return obj

        err = "Channel %s does not exists" % name
        raise UnknownChannelError(err)

    def new_channel(self, parent_id, name, temporary=False):
        cmd = messages.CreateChannel(parent_id, name, temporary)
        self.mumble_object.execute_command(cmd)

    def remove_channel(self, channel_id):
        cmd = messages.RemoveChannel(channel_id)
        self.mumble_object.execute_command(cmd)

    def unlink_every_channel(self):
        """
        Unlink every channels in server.
        So there will be no channel linked to other channel.
        """
        for channel in list(self.values()):
            if "links" in channel:
                cmd = messages.UnlinkChannel(
                    {
                        "channel_id": channel["channel_id"],
                        "remove_ids": channel["links"],
                    }
                )
                self.mumble_object.execute_command(cmd)


class Channel(dict):
    """
    Stores information about one specific channel
    """

    def __init__(self, mumble_object, message):
        self.mumble_object = mumble_object
        self["channel_id"] = message.channel_id
        self.acl = ACL(mumble_object=mumble_object, channel_id=self["channel_id"])
        self.update(message)

    def get_users(self):
        users = []
        for user in list(self.mumble_object.users.values()):
            if user["channel_id"] == self["channel_id"]:
                users.append(user)
        return users

    def update(self, message):
        """Update a channel based on an incoming message"""
        actions = dict()

        for field, value in message.ListFields():
            if field.name in ("session", "actor", "description_hash"):
                continue
            actions.update(self.update_field(field.name, value))

        if message.HasField("description_hash"):
            actions.update(
                self.update_field("description_hash", message.description_hash)
            )
            if message.HasField("description"):
                self.mumble_object.blobs[message.description_hash] = message.description
            else:
                self.mumble_object.blobs.get_channel_description(
                    message.description_hash
                )

        return actions  # return a dict with updates performed, useful for the callback functions

    def update_acl(self, message):
        self.acl.update(message)

    def get_id(self):
        return self["channel_id"]

    def update_field(self, name, field):
        """Update one value"""
        actions = dict()
        if name not in self or self[name] != field:
            self[name] = field
            actions[name] = field

        return actions  # return a dict with updates performed, useful for the callback functions

    def get_property(self, property):
        if property in self:
            return self[property]
        else:
            return None

    def move_in(self, session=None):
        """Ask to move a session in a specific channel.  By default move pymumble own session"""
        if session is None:
            session = self.mumble_object.users.myself_session

        cmd = messages.MoveCmd(session, self["channel_id"])
        self.mumble_object.execute_command(cmd)

    def remove(self):
        cmd = messages.RemoveChannel(self["channel_id"])
        self.mumble_object.execute_command(cmd)

    def send_text_message(self, message):
        """Send a text message to the channel."""

        # TODO: This check should be done inside execute_command()
        # However, this is currently not possible because execute_command() does
        # not actually execute the command.
        if len(message) > self.mumble_object.get_max_image_length() != 0:
            raise ImageTooBigError(self.mumble_object.get_max_image_length())

        if not ("<img" in message and "src" in message):
            if len(message) > self.mumble_object.get_max_message_length() != 0:
                raise TextTooLongError(self.mumble_object.get_max_message_length())

        session = self.mumble_object.users.myself_session

        cmd = messages.TextMessage(session, self["channel_id"], message)
        self.mumble_object.execute_command(cmd)

    def link(self, channel_id):
        """Link selected channel with other channel"""
        cmd = messages.LinkChannel(
            {"channel_id": self["channel_id"], "add_id": channel_id}
        )
        self.mumble_object.execute_command(cmd)

    def unlink(self, channel_id):
        """Unlink one channel which is linked to a specific channel."""
        cmd = messages.UnlinkChannel(
            {"channel_id": self["channel_id"], "remove_ids": [channel_id]}
        )
        self.mumble_object.execute_command(cmd)

    def unlink_all(self):
        """Unlink all channels which is linked to a specific channel."""
        if "links" in self:
            cmd = messages.UnlinkChannel(
                {"channel_id": self["channel_id"], "remove_ids": self["links"]}
            )
            self.mumble_object.execute_command(cmd)

    def rename_channel(self, name):
        params = {"channel_id": self["channel_id"], "name": name}
        cmd = messages.UpdateChannel(params)
        self.mumble_object.execute_command(cmd)

    def move_channel(self, new_parent_id):
        params = {"channel_id": self["channel_id"], "parent": new_parent_id}
        cmd = messages.UpdateChannel(params)
        self.mumble_object.execute_command(cmd)

    def set_channel_position(self, position):
        params = {"channel_id": self["channel_id"], "position": position}
        cmd = messages.UpdateChannel(params)
        self.mumble_object.execute_command(cmd)

    def set_channel_max_users(self, max_users):
        params = {"channel_id": self["channel_id"], "max_users": max_users}
        cmd = messages.UpdateChannel(params)
        self.mumble_object.execute_command(cmd)

    def set_channel_description(self, description):
        params = {"channel_id": self["channel_id"], "description": description}
        cmd = messages.UpdateChannel(params)
        self.mumble_object.execute_command(cmd)

    def request_acl(self):
        cmd = messages.QueryACL(self["channel_id"])
        self.mumble_object.execute_command(cmd)

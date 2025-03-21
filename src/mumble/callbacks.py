# -*- coding: utf-8 -*-

from .errors import UnknownCallbackError
from .constants import CALLBACK
import threading


class CallBacks(dict):
    """
    Define the callbacks that can be registered by the application.
    Multiple functions can be assigned to a callback using "add_callback"

    The call is done from within the pymumble loop thread, it's important to
    keep processing short to avoid delays on audio transmission
    """

    def __init__(self):
        self.update(
            {
                CALLBACK.CONNECTED: None,  # Connection succeeded
                CALLBACK.DISCONNECTED: None,  # Connection as been dropped
                CALLBACK.CHANNEL_CREATED: None,  # send the created channel object as parameter
                CALLBACK.CHANNEL_UPDATED: None,  # send the updated channel object and a dict with all the modified fields as parameter
                CALLBACK.CHANNEL_REMOVED: None,  # send the removed channel object as parameter
                CALLBACK.USER_CREATED: None,  # send the added user object as parameter
                CALLBACK.USER_UPDATED: None,  # send the updated user object and a dict with all the modified fields as parameter
                CALLBACK.USER_REMOVED: None,  # send the removed user object and the mumble message as parameter
                CALLBACK.SOUND_RECEIVED: None,  # send the user object that received the sound and the SoundChunk object itself
                CALLBACK.TEXT_MESSAGE_RECEIVED: None,  # Send the received message
                CALLBACK.CONTEXT_ACTION_RECEIVED: None,  # Send the contextaction message
                CALLBACK.ACL_RECEIVED: None,  # Send the received ACL permissions object
                CALLBACK.PERMISSION_DENIED: None,  # Permission Denied for some action, send information
            }
        )

    def set_callback(self, callback, dest):
        """Define the function to call for a specific callback.  Suppress any existing callback function"""
        if callback not in self:
            raise UnknownCallbackError('Callback "%s" does not exists.' % callback)

        self[callback] = [dest]

    def add_callback(self, callback, dest):
        """Add the function to call for a specific callback."""
        if callback not in self:
            raise UnknownCallbackError('Callback "%s" does not exists.' % callback)

        if self[callback] is None:
            self[callback] = list()
        self[callback].append(dest)

    def get_callback(self, callback):
        """Get the functions assigned to a callback as a list. Return None if no callback defined"""
        if callback not in self:
            raise UnknownCallbackError('Callback "%s" does not exists.' % callback)

        return self[callback]

    def remove_callback(self, callback, dest):
        """Remove a specific function from a specific callback.  Function object must be the one added before."""
        if callback not in self:
            raise UnknownCallbackError('Callback "%s" does not exists.' % callback)

        if self[callback] is None or dest not in self[callback]:
            raise UnknownCallbackError(
                'Function not registered for callback "%s".' % callback
            )

        self[callback].remove(dest)
        if len(self[callback]) == 0:
            self[callback] = None

    def reset_callback(self, callback):
        """remove functions for a defined callback"""
        if callback not in self:
            raise UnknownCallbackError('Callback "%s" does not exists.' % callback)

        self[callback] = None

    def call_callback(self, callback, *pos_parameters):
        """Call all the registered function for a specific callback."""
        if callback not in self:
            raise UnknownCallbackError('Callback "%s" does not exists.' % callback)

        if self[callback]:
            for func in self[callback]:
                if callback is CALLBACK.TEXT_MESSAGE_RECEIVED:
                    thr = threading.Thread(target=func, args=pos_parameters)
                    thr.start()
                else:
                    func(*pos_parameters)

    def __call__(self, callback, *pos_parameters):
        """shortcut to be able to call the dict element as a function"""
        self.call_callback(callback, *pos_parameters)

    def get_callbacks_list(self):
        """Get a list of all callbacks"""
        return list(self.keys())

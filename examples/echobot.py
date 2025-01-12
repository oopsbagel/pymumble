#!/usr/bin/python3
# This bot sends any sound it receives back to where it has come from.
# WARNING! Don't put two bots in the same place!

from mumble import Mumble
from mumble.callbacks import CALLBACK

pwd = ""  # password
server = "localhost"
nick = "Bob"


def sound_received_handler(user, soundchunk):
    # sending the received sound back to server
    mumble.sound_output.add_sound(soundchunk.pcm)


mumble = Mumble(server, nick, password=pwd)
mumble.callbacks.set_callback(CALLBACK.SOUND_RECEIVED, sound_received_handler)
mumble.start()
mumble.join()

#!/usr/bin/python3
# This bot sends any sound it receives back to where it has come from.
# WARNING! Don't put two bots in the same place!

from mumble import Mumble

pwd = ""  # password
server = "127.0.0.1"
nick = "Bob"


def sound_received_handler(user, soundchunk):
    # sending the received sound back to server
    mumble.send_audio.add_sound(soundchunk.pcm)


mumble = Mumble(server, nick, password=pwd)
mumble.callbacks.sound_received.set_handler(sound_received_handler)
mumble.start()
mumble.join()

# A python script to do both listening and talking. This is the basic model
# for an audio-only mumble client.

# Usage:

# Install pyaudio (instructions: https://people.csail.mit.edu/hubert/pyaudio/#downloads)
# If `fatal error: 'portaudio.h' file not found` is encountered while installing
# pyaudio even after following the instruction, this solution might be of help:
# https://stackoverflow.com/questions/33513522/when-installing-pyaudio-pip-cannot-find-portaudio-h-in-usr-local-include
#
# Install dependencies for pymumble.
#
# Set up a mumber server. For testing purpose, you can use https://guildbit.com/
# to spin up a free server. Hard code the server details in this file.
#
# run `python3 ./listen_n_talk.py`. Now an audio-only mumble client is connected
# to the server.
#
# To test its functionality, in a separate device, use some official mumble
# client (https://www.mumble.com/mumble-download.php) to verbally communicate
# with this audio-only client.
#
# Works on MacOS. Does NOT work on RPi 3B+ (I cannot figure out why. Help will
# be much appreciated)

import argparse
from mumble import Mumble
import pyaudio

parser = argparse.ArgumentParser(description="audio only mumble client")

parser.add_argument("--server", "-s", required=True)
parser.add_argument("--port", "-P", type=int, default=64738)
parser.add_argument("--name", "-n", required=True)
parser.add_argument("--passwd", "-p", default="")
args = parser.parse_args()

server = args.server
port = args.port
nick = args.name
pwd = args.passwd

# pyaudio set up
CHUNK = 1024
FORMAT = pyaudio.paInt16  # pymumble soundchunk.pcm is 16 bits
CHANNELS = 1
RATE = 48000  # pymumble soundchunk.pcm is 48000Hz

p = pyaudio.PyAudio()
output_stream = p.open(
    format=FORMAT,
    channels=CHANNELS,
    rate=RATE,
    output=True,
    frames_per_buffer=CHUNK,
)
input_stream = p.open(
    format=FORMAT,
    channels=CHANNELS,
    rate=RATE,
    input=True,
    frames_per_buffer=CHUNK,
)


def sound_received_handler(user, soundchunk):
    """play sound received from mumble server upon its arrival"""
    output_stream.write(soundchunk.pcm)


# Spin up a client and connect to mumble server
mumble = Mumble(server, nick, password=pwd, port=port)
mumble.callbacks.sound_received.set_handler(sound_received_handler)
mumble.start()
mumble.wait_until_connected()

# constant capturing sound and sending it to mumble server
while True:
    data = input_stream.read(CHUNK, exception_on_overflow=False)
    mumble.send_audio.add_sound(data)

# close the streams and pyaudio instance
input_stream.stop_stream()
input_stream.close()
output_stream.stop_stream()
output_stream.close()
p.terminate()

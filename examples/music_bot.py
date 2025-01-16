#!/usr/bin/python3

import subprocess as sp
import argparse
from mumble import Mumble

parser = argparse.ArgumentParser(description="get parameters.")

parser.add_argument("--server", "-s", required=True)
parser.add_argument("--port", "-P", type=int, default=64738)
parser.add_argument("--name", "-n", required=True)
parser.add_argument("--passwd", "-p", default="")
parser.add_argument("file")
args = parser.parse_args()

musicfile = args.file
server = args.server
nick = args.name
passwd = args.passwd
port = args.port

with Mumble(server, nick, password=passwd, port=port) as mumble:
    command = (
        "ffmpeg -acodec pcm_s16le -f s16le -ab 192k -ac 1 -ar 48000 - -i".split()
        + [musicfile]
    )
    sound = sp.Popen(command, stdout=sp.PIPE, stderr=sp.DEVNULL, bufsize=1024)
    raw_music = sound.stdout.read()
    mumble.send_audio.add_sound(raw_music)
    mumble.send_audio.queue_empty.wait()

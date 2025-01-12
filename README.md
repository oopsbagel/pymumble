# pymumble - Python Mumble client library
## Installation

### Requirements

**`libopus` is a mandatory OS library when sending and receiving audio**. Please refer to your package manager to install it.

### Install with `uv` or `pip`

One of the following:
- `uv add pymumble`
- `uv pip install pymumble`
- `pip install pymumble`

### Install from git

```sh
git clone https://git.sr.ht/~oopsbagel/pymumble
cd pymumble
uv sync
```

## Usage

```python
# /// script
# dependencies = [
#     "pymumble>=2",
# ]
# ///
from mumble import Mumble

m = Mumble("127.0.0.1", "A Weedy Samaritan")
m.start()
m.is_ready()
usernames = [
    user["name"]
    for user in m.my_channel().get_users()
    if user["session"] != m.users.myself_session
]
m.my_channel().send_text_message(
    "Hello, " + ", ".join(usernames) + ". You're all Brian! You're all individuals!"
)

# If you have `espeak` installed:
import subprocess

wav = subprocess.Popen(
    ["espeak", "--stdout", "'People called Romanes, they go the house?'"],
    stdout=subprocess.PIPE,
).stdout
sound = subprocess.Popen(
    ["ffmpeg", "-i", "-", "-ac", "1", "-f", "s32le", "-"],
    stdout=subprocess.PIPE,
    stdin=wav,
).stdout.read()
m.send_audio.add_sound(sound)
m.join()
```

Refer to the [user manual](API.md) for detailed documentation.

## BREAKING CHANGES and updates in pymumble 2.0.0
The following enhancements are included in pymumble 2.0.0:

- Implement encrypted UDP audio & pings with AES-OCB2, compatible with the latest Mumble server.
- Implement unencrypted UDP pings to retrieve extended server info before connecting.
- Support the latest protocol version: 1.5.735.
- Use `uv` for packaging and `ruff` for linting.
- Send functional version string compatible with the latest Mumble server.

In order to bring pymumble up to date with modern python development practices, the following breaking changes have been introduced in version 2.0.0:

- Change the import path from `pymumble_py3` to simply `mumble`.
- Change callback constants to an enum. e.g., `PYMUMBLE_CLBK_SOUNDRECEIVED` is now `CALLBACK.SOUND_RECEIVED`.
- Remove `Mumble.set_receive_sound()`, audio support is now enabled by default.
  - To disable audio support and avoid importing `opuslib`, instantiate the `Mumble` object with `Mumble(enable_audio=False)`.
  - To disable audio support after the object has been created set `m = Mumble(); m.enable_audio = False`. This will still import `opuslib`.
- The `Mumble` class getter/setter functions `set_application_string()`, `set_loop_rate()`, and `get_loop_rate()` have been removed. These parameters can be set in the `Mumble` object initializer and queried and changed by accessing the object's `application` and `loop_rate` public attributes.
- Drop support for legacy audio codecs.
- Rename all constants to drop the `PYMUMBLE_` prefix, some also renamed for clarity.
- Rename `SoundOutput` to `SendAudio`.

Because pymumble now follows the [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html) versioning scheme, any further breaking changes must increment the MAJOR version number. The dependency
```
pymumble>=2,<3
```
will resolve to the latest version with a stable API.

## Goals

We strive to keep pymumble up to date with the latest version of the mumble protocol and compatible with the mumble server. Pymumble should be bit-compatible with the official mumble client at the application/messaging layer. (The python & C++ protobuf implementations may vary in how they serialise the data over the wire, which is acceptable per the protocol buffer specification.)

Future releases will focus on:

- improving the API
- improving performance
- improving test coverage
- improving documentation
- rounding out protocol support

## Contributing guidelines

- Follow [conventional commit](https://www.conventionalcommits.org/en/v1.0.0/#specification) guidelines for writing commit messages.
- Document code in the [Sphinx docstring format](https://sphinx-rtd-tutorial.readthedocs.io/en/latest/docstrings.html).
- Include integration tests for updated or new functionality.
- Format code with `ruff format` and lint with `ruff lint` before committing.

## Applications using `pymumble`

- [Abot](https://github.com/ranomier/pymumble-abot)
- [Botamusique](https://github.com/azlux/botamusique)
- [MumbleRadioPlayer](https://github.com/azlux/MumbleRadioPlayer) (archived)
- [MumbleRecbot](https://github.com/Robert904/mumblerecbot) (deprecated)

## Thanks

- [@azlux](https://github.com/azlux) for maintaining the `pymumble` library before version 2
- [Jan Petykiewicz](https://github.com/anewusername) for the AES-OCB2 implementation
- [Ranomier](https://github.com/ranomier) for the python3 port
- [@raylu](https://github.com/raylu) for making `pymumble` speak into channels
- [@schlarpc](https://github.com/schlarpc) for fixes on buffer
- [@Robert904](https://github.com/Robert904) for the inital pymumble implementation
- All contributors to the previous versions.

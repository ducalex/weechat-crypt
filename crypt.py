# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 Alex Duchesne
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import weechat, struct, base64, os, re

try:
    import Crypto.Cipher.Blowfish
except ImportError:
    exit("PyCrypto is required for this script")


# Constants
SCRIPT_NAME      = "crypt"
SCRIPT_AUTHOR    = "ducalex"
SCRIPT_VERSION   = "1.0"
SCRIPT_LICENSE   = "GPL3"
SCRIPT_DESC      = "End-to-end encryption for weechat (Mircryption, Blowcrypt, AES)"
SCRIPT_HELP_TEXT = (
    "     listkeys: List all keys (default)\n"
    "       setkey: Set key for target\n"
    "       delkey: Delete key for target\n"
    "    sendplain: Send unencrypted message on current buffer\n"
    "       target: [server/]nickname, [server/]#channel\n"
    "\n"
)


# Globals
crypt_config_file = None
crypt_config_opts = {}
crypt_ciphers = {}
crypt_last_msg_type = {}


class Fish64:
    """A non-standard base64-decode."""
    """ Copyright (C) 2009 Bjorn Edstrom <be@bjrn.se> """
    """ Source: http://www.bjrn.se/code/irccrypt/irccrypt.py """

    B64 = "./0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

    def b64encode(s):
        res = bytes()
        while s:
            left, right = struct.unpack('>LL', s[:8])
            for i in range(6):
                res += Fish64.B64[right & 0x3f]
                right >>= 6
            for i in range(6):
                res += Fish64.B64[left & 0x3f]
                left >>= 6
            s = s[8:]
        return res

    def b64decode(s):
        if len(s) < 12: raise ValueError
        if len(s) % 12 > 0: s = s[:-(len(s) % 12)]
        res = []
        while s:
            left, right = 0, 0
            for i, p in enumerate(s[0:6]):
                right |= Fish64.B64.index(p) << (i * 6)
            for i, p in enumerate(s[6:12]):
                left |= Fish64.B64.index(p) << (i * 6)
            for i in range(0,4):
                res.append((left & (0xFF << ((3 - i) * 8))) >> ((3 - i) * 8))
            for i in range(0,4):
                res.append((right & (0xFF << ((3 - i) * 8))) >> ((3 - i) * 8))
            s = s[12:]
        return bytes(res)


class Cipher:
    MODE_MIRCRYPTION = 1
    MODE_BLOWCRYPT = 2
    MODE_MODERN_AES = 3

    def __init__(self, key=None, mode=MODE_MIRCRYPTION):
        self.key = key
        self.mode = mode

    # TO DO: It might be possible to cache the ciphers and reuse them...
    def cipher(self, mode, iv=None):
        if mode == self.MODE_MIRCRYPTION:
            return Crypto.Cipher.Blowfish.new(self.key, Crypto.Cipher.Blowfish.MODE_CBC, iv)
        return Crypto.Cipher.Blowfish.new(self.key, Crypto.Cipher.Blowfish.MODE_ECB)

    def decrypt(self, data, mode=None) -> bytes:
        mode = mode or self.mode
        if type(data) is str:
            data = data.encode()
        if mode == self.MODE_MIRCRYPTION:
            return self.cipher(mode, data[:8]).decrypt(data[8:]).strip(b'\0')
        return self.cipher(mode).decrypt(data).strip(b'\0')

    def encrypt(self, data, mode=None) -> bytes:
        mode = mode or self.mode
        if type(data) is str:
            data = data.encode()
        if len(data) % 8:
            data += b'\0' * (8 - len(data) % 8)
        if mode == self.MODE_MIRCRYPTION:
            iv = os.urandom(8)
            # Which way is correct? They both seem to work, somehow...
            # return iv + self.cipher(mode, iv).encrypt(data)
            return self.cipher(mode, iv).encrypt(iv + data)
        return self.cipher(mode).encrypt(data)

    def pack_msg(self, msg) -> bytes:
        if self.mode == self.MODE_MIRCRYPTION:
            return b"+OK *" + base64.b64encode(self.encrypt(msg))
        return b"+OK " + Fish64.b64encode(self.encrypt(msg))

    def unpack_msg(self, msg) -> bytes:
        if not (msg.startswith("+OK ") or msg.startswith("mcps ")):
            raise ValueError

        msg = msg.split(' ', 1)[1]

        if msg.startswith('*'):
            mode = self.MODE_MIRCRYPTION
            data = base64.b64decode(msg[1:])
        else:
            mode = self.MODE_BLOWCRYPT
            data = Fish64.b64decode(msg)

        return self.decrypt(data, mode)


# Weechat hooks and helpers

def crypt_print_notice(target, message, color="chat"):
    buffer = weechat.info_get("irc_buffer", target.replace("/", ","))
    if not buffer:
        # Maybe we should also beep?
        message = "[%s] %s" % (target, message)
    weechat.prnt(buffer, "%s%s%s%s" % (
            weechat.prefix("error"),
            weechat.color(color),
            message,
            weechat.color("chat")
    ))


def crypt_print_error(target, message):
    crypt_print_notice(target, message, "emphasized")


def crypt_modifier_outgoing(data, modifier, server_name, string):
    """ Encrypt outgoing messages after split """

    match = re.match(
        r"(?i)^((TOPIC|PRIVMSG|NOTICE) (.+?) :)(.+)$",
        string if type(string) is str else str(string, errors="ignore")
    )

    if not match:
        return string

    target = "%s/%s" % (server_name, match.group(3))
    cipher = crypt_ciphers.get(target.lower())
    command = match.group(1)
    irc_cmd = match.group(2)
    message = match.group(4)

    if not cipher:
        return string

    if irc_cmd.upper() == "PRIVMSG" and not crypt_last_msg_type.get(target, None):
        crypt_print_notice(target, "Messages to/from %s are encrypted" % target)
        crypt_last_msg_type[target] = True

    try:
        return b"%s%s" % (command.encode(), cipher.pack_msg(message))
    except Exception as e:
        crypt_print_error(target, f"Encryption failed: {repr(e)}. (Message not sent)", True)
        return b""


def crypt_modifier_incoming(data, modifier, server_name, string):
    """ Decrypt incoming messages before UTF-8 decoding """

    match = re.match(
        r"(?i)^(:(.*?)(!.*?)? (PRIVMSG|NOTICE|TOPIC|332 .*?) (.+?) :)(.*?)$",
        string if type(string) is str else str(string, errors="ignore")
    )

    if not match:
        return string

    command = match.group(1)
    sent_by = match.group(2)
    irc_cmd = match.group(4)
    sent_to = match.group(5)
    message = match.group(6)
    encrypted = (message.startswith("+OK ") or message.startswith("mcps "))

    if irc_cmd.upper() == "PRIVMSG" and sent_to == weechat.info_get("irc_nick", server_name):
        target = "%s/%s" % (server_name, sent_by)
    else:
        target = "%s/%s" % (server_name, sent_to)

    cipher = crypt_ciphers.get(target.lower())

    if not cipher:
        return string

    if irc_cmd.upper() == "PRIVMSG" and crypt_last_msg_type.get(target, None) != encrypted:
        status = "encrypted" if encrypted else "*not* encrypted"
        crypt_print_notice(target, "Messages to/from %s are %s" % (target, status))
        crypt_last_msg_type[target] = encrypted

    if not encrypted:
        return string

    try:
        return b"%s%s" % (command.encode(), cipher.unpack_msg(message))
    except Exception as e:
        crypt_print_error(target, f"Decryption failed: {repr(e)}", True)
        return string


def crypt_bar_item_update(data, item, window, buffer, extra_info):
    server_name = weechat.buffer_get_string(buffer, "localvar_server")
    buffer_name = weechat.buffer_get_string(buffer, "localvar_channel")
    buffer_type = weechat.buffer_get_string(buffer, "localvar_type")

    if buffer_type in ["private", "channel"]:
        target = f"{server_name}/{buffer_name}"
        return "🔒" if target.lower() in crypt_ciphers else "" #"🔓"

    return ""


def crypt_cmd_crypt(data, buffer, args):
    argv = args.split(" ")
    command = argv.pop(0) or "listkeys"

    server_name = weechat.buffer_get_string(buffer, "localvar_server")
    buffer_name = weechat.buffer_get_string(buffer, "localvar_channel")

    if command == "listkeys":
        weechat.prnt(buffer, "\t%s: %s" % (SCRIPT_NAME, SCRIPT_DESC))
        if len(crypt_ciphers) == 0:
            weechat.prnt(buffer, "\tNo key configured")
        else:
            weechat.prnt(buffer, "\tEncryption keys:")
            for (target, cipher) in sorted(crypt_ciphers.items()):
                weechat.prnt(buffer, "\t    %s: mode=%d, key=%s" % (target, cipher.mode, cipher.key))

    elif command == "setkey":
        if len(argv) != 2: return weechat.WEECHAT_RC_ERROR
        target = argv[0] if argv[0].count('/') else "%s/%s" % (server_name, argv[0])
        if target[0] == '/':
            weechat.prnt(buffer, f"Could not determinate server")
            return weechat.WEECHAT_RC_ERROR
        crypt_ciphers[target.lower()] = Cipher(argv[-1])
        weechat.prnt(buffer, "Set key for %s to %s" % (target, argv[-1]))

    elif command == "delkey":
        if len(argv) != 1: return weechat.WEECHAT_RC_ERROR
        target = argv[0] if argv[0].count('/') else "%s/%s" % (server_name, argv[0])
        if target[0] == '/':
            weechat.prnt(buffer, f"Could not determinate server")
            return weechat.WEECHAT_RC_ERROR
        if crypt_ciphers.pop(target.lower(), None):
            weechat.prnt(buffer, "Deleted key for %s" % target)
            crypt_last_msg_type.pop(target.lower(), None)
        else:
            weechat.prnt(buffer, f"No such target {target}")
            return weechat.WEECHAT_RC_ERROR

    elif command == "sendplain":
        target = "%s/%s" % (server_name, buffer_name)
        weechat.prnt(buffer, "Sending unencrypted message to %s" % target)
        return weechat.WEECHAT_RC_ERROR

    else:
        weechat.prnt(buffer, "Unknown command %s" % command)
        return weechat.WEECHAT_RC_ERROR

    weechat.bar_item_update("encryption")

    return weechat.WEECHAT_RC_OK


def crypt_unload():
    weechat.config_write(crypt_config_file)
    return weechat.WEECHAT_RC_OK


def crypt_config_reload(data, config_file):
    global crypt_last_msg_type, crypt_ciphers
    crypt_last_msg_type = {}
    crypt_ciphers = {}
    return weechat.config_reload(config_file)


def crypt_config_keys_read(data, config_file, section_name, option_name, value):
    crypt_ciphers[option_name.lower()] = Cipher(value)
    return weechat.WEECHAT_CONFIG_OPTION_SET_OK_CHANGED


def crypt_config_keys_write(data, config_file, section_name):
    weechat.config_write_line(config_file, section_name, "")
    for target, cipher in sorted(crypt_ciphers.items()):
        weechat.config_write_line(config_file, target, cipher.key)
    return weechat.WEECHAT_RC_OK



if __name__ == "__main__":
    weechat.register(SCRIPT_NAME, SCRIPT_AUTHOR, SCRIPT_VERSION, SCRIPT_LICENSE, SCRIPT_DESC, "crypt_unload", "")

    crypt_config_file = weechat.config_new(SCRIPT_NAME, "crypt_config_reload", "")
    if crypt_config_file:
        weechat.config_new_section(crypt_config_file, "options", 0, 0, "", "", "", "", "", "", "", "", "", "")
        weechat.config_new_section(crypt_config_file, "keys", 0, 0, "crypt_config_keys_read", "",
                "crypt_config_keys_write", "", "", "", "", "", "", "")
        weechat.config_read(crypt_config_file)

    weechat.hook_command("crypt", "Manage E2EE encryption keys",
            "listkeys | setkey <target> <key> | delkey <target> | sendplain <msg> ",
            SCRIPT_HELP_TEXT,
            "listkeys || setkey %(irc_channel)|%(nicks)|%(irc_servers) %- "
            "|| delkey %(irc_channel)|%(nicks)|%(irc_servers) %- || sendplain %-",
            "crypt_cmd_crypt", "")

    weechat.hook_modifier("irc_in_notice", "crypt_modifier_incoming", "")
    weechat.hook_modifier("irc_in_privmsg", "crypt_modifier_incoming", "")
    weechat.hook_modifier("irc_in_topic", "crypt_modifier_incoming", "")
    weechat.hook_modifier("irc_in_332", "crypt_modifier_incoming", "")
    weechat.hook_modifier("irc_out_privmsg", "crypt_modifier_outgoing", "")
    weechat.hook_modifier("irc_out_topic", "crypt_modifier_outgoing", "")
    weechat.hook_modifier("irc_out_notice", "crypt_modifier_outgoing", "")

    weechat.bar_item_new("(extra)encryption", "crypt_bar_item_update", "")

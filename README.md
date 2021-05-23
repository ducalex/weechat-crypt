# weechat-crypt
End-to-end encryption for weechat.

Supported modes:
- Blowcrypt/FiSH
- Mircryption
- AES

# Usage
To avoid getting broken encyrption on long messages:
    `/set irc.server_default.split_msg_max_length 400`

# Acknowledgments
- FiSH Base64 code is from irccrypt: http://www.bjrn.se/code/irccrypt/irccrypt.py
- weechat-fish was a big inspiration: https://github.com/freshprince/weechat-fish

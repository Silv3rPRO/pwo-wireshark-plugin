# PWO Wireshark Plugin

A wireshark dissector for the protocol of Pokémon World Online.

## The protocol

Text protocol. RC4 encryption with a fixed key.

There is a security byte after each packet sent by the client.

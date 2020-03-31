#!/usr/bin/env python

from scapy.all import *
import binascii
from rc4 import RC4

#Cle wep AA:AA:AA:AA:AA
key= b'\xaa\xaa\xaa\xaa\xaa'

text = bytes.fromhex("aaaa03000000080600010800060400019027e4ea61f2c0a80164000000000000c0a801c8")

icv_hex = binascii.crc32(text)
icv = struct.pack("<L", icv_hex)

message = text + icv

arp = rdpcap('arp.cap')[0]  

seed = arp.iv+key

cipher = RC4(seed, streaming=False)
message_encripted = cipher.crypt(message)

print(message_encripted.hex())
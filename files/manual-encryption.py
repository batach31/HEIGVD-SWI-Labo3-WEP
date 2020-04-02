#!/usr/bin/env python

from scapy.all import *
import binascii
from rc4 import RC4

#Cle wep AA:AA:AA:AA:AA
key= b'\xaa\xaa\xaa\xaa\xaa'

# text en clair de 36 chars
text = "This is some 36 chars long text !!!!"
text = bytes.fromhex((text).encode("utf-8").hex())

# text clair de la trame fournie pour vérification du programme
# text = bytes.fromhex("aaaa03000000080600010800060400019027e4ea61f2c0a80164000000000000c0a801c8")

# creation de l'icv
icv_hex = binascii.crc32(text)

# packing de icv en byte sous forme unsigned long (little endian)
icv = struct.pack("<L", icv_hex)

# creation du message avec l'icv
message = text + icv

# lecture de la trame
arp = rdpcap('arp.cap')[0]  

# creation de la seed avec IV de la trame et la clée
seed = arp.iv+key

# préparation du cipher avec RC4
cipher = RC4(seed, streaming=False)

# encryption du message
message_encripted = cipher.crypt(message)
print(message_encripted.hex())

# préparation de la nouvelle trame
trame = arp
trame.wepdata = message_encripted[:-4]
(trame.icv,) = struct.unpack(">L", message_encripted[-4:])

# écriture du pcap
wrpcap("forged_arp.cap", trame)


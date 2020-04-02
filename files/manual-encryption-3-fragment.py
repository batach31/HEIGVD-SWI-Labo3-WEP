#!/usr/bin/env python

from scapy.all import *
import binascii
from rc4 import RC4
from textwrap import wrap

#Cle wep AA:AA:AA:AA:AA
key= b'\xaa\xaa\xaa\xaa\xaa'

# text en clair de 108 chars soit 3 fois 36
text = "All the world's a stage, and all the men and women merely players they have their exits and their entrances."
# text = bytes.fromhex((text).encode("utf-8").hex())

n = 36
fragmentation = [text[i:i+n] for i in range(0, len(text), n)]

# print(*fragmentation, sep = "## ")

trame_fragments = []

# text clair de la trame fournie pour vérification du programme
# text = bytes.fromhex("aaaa03000000080600010800060400019027e4ea61f2c0a80164000000000000c0a801c8")

for i in range(0, len(fragmentation)):
	text = bytes.fromhex((fragmentation[i]).encode("utf-8").hex())

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

	# on incrémente le compteur de fragments (il augmente avec le compteur)
	trame.SC = i

	# on indique qu'il reste encore des fragments dans le cas ou on n'est pas au dernier fragment
	if i < len(fragmentation) - 1:
		# dans la trame sur wireshark, il s'agit du 3eme bit depuis la droite
		trame.FCfield = trame.FCfield | 0x04
	
	trame_fragments.append(arp)

# écriture du pcap
wrpcap("forged_arp_fragments.cap", trame_fragments)


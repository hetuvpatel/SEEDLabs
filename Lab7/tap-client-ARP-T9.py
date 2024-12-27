#!/usr/bin/env python3

import fcntl
import struct
import os
import time
from scapy.all import *

TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_TAP   = 0x0002
IFF_NO_PI = 0x1000

# Create the tap interface
tap = os.open("/dev/net/tun", os.O_RDWR)
ifr = struct.pack('16sH', b'mehvi%d', IFF_TAP | IFF_NO_PI)
ifname_bytes  = fcntl.ioctl(tap, TUNSETIFF, ifr)

# Get the interface name
ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00")
print("Interface Name: {}".format(ifname))

# Configure the interface
os.system("ip addr add 192.168.53.99/24 dev {}".format(ifname))
os.system("ip link set dev {} up".format(ifname))

while True:
	packet = os.read(tap, 2048)
	if packet:
		print("--------------------------------")
		ether = Ether(packet)
		print(ether.summary())
		# Send a spoofed ARP response
		FAKE_MAC = "aa:bb:cc:dd:ee:ff"

	if ARP in ether and ether[ARP].op == 1 :
		arp = ether[ARP]
		newether = Ether(dst=ether.src, src=FAKE_MAC)
		newarp = ARP(psrc=arp.pdst, hwsrc=FAKE_MAC, pdst=arp.psrc, hwdst=ether.src, op=2)
		newpkt = newether/newarp
		print("***** Fake response: {}".format(newpkt.summary()))
		os.write(tap, bytes(newpkt))

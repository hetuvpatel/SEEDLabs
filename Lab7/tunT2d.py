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

# Create the TUN interface
tun = os.open("/dev/net/tun", os.O_RDWR)
ifr = struct.pack('16sH', b'regin%d', IFF_TUN | IFF_NO_PI) #for Task 2.a
ifname_bytes = fcntl.ioctl(tun, TUNSETIFF, ifr)

# Get the interface name
ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00")
print("Interface Name: {}".format(ifname))

os.system("ip addr add 192.168.53.99/24 dev {}".format(ifname))
os.system("ip link set dev {} up".format(ifname))

while True:
    # Read a packet from the TUN interface
    packet = os.read(tun, 2048)
    if packet:
        ip = IP(packet)  # Interpret the packet as an IP packet
        print(f"Received: {ip.summary()}")

        # Check if it's an ICMP echo request
        if ip.proto == 1:  # ICMP protocol number is 1
            icmp = ip.payload
            if icmp.type == 8:  # Echo request type
                print("Received an ICMP Echo Request")

                # Construct the echo reply packet
                newip = IP(src=ip.dst, dst=ip.src)  # Swap source and destination
                newicmp = ICMP(type=0, id=icmp.id, seq=icmp.seq)  # Echo reply
                newpkt = newip / newicmp / icmp.payload  # Include original payload
                print(f"Sending: {newip.summary()}")

                # Write the new packet to the TUN interface
                os.write(tun, bytes(newpkt))

        # arbitrary data experiment
        arbData = b'arbitrary data'
        os.write(tun, arbData)
        print("Wrote arbitrary data to the TUN interface.")



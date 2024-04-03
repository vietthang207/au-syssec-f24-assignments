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

PROTO_NUMBER_ICMP = 1

IP_A = "0.0.0.0"

CLIENT_IP="10.9.0.5"
CLIENT_PORT = 9090
CLIENT_TUN_GATEWAY="192.168.53.99"

SERVER_IP="10.9.0.11"
SERVER_PORT=9090
SERVER_TUN_GATEWAY="192.168.53.98"

PRIVATE_NETWORK_SUBNET="192.168.60.0/24"

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((IP_A, SERVER_PORT))

# Create the tun interface
tun = os.open("/dev/net/tun", os.O_RDWR)
ifr = struct.pack('16sH', b'tun%d', IFF_TUN | IFF_NO_PI)
ifname_bytes  = fcntl.ioctl(tun, TUNSETIFF, ifr)

# Get the interface name
ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00")
print("Interface Name: {}".format(ifname))

os.system("ip addr add {}/24 dev {}".format(SERVER_TUN_GATEWAY, ifname))
os.system("ip link set dev {} up".format(ifname))

while True:
    ready, _, _ = select.select([sock, tun], [], [])
    for fd in ready:
        if fd is sock:
            data, (ip, port) = sock.recvfrom(2048)
            pkt = IP(data)
            print("From socket <==: {} --> {}".format(pkt.src, pkt.dst))
            os.write(tun, data)
        
        if fd is tun:
            packet = os.read(tun, 2048)
            pkt = IP(packet)
            print("From tun ==>: {} --> {}".format(pkt.src, pkt.dst))
            sock.sendto(packet, (CLIENT_IP, CLIENT_PORT))

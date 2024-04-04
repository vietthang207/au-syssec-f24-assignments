#!/usr/bin/env python3

import fcntl
import struct
import os
import time
from scapy.all import *
import ssl

TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_TAP   = 0x0002
IFF_NO_PI = 0x1000

PROTO_NUMBER_ICMP = 1

CLIENT_IP="10.9.0.5"
CLIENT_PORT = 9090
CLIENT_TUN_GATEWAY="192.168.53.99"
SERVER_IP="10.9.0.11"
SERVER_PORT=9090
SERVER_TUN_GATEWAY="192.168.53.98"
PRIVATE_NETWORK_SUBNET="192.168.60.0/24"

CLIENT_CERT_FILE="client-cert.pem"
CLIENT_KEY_FILE="client-key.pem"
SERVER_CERT_FILE="server-cert.pem"
SERVER_KEY_FILE="server-key.pem"

# Create the tun interface
tun = os.open("/dev/net/tun", os.O_RDWR)
ifr = struct.pack('16sH', b'tun%d', IFF_TUN | IFF_NO_PI)
ifname_bytes  = fcntl.ioctl(tun, TUNSETIFF, ifr)
ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00")
print("Interface Name: {}".format(ifname))
os.system("ip addr add {}/24 dev {}".format(SERVER_TUN_GATEWAY, ifname))
os.system("ip link set dev {} up".format(ifname))

# Create context
context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile=SERVER_CERT_FILE, keyfile=SERVER_KEY_FILE)
context.verify_mode = ssl.CERT_REQUIRED
context.load_verify_locations(CLIENT_CERT_FILE)
# Create Socket
tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp_socket.bind((SERVER_IP, SERVER_PORT))
tcp_socket.listen()
tcp_connection, fromaddr = tcp_socket.accept()
tls_connection = context.wrap_socket(tcp_connection, server_side=True)
print("accept conn from {}".format(fromaddr))

while True:
    ready, _, _ = select.select([tls_connection, tun], [], [])
    for fd in ready:
        if fd is tls_connection:
            data = tls_connection.recv(2048)
            pkt = IP(data)
            print("From socket <==: {} --> {}".format(pkt.src, pkt.dst))
            os.write(tun, data)
        
        if fd is tun:
            packet = os.read(tun, 2048)
            pkt = IP(packet)
            print("From tun ==>: {} --> {}".format(pkt.src, pkt.dst))
            tls_connection.send(bytes(pkt))

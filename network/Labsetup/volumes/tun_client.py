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
SERVER_TUN_GATEWAY="192.168.53.99"
PRIVATE_NETWORK_SUBNET="192.168.60.0/24"

PATH_CERT_FILE="cert.pem"
PATH_KEY_FILE="key.pem"

# Create the tun interface
tun = os.open("/dev/net/tun", os.O_RDWR)
ifr = struct.pack('16sH', b'tun%d', IFF_TUN | IFF_NO_PI)
ifname_bytes  = fcntl.ioctl(tun, TUNSETIFF, ifr)
ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00")
print("Interface Name: {}".format(ifname))
os.system("ip addr add {}/24 dev {}".format(CLIENT_TUN_GATEWAY, ifname))
os.system("ip link set dev {} up".format(ifname))

os.system("ip route add {} dev {} via {}".format(PRIVATE_NETWORK_SUBNET,ifname, CLIENT_TUN_GATEWAY))

# Create UDP socket
ingress_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
ingress_context.load_cert_chain(certfile=PATH_CERT_FILE, keyfile=PATH_KEY_FILE)
ingress_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ingress_socket.bind((CLIENT_IP, CLIENT_PORT))
ingress_socket.listen(1)

egress_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT, check_hostname=False)
egress_context.load_verify_locations(PATH_CERT_FILE)
egress_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# egress_tls_socket = egress_context.wrap_socket(egress_socket)
egress_tls_socket = egress_context.wrap_socket(egress_socket, server_hostname=SERVER_IP)
while True:
    try:
        egress_tls_socket.connect((SERVER_IP, SERVER_PORT))
        break
    except Exception as e:
        print(e)
        time.sleep(1)

ingress_connection, fromaddr = ingress_socket.accept()
# ingress_tls_connection = ingress_context.wrap_socket(ingress_connection, server_side=True)
print("accept conn from {}".format(fromaddr))

# sock.sendall(b'Hello, world')
# context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
# context.load_cert_chain(certfile=PATH_CERT_FILE, keyfile=PATH_KEY_FILE)

while True:
    ready, _, _ = select.select([ingress_connection, tun], [], [])
    for fd in ready:
        if fd is ingress_connection:
            data = ingress_connection.recv(2048)
            # data, (ip, port) = sock.recvfrom(2048)
            pkt = IP(data)
            print("From socket <==: {} --> {}".format(pkt.src, pkt.dst))
            os.write(tun, data)
        
        if fd is tun:
            packet = os.read(tun, 2048)
            pkt = IP(packet)
            print("From tun ==>: {} --> {}".format(pkt.src, pkt.dst))
            # sock.connect((SERVER_IP, SERVER_PORT))
            # sock.connect((SERVER_IP, SERVER_PORT))
            # sock.send(packet)
            print("sending")
            # sock.sendall(b'Hello, world')
            egress_tls_socket.send(bytes(pkt))
            # sock.sendto(packet, (SERVER_IP, SERVER_PORT))
            # sock.close()

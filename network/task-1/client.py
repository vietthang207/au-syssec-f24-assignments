import socket
from scapy.all import *
import secrets
from Crypto.Cipher import AES
from shared_keys import aes_key

BLOCK_SIZE=16
NONCE_SIZE=12
SERVER_HOSTNAME="covert-server"
icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

while True:
    msg = input("Enter a message: ")
    print("Sending msg: {}".format(msg))

    nonce = secrets.token_bytes(NONCE_SIZE)
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(bytes(msg, 'utf-8'))

    data = nonce + tag + ciphertext
    packet = ICMP(type=47, code=0) / data
    icmp_socket.sendto(bytes(packet), (SERVER_HOSTNAME, 0))

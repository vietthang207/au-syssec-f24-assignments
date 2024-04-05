import socket
from scapy.all import *
import secrets
from Crypto.Cipher import AES
from shared_keys import aes_key

BLOCK_SIZE=16
NONCE_SIZE=12

icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

while True:
    data = icmp_socket.recv(2048)
    packet = IP(data)
    payload = packet[Raw].load
    nonce = payload[0 : NONCE_SIZE]
    tag = payload[NONCE_SIZE : NONCE_SIZE+BLOCK_SIZE]
    ciphertext = payload[NONCE_SIZE+BLOCK_SIZE :]

    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    try:
        msg = cipher.decrypt_and_verify(ciphertext, tag)
        print("Received plaintext: {}".format(msg))
    except Exception as e:
        print(e)

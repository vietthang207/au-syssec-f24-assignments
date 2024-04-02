import base64
import json
import sys
import requests
import math
from Crypto.Util.number import long_to_bytes, getStrongPrime
from Crypto.Hash import SHA256
import secrets

LEN_HASH = 32
LEN_SALT = 32
LEN_MASK = 32
LEN_KEY = 3072

def gcd(a: int, b: int) -> int:
    while b != 0:
        a, b = b, a % b
    return a

def extended_gcd(a: int, b: int) -> (int, int, int):
    prev_x, x = 1, 0
    prev_y, y = 0, 1
    while b != 0:
        q = a // b
        prev_x, x = x, prev_x - q * x
        prev_y, y = y, prev_y - q * y
        a, b = b, a % b
    return a, prev_x, prev_y

def inverse_mod(N: int, x: int) -> int:
    #return pow(x, -1, N)
    g, a, b = extended_gcd (x, N)
    return a % N

def keygen(k: int) -> (int, int, int):
    p = getStrongPrime(k // 2) 
    q = getStrongPrime(k // 2) 
    N = p * q
    phi = (p - 1) * (q - 1)

    e = secrets.randbelow(phi)
    while gcd(phi, e) != 1:
        e = secrets.randbelow(phi)
    d = inverse_mod(phi, e)
    return N, e, d

def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError('xor bytes string of different length')
    c = bytes()
    for i in range(len(a)):
        c += (a[i] ^ b[i]).to_bytes(1, 'big')
    return c

def hash(s: bytes) -> bytes:
    h = SHA256.new(s)
    return h.digest()

def get_salt() -> bytes:
    return secrets.token_bytes(LEN_SALT)

def MGF(H: bytes) -> bytes:
    return hash(H)

def build_encoded_message(msg, salt) -> bytes:
    mHash = hash(msg)
    M_prime = mHash + salt
    H = hash(M_prime)
    DB = salt
    maskedDB = xor_bytes(DB, MGF(H))
    EM = maskedDB + H
    return EM

def sign(msg: bytes, N: int, d: int) -> bytes:
    salt = get_salt()
    EM = build_encoded_message(msg, salt)
    print('EM1:', EM)
    m = int.from_bytes(EM, 'big')
    s = pow(m, d, N)
    signature = s.to_bytes(math.ceil(N.bit_length() / 8), 'big')
    return signature
    
def verify(msg: bytes, signature: bytes, N: int, e: int) -> bool:
    m = int.from_bytes(msg, 'big')
    s = int.from_bytes(signature, 'big')
    mm = pow(s, e, N)
    EM = mm.to_bytes(math.ceil(N.bit_length() / 8), 'big')[-LEN_MASK-LEN_HASH:]
    print('EM2:', EM)
    print()
    maskedDB = EM[0:LEN_MASK]
    H = EM[LEN_MASK:]
    salt = xor_bytes(maskedDB, MGF(H))
    mHash = hash(msg)
    H_prime = hash(mHash+salt)
    return H == H_prime

if __name__ == '__main__':
    print('Start testing')
    print('keygen:')
    N, e, d = keygen(LEN_KEY)
    print('key: N', N)
    print()
    print('key: e', e)
    print()
    print('key: d', d)
    print()

    msg = b'By failing to prepare, you are preparing to fail. Benjamin Franklin'
    print('msg: ', msg)
    print()
    signature = sign(msg, N, d)
    if verify(msg, signature, N, e):
        print('correct signature')
    else:
        print('wrong signature')
    print('signature: ', signature)
    print()
    
    msg = b'Never interrupt your enemy when he is making a mistake. Napoleon Bonaparte'
    print('msg: ', msg)
    print()
    signature = sign(msg, N, d)
    if verify(msg, signature, N, e):
        print('correct signature')
    else:
        print('wrong signature')
    print()
    print('signature: ', signature)

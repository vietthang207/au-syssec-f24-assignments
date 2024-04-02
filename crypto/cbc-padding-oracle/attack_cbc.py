#!/usr/bin/env python3

import requests
import sys
import copy
import secrets

BLOCK_SIZE = 16
BYTE_RANGE = 256
VERBOSE = False

def ask_oracle(base_url, ciphertext) -> bool:
    res = requests.get(f'{base_url}/quote/', cookies={'authtoken': ciphertext.hex()})
    if res.text == 'Padding is incorrect.' or res.text == 'PKCS#7 padding is incorrect.':
        return False
    return True

def get_quote(base_url, ciphertext) -> bytes:
    res = requests.get(f'{base_url}/quote/', cookies={'authtoken': ciphertext.hex()})
    return res.text

def pad(message) -> bytes:
    pad_size = BLOCK_SIZE - len(message) % BLOCK_SIZE
    for i in range(pad_size):
        message += pad_size.to_bytes(1, 'big')
    return message

def check_edge_case(base_url, block, iv, pad_size) -> bool:
    if pad_size > 1:
        return True
    new_iv = copy.deepcopy(iv)
    new_iv[-2] ^= 1
    if VERBOSE:
        print('   check_edge_case')
    if ask_oracle(base_url, new_iv + block):
        return True
    else:
        if VERBOSE:
            print('   Edge case return False')
        return False

def guess_iv_byte_for_pad_size(base_url, block, current_iv, pad_size) -> int:
    for i in range(BYTE_RANGE):
        iv = current_iv
        iv[-pad_size] = i.to_bytes(1, 'big')[0]
        ciphertext = iv + block
        answer = ask_oracle(base_url, ciphertext)
        if answer:
            if check_edge_case(base_url, block, iv, pad_size):
                if VERBOSE:
                    print('  Guess IV byte for pad_size: ', pad_size, ' found byte value', i)
                return i

def construct_iv_from_zeroing_iv(zeroing_iv, pad_size) -> bytearray:
    iv = copy.deepcopy(zeroing_iv)
    for i in range(pad_size-1):
        iv[BLOCK_SIZE-1-i] ^= pad_size
    return iv

def attack_single_block(base_url, block) -> bytearray:
    zeroing_iv = bytearray(BLOCK_SIZE)
    for i in range(BLOCK_SIZE):
        pad_size = i + 1
        current_iv = construct_iv_from_zeroing_iv(zeroing_iv, pad_size)
        search_res = guess_iv_byte_for_pad_size(base_url, block, current_iv, pad_size)
        zeroing_iv[-pad_size] = search_res ^ pad_size
    return zeroing_iv

def attack_full_ciphertext(base_url, ciphertext) -> bytearray:
    num_block = len(ciphertext)//BLOCK_SIZE
    if VERBOSE:
        print('num_block: ', num_block)

    plaintext = bytearray()
    for i in range(num_block-1):
        prev_block = ciphertext[(num_block-i-2)*BLOCK_SIZE : (num_block-1)*BLOCK_SIZE]
        current_block = ciphertext[(num_block-i-1)*BLOCK_SIZE : (num_block-i)*BLOCK_SIZE]
        if VERBOSE:
            print(' Cracking block', num_block - i - 1)
            print(' ciphertext_block', current_block)

        decrypted_block = attack_single_block(base_url, current_block)
        plaintext_block = bytearray()
        for j in range(BLOCK_SIZE):
            plaintext_block += (decrypted_block[j] ^ prev_block[j]).to_bytes(1, 'big')
        if VERBOSE:
            print(' plaintext_block: ', plaintext_block)
        plaintext = plaintext_block + plaintext
    return plaintext

def forge_ciphertext(base_url, message) -> bytes:
    cipher_block = secrets.token_bytes(BLOCK_SIZE)
    ciphertext = cipher_block
    prev_cipher_block = cipher_block
    plaintext = message
    num_block = len(plaintext)//BLOCK_SIZE
    if VERBOSE:
        print('num_block: ', num_block)
    for i in range(num_block):
        if VERBOSE:
            print('Forge ciphertext for block ', num_block-i-1)
        current_plaintext_block = plaintext[(num_block-i-1)*BLOCK_SIZE : (num_block-i)*BLOCK_SIZE]
        if VERBOSE:
            print('current_block: ', current_plaintext_block)
        decrypted_block = attack_single_block(base_url, prev_cipher_block)
        prev_cipher_block = bytearray()
        for j in range(BLOCK_SIZE):
            prev_cipher_block += (current_plaintext_block[j] ^ decrypted_block[j]).to_bytes(1, 'big')
        ciphertext = prev_cipher_block + ciphertext
    return bytes(ciphertext)

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f'usage: {sys.argv[0]} <base url>', file=sys.stderr)
        exit(1)
    base_url = sys.argv[1]
    res = requests.get(f'{base_url}/')
    ciphertext = res.cookies['authtoken']
    print('Received authtoken: ', ciphertext)
    print('Start cracking ...')
    secret_message = attack_full_ciphertext(base_url, bytes.fromhex(ciphertext))
    print('Secret message:')
    print(secret_message)
    message = f'I should have used authenticated encryption because ... plain CBC is not secure!'.encode()
    message = pad(message)
    print('Forge ciphertext for padded message: ', message)
    forged_ciphertext = forge_ciphertext(base_url, message)
    #forged_ciphertext = bytes.fromhex('58139eafdd3097ba1f6246ac030b4ca904712c3de65663615f38eaaf9e6eb0110e7c1693a3f68be6617b33d9d06159830868a98dd11596b48fe8346d5b90ccf39c5be1b245e14bb3617cf7353dc7fd4227e414538c8d2c28c49d8d38e7fd966b736563726574207365637265742e2e2e')
    print('Forged ciphertext: ', forged_ciphertext)
    print('Forged authtoken: ', forged_ciphertext.hex())
    print('Quotes from server:')
    for i in range(10):
        print(get_quote(base_url, forged_ciphertext))

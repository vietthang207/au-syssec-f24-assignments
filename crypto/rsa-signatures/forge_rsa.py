import base64
import json
import sys
import requests
from Crypto.Util.number import long_to_bytes
import secrets

def json_to_cookie(j: str) -> str:
    """Encode json data in a cookie-friendly way using base64."""
    # The JSON data is a string -> encode it into bytes
    json_as_bytes = j.encode()
    # base64-encode the bytes
    base64_as_bytes = base64.b64encode(json_as_bytes, altchars=b'-_')
    # b64encode returns bytes again, but we need a string -> decode it
    base64_as_str = base64_as_bytes.decode()
    return base64_as_str

def hex_to_int(s):
    return int.from_bytes(bytes.fromhex(s), 'big')

def gcd(a: int, b: int) -> int:
    while b != 0:
        a, b = b, a % b
    return a

def get_random_element(N: int):
    r = secrets.randbelow(N)
    while gcd(N, r) != 1:
        r = secrets.randbelow(N)
    return r

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

def mul_mod(N: int, x: int, y: int) -> int:
    return (x*y)%N

def get_pk(base_url: str):
    resp = requests.get(f'{base_url}/pk/')
    return resp.json()

def get_signature(base_url: str, doc: str):
    data = long_to_bytes(doc).hex()
    resp = requests.get(f'{base_url}/sign_random_document_for_students/{data}/')
    j = resp.json()
    return resp.json()['signature']

def get_quote(base_url: str, msg: str, signature: str):
    c = json_to_cookie(json.dumps({'msg': msg.hex(), 'signature': long_to_bytes(signature).hex() }))
    resp = requests.get(f'{base_url}/quote/', cookies={'grade': c})
    print(resp.text)

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f'usage: {sys.argv[0]} <base url>', file=sys.stderr)
        exit(1)
    base_url = sys.argv[1]

    pk = get_pk(base_url)
    chosen_plaintext = b'You got a 12 because you are an excellent student! :)'
    print('choosen_plaintext:', chosen_plaintext)
    encoded_plaintext = int.from_bytes(chosen_plaintext, 'big')
    print('encoded_plaintext:', encoded_plaintext)
    N = pk['N']
    try:
        m1 = get_random_element(N)
        m2 = mul_mod(N, encoded_plaintext, inverse_mod(N, m1))
        s1 = get_signature(base_url, m1)
        s2 = get_signature(base_url, m2)
    except Exception as e:
        print(e)
        
    s = mul_mod(N, hex_to_int(s1), hex_to_int(s2))
    print('get_quote')
    for i in range(10):
        get_quote(base_url, chosen_plaintext, s)

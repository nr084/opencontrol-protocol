"""Deterministic synthetic fixtures, independently encrypted by Python cryptography.
Not a live capture, password, session key or production randomness source.
"""
import json
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.decrepit.ciphers.algorithms import Blowfish

def checksum(data):
    data += b'\0' * (len(data) % 2)
    total = sum(int.from_bytes(data[i:i+2], 'big') for i in range(0, len(data), 2))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535

vectors = []
for wire in (1, 2, 3, 4):
    for payload in (b'odd', b'even'):
        key, salt, counter = bytes(range(16)), bytes(range(16, 24)), bytes(range(24, 32))
        inner = b'\x08\x00' + payload
        if wire > 1:
            inner += (1).to_bytes(4, 'big')
            inner += checksum(inner).to_bytes(2, 'big')
        plain = len(inner).to_bytes(2, 'big') + inner
        plain += b'\xff' * (-len(plain) % 8)
        blocks = b''.join((int.from_bytes(counter, 'little') + i).to_bytes(8, 'little') for i in range(len(plain)//8))
        encryptor = Cipher(Blowfish(key), modes.ECB()).encryptor()
        stream = encryptor.update(blocks) + encryptor.finalize()
        encrypted = bytes(a ^ b for a, b in zip(plain, stream))
        datagram = b'K\0\0\0\x08' + bytes(a ^ b for a, b in zip(counter, salt)) + encrypted
        vectors.append(dict(wire=wire,key=key.hex(),salt=salt.hex(),counter=counter.hex(),payload=payload.hex(),datagram=datagram.hex()))
target = Path(__file__).resolve().parents[1] / 'protocol/vectors/legacy_synthetic.json'
target.write_text(json.dumps(dict(provenance='Synthetic fixed test inputs, Python cryptography ECB-generated counter stream, not CBC or live material',vectors=vectors),indent=2)+'\n',encoding='utf-8')

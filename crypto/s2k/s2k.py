from __future__ import division, print_function

from binascii import hexlify as hx
from binascii import unhexlify as uhx
from hashlib import sha1, sha224, sha256, sha384, sha512

def decodecount(c):
    return (16 + (c & 15)) << ((c >> 4) + 6)

def fillblock(s, blocksize=128):
    repeats = blocksize // len(s)
    return ''.join(s for _ in range(repeats + 1))

def s2k(password, salt='', c=None, digestmod=sha1):
    h = digestmod()
    if c is None:
        h.update(salt + password)
        return h.digest()
    # The I&S case
    if len(salt) != 8:
        raise Exception()
    s = salt + password
    lens = len(s)
    bytecount = decodecount(c)
    while bytecount > 0:
        h.update(s[:bytecount])
        bytecount -= lens
    return h.digest()


def s2kis(password, salt, c, H=sha1):
    h = H()
    s = salt + password
    block = fillblock(s)
    bytecount = decodecount(c)
    i = 0
    while bytecount > 0:
        imods = i % len(s)
        length = min(bytecount, 64)
        h.update(block[imods:imods + length])
        bytecount -= length
        i += 64
    return h.digest()



TEST_SALT = str(bytearray(i for i in range(1, 9)))
TESTS = [
[0, 'hello', 'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d'],
[1, ('hello', TEST_SALT),
     'f4f7d67ef85a8ac07fedfd036702748ad458a130'],
[2, ('hello', TEST_SALT, 0xf1),
     'f2a57b7cf57cd35356df9d09205c5761fe18e1c4']]

#test0 = s2k('y', '\x79\x58\x0b\x0c\x1c\xca\x01\x11', 255, sha256)
#test1 = s2kis('y', '\x79\x58\x0b\x0c\x1c\xca\x01\x11', 255, sha256)
s = open('header.o.gpg', 'rb').read()
from Crypto.Cipher import AES
d = s[19:]

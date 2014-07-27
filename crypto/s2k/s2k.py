from __future__ import division, print_function

from binascii import hexlify as hx
from binascii import unhexlify as uhx
from hashlib import md5, sha1, sha224, sha256, sha384, sha512


def decodecount(c):
  return (16 + (c & 15)) << ((c >> 4) + 6)


def fillblock(s, blocksize=128):
  repeats = blocksize // len(s)
  return ''.join(s for _ in range(repeats + 1))


def _s2k_base(h, password, salt='', c=None):
  """Hash a single 'S2K context'."""
  if len(salt) not in {0, 8}:
    raise Exception()

  # Plain or salted
  if c is None:
    h.update(salt + password)
    return h.digest()

  # Iterated
  s = salt + password
  lens = len(s)
  bytecount = decodecount(c)
  while bytecount > 0:
    h.update(s[:bytecount])
    bytecount -= lens

  return h.digest()


def s2k(password, salt='', c=None, H=sha1, outlen=None):
  """Erm...S2K. In all its glory."""
  if outlen is None:
    outlen = H().digest_size
  out = ''
  leading_zeros = 0
  while len(out) < outlen:
    h = H('\x00' * leading_zeros)
    out += _s2k_base(h, password, salt, c)
    leading_zeros += 1
  return out[:outlen]


TEST_SALT = bytes(bytearray(i for i in range(1, 9)))
TESTS = [
  ['aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d', ('hello', '', None)],
  ['f4f7d67ef85a8ac07fedfd036702748ad458a130', ('hello', TEST_SALT, None)],
  ['f2a57b7cf57cd35356df9d09205c5761fe18e1c4', ('hello', TEST_SALT, 0xf1)]]

def test_kats():
  for expected, test in TESTS:
    if hx(s2k(*test)) != expected:
      raise Exception()

HH = [['Md5', 'Sha1', 'Sha224', 'Sha256', 'Sha384', 'Sha512'],
      [md5, sha1, sha224, sha256, sha384, sha512]]

SIMPLE_TEMPLATE = '''\
  expectedKey = '{expected}';
  passphrase = '{input}';
  s2kTest = new e2e.openpgp.SimpleS2K(new e2e.hash.{hash_name});
  assertArrayEquals(expectedKey,
                    goog.crypt.byteArrayToHex(
                        s2k.getKey(passphrase, {length})));
'''
SALTED_TEMPLATE = '''\
  salt = goog.crypt.hexToByteArray('{salt}');
  expectedKey = '{expected}';
  passphrase = goog.crypt.hexToByteArray('{input}');
  s2kTest = new e2e.openpgp.SaltedS2K(new e2e.hash.{hash_name}, salt);
  assertArrayEquals(expectedKey,
                    goog.crypt.byteArrayToHex(
                        s2k.getKey(passphrase, {length})));
'''
SALTED_TEMPLATE = '''\
  salt = goog.crypt.hexToByteArray('{salt}');
  count = {count};
  expectedKey = '{expected}';
  passphrase = goog.crypt.hexToByteArray('{input}');
  s2kTest = new e2e.openpgp.IteratedS2K(new e2e.hash.{hash_name}, salt, count);
  assertArrayEquals(expectedKey,
                    goog.crypt.byteArrayToHex(
                        s2k.getKey(passphrase, {length})));
'''


SIMPLE_TEMPLATE = '''\
    expectedKey = '{expected}';
    s2kTest = new e2e.openpgp.SimpleS2K(new e2e.hash.{hash_name});
    assertArrayEquals(expectedKey,
                      goog.crypt.byteArrayToHex(
                          s2k.getKey(passphrase, {length})));\
'''
SALTED_TEMPLATE = '''\
    expectedKey = '{expected}';
    s2kTest = new e2e.openpgp.SaltedS2K(new e2e.hash.{hash_name}, salt);
    assertArrayEquals(expectedKey,
                      goog.crypt.byteArrayToHex(
                          s2k.getKey(passphrase, {length})));\
'''
ITERATED_TEMPLATE = '''\
    expectedKey = '{expected}';
    s2kTest = new e2e.openpgp.IteratedS2K(new e2e.hash.{hash_name}, salt, {count});
    assertArrayEquals(expectedKey,
                      goog.crypt.byteArrayToHex(
                          s2k.getKey(passphrase, {length})));\
'''


KAT_TEMPLATE_1 = '''\
  function test{name}Kats() {{
    var password = '{password}';
    var salt = [1, 2, 3, 4, 5, 6, 7, 8];

    // Short-output KATs
{short_output}

    // Long-output KATs
{long_output}
  }}
'''

def gen_kat1(password, name):
  kats = []
  length = 4
  for name, H in zip(*HH):
    expected = s2k(password, H=H, outlen=length)
    kats.append(SIMPLE_TEMPLATE.format(expected=hx(expected), hash_name=name, length=length))
    expected = s2k(password, TEST_SALT, H=H, outlen=length)
    kats.append(SALTED_TEMPLATE.format(expected=hx(expected), hash_name=name, length=length))
    for c in range(3):
      expected = s2k(password, TEST_SALT, c=c, H=H, outlen=length)
      kats.append(ITERATED_TEMPLATE.format(expected=hx(expected), hash_name=name, count=c, length=length))
  short_output = '\n'.join(kats)

  kats = []
  length = 32
  for name, H in zip(*HH):
    expected = s2k(password, H=H, outlen=length)
    kats.append(SIMPLE_TEMPLATE.format(expected=hx(expected), hash_name=name, length=length))
    expected = s2k(password, TEST_SALT, H=H, outlen=length)
    kats.append(SALTED_TEMPLATE.format(expected=hx(expected), hash_name=name, length=length))
    for c in range(3):
      expected = s2k(password, TEST_SALT, c=c, H=H, outlen=length)
      kats.append(ITERATED_TEMPLATE.format(expected=hx(expected), hash_name=name, count=c, length=length))
  long_output = '\n'.join(kats)

  return KAT_TEMPLATE_1.format(password=password, name=name, short_output=short_output, long_output=long_output)

password = '''the brawny quark fox tunnels lazily'''
print(gen_kat1(password, 'shortInput'))
password = '''the brawny quark fox tunnels lazily over the alarmed frog Who then tests? whether the weather is good %*(#)%_&qwertyuiopasdfjkl;zxcvnm,.''' * 11
print(gen_kat1(password, 'longInput'))

if __name__ == '__main__':
  test_kats()

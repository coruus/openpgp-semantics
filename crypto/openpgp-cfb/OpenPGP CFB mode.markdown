# OpenPGP CFB (OCFB) mode

OpenPGP defines two variants of CFB mode, OCFB-R, and OCFB-NR.

These differ slightly; OCFB-R is a valid instantiation of the CFB block
cipher mode with the same security properties. OCFB-NR is an invalid
variant of CFB; it reuses two bytes of keystream.

OCFB-NR is used for most purposes in the OpenPGP standard. OCFB-R is,
by-and-large, deprecated.

## RFC 4880 definitions

OpenPGP CFB with resynchronization step (OCFB-R):

    s = blocksize
    prefix = randombytes(s)
    fr = [0] * s
    fre = encrypt(FR)
    fr  = xor(FRE, prefix)
    ciphertext.append(fr)
    fre = encrypt(FR)
    ciphertext.append(xor(FRE[0:2] ^ prefix[0:2]))
    # CFB resync with shift 16
    fr = C[2:s+2]
    ciphertext += cfb(plaintext, shift=s, iv=fr)

OpenPGP CFB with keystream reuse (OCFB-NR):

    s = blocksize
    prefix = randombytes(s)
    # Load the feedback register with zeros.
    fr  = [0] * s
    fre = encrypt(fre)
    # Load the feedback register with the encrypted prefix.
    fr  = xor(fre, prefix)
    ciphertext.append(fr)
    fre = encrypt(fr)
    # Use the first two bytes of keystream that will be
    # used to encrypt the plaintext to re-encrypt part
    # of the prefix.
    ciphertext += xor(fre[0:2] ^ prefix[0:2])
    ciphertext += cfb(plaintext, shift=s, iv=fr)

## In practice

Some software does not conform to the RFC 4880 spec.

(In addition, it is not possible for software that complies with the
OpenPGP RFC 4880 specification to be FIPS-compliant; OCFB-NR is not
an approved mode of operation for any FIPS-approved cipher.[^fips]
It is unclear whether OCFB-R is.)

OCFB-NR, however, can be made a valid implementation of CFB-blocksize,
in the following way:

    s = blocksize
    prefix = randombytes(s)
    # Load the feedback register with zeros.
    fr = [0] * s
    fre = encrypt(fr)
    fr = xor(fre, prefix)
    ciphertext += fr
    # Append two zeros to the ciphertext.
    ciphertext += [0, 0]
    ciphertext += cfb(plaintext, shift=s, iv=fr)

This implements CFB-blocksize by appending fixed 'padding' to the
initial block to comply with OpenPGP's wire format.

Decryption for OCFB-NR mode may proceed in the standards-approved way,
so long as bytes 17 and 18 of the ciphertext are not examined.

It is also possible to decrypt OCFB-R ciphertexts for which bytes 17
and 18 are invalid by doing:

    fr = [0] * s
    fre = encrypt(fr)
    e1_prefix = ciphertext[0:16]
    prefix = xor(fre, e1_prefix)
    e2_prefix = encrypt(e1_prefix)
    last_two = xor(e2_prefix[0:2], prefix[0:2])
    fr = ciphertext[12:16] + last_two
    plaintext = cfb(ciphertext[19:], shift=s, iv=fr)

This technique is recommended.


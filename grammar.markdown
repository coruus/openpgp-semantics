OpenPGP syntax and semantic validity
====================================
(incomplete draft)
------------------



Introduction
============

A note: All references are to RFC 4880, unless otherwise specified.

Common definitions
===================

TODO cleanup and make bindings consistent

## Notes on types

    _||_ : (Bool, Bool) -> Bool
    _|_  : ({Type}A, {Type}B) -> (A + B)
    # (Note that the | operator represents ordered choice.)
    map : (T -> T) -> (Sequence[T] -> Sequence[T])
    take : (Sequence, Nat, Nat) -> (Sequence)

Basic datatypes
---------------

Unsigned big-endian integers (ubints):

    byte       ::= 0..255
               >>= \x = Nat(x0)
    two_octet  ::= byte byte
               >>= \x = x0<<8 + x1
    four_octet ::= two_octet two_octet
               >>= \x = x0<<16 + x1

Old-style lengths are just ubints; their length is implicitly selected
by other syntactic elements.

    len_old1 ::= byte
             >>= \length = x0
    len_old2 ::= two_octet
             >>= \length = x0
    len_old4 ::= four_octet
             >>= \length = x0

New-style lengths (4.2.2) implicitly encode their own length:

    len_new1 ::= 0..192                                       # 4.2.2.1
             >>= \length = Nat(x0)
    len_new2 ::= 192..223 0..255                              # 4.2.2.2
             >>= \length = Nat((x0 - 192)<<8 + x1 + 192)
    len_new4 ::= 255 byte byte byte byte                      # 4.2.2.3
             >>= \length = Nat(x1<<24 + x2<<16 + x3<<8 + x4)
    len_new  ::= (len_new1 | len_new2 | len_new4 | len_new_partial)

New-style lengths with their first byte in 192..223 encode a *partial* body
length (4.2.2.4),

    let partial_length x = Nat(1 << (x&0x1f))

which, by definition, is in {2^n : n /in 0..30. Other semantic
conditions apply:

     packet_body <<= nil
     len_new_partial ::= 224..254 bytes[length] len_new
                     >>= \length = partial_length(x0)
         packet_body <<= packet_body ++ x1

Other common types
------------------

Some other commonly used types:

    sha1_hash   ::= byte[20]
    fingerprint ::= sha1_hash
    timestamp   ::= four_octet
    timestamporinf ::= timestamp
                   >>= \x = IF x0 == 0 THEN Inf ELSE x0

# Elliptic curve cryptography definitions

### Curve OIDs

RFC 6637 s. 11:

    curve_oid_p256 ::= 0x08 0x2a 0x86 0x48 0xce 0x3d 0x03 0x01 0x07
    curve_oid_p384 ::= 0x05 0x2b 0x81 0x04 0x00 0x22
    curve_oid_p521 ::= 0x05 0x2b 0x81 0x04 0x00 0x23

    ec_curve_oid   ::= curve_oid_p256 | curve_oid_p384 | curve_oid_p521

### Algorithm limitations

RFC 6637 s. 11-13: SHA2 is the only permitted hash algorithm for the
ECDH KDF, and for ECDSA hashes-to-sign:

    ec_hash_algo  ::= hash_algo_sha2

For ECDH:

    ecdh_kek_algo   ::= symm_algo_aes
    ecdh_kdf_params ::= ecdh_kdf_algo:ec_hash_algo ecdh_kek_algo


# Packet tags

RFC 4880 s. 4.2.0.

## PTag bit-level diagram

          ================= old-format
          1 0=========================
          | | ------------- packet tag
          | | | | | | ----- length type
          | | | | | | | |
         +---------------+
    PTag |7 6 5 4 3 2 1 0|
         +---------------+
          | | | | | | | |
          | | ------------- packet tag
          1 1 =======================
          ================= new-format


## Special packet tag types

We define two types to represent packets whose contents are opaque:

    # An opaque, possibly valid private packet body
    private_body ::= bytes[length]

    # An opaque, invalid packet body
    invalid_packet_body ::= bytes[length]

The invalid packet body type is used to recover parsing from an invalid
packet; this is needed to replicate the behavior of typical OpenPGP
implementations.

## Old- or new-format tag types (type < 16)

All 4-bit tag types, old- or new-format PTags:

    private0 ::=\
      (  0x00 len_old1 | 0x01 len_old2 | 0x02 len_old4 | 0xc0 len_new)
      (private_body | invalid_tag_body)
    pkesk ::=\
      (  0x04 len_old1 | 0x05 len_old2 | 0x06 len_old4 | 0xc1 len_new)
      (pkesk_body | invalid_tag_body)
    sig ::=\
      (  0x08 len_old1 | 0x09 len_old2 | 0x0a len_old4 | 0xc2 len_new)
      (sig_body | invalid_tag_body)
    skesk ::=\
      (  0x0c len_old1 | 0x0d len_old2 | 0x0e len_old4 | 0xc3 len_new)
      (skesk_body | invalid_tag_body)
    onepass_sig ::=\
      (  0x10 len_old1 | 0x11 len_old2 | 0x12 len_old4 | 0xc4 len_new)
      (onepass_sig_body | invalid_tag_body)
    secretkey ::=\
      (  0x14 len_old1 | 0x15 len_old2 | 0x16 len_old4 | 0xc5 len_new)
      (secretkey_body | invalid_tag_body)
    publickey ::=\
      (  0x18 len_old1 | 0x19 len_old2 | 0x1a len_old4 | 0xc6 len_new)
      (publickey_body | invalid_tag_body)
    secretsubkey ::=\
      (  0x1c len_old1 | 0x1d len_old2 | 0x1e len_old4 | 0xc7 len_new)
      (secretsubkey_body | invalid_tag_body)
    compressed ::=\
      (  0x20 len_old1 | 0x21 len_old2 | 0x22 len_old4 | 0xc8 len_new)
      (compressed_body | invalid_tag_body)
    sedp ::=\
      (  0x24 len_old1 | 0x25 len_old2 | 0x26 len_old4 | 0xc9 len_new)
      (sedp_body | invalid_tag_body)
    marker ::=\
      (  0x28 len_old1 | 0x29 len_old2 | 0x2a len_old4 | 0xca len_new)
      (marker_body | invalid_tag_body)
    literal ::=\
      (  0x2c len_old1 | 0x2d len_old2 | 0x2e len_old4 | 0xcb len_new)
      (literal_body | invalid_tag_body)
    trust ::=\
      (  0x30 len_old1 | 0x31 len_old2 | 0x32 len_old4 | 0xcc len_new)
      (trust_body | invalid_tag_body)
    userid ::=\
      (  0x34 len_old1 | 0x35 len_old2 | 0x36 len_old4 | 0xcd len_new)
      (userid_body | invalid_tag_body)
    publicsubkey ::=\
      (  0x38 len_old1 | 0x39 len_old2 | 0x3a len_old4 | 0xce len_new)
      (publicsubkey_body | invalid_tag_body)
    private15 ::=\
      (  0x3c len_old1 | 0x3d len_old2 | 0x3e len_old4 | 0xcf len_new)
      (private_body | invalid_tag_body)

## New-format tag types (type > 15)

All 6-bit tag types > 15, new-format PTags only:

    private16 ::=\
      0xd0 len_new (private_body | invalid_tag_body)
    userattrib ::=\
      0xd1 len_new (userattrib_body | invalid_tag_body)
    seipd ::=\
      0xd2 len_new (seipd_body | invalid_tag_body)
    mdc ::=\
      0xd3 len_new (mdc_body | invalid_tag_body)
    private20 ::=\
      0xd4 len_new (private_body | invalid_tag_body)
    private21 ::=\
      0xd5 len_new (private_body | invalid_tag_body)
    private22 ::=\
      0xd6 len_new (private_body | invalid_tag_body)
    private23 ::=\
      0xd7 len_new (private_body | invalid_tag_body)

# Algorithms


## Public-key algorithms

RFC 4880 s. 9.1.

### Prime-based crypto

#### RSA

    # RSA
    RSA_ES             ::= 1
    algo_rsa_enc       ::= RSA_E=2 | RSA_ES
    algo_rsa_sig       ::= RSA_S=3 | RSA_ES

    # RSA predicates
    let \is_rsae x       = (x == 2 || x == 1)
    let \is_rsas x       = (x == 3 || x == 1)
    let \is_rsa  x       = (x \in {1,2,3})

#### Other prime-based crypto

TODO(dlg): PS use of X9.42 DH?

    algo_elg_es        ::= ELG_ES=20
    algo_elg_enc       ::= ELG_E=16
    algo_dhx942_enc    ::= DH_X942=21

    # Prime-based encryption
    algo_prime_enc     ::= algo_elg_enc | algo_rsa_enc | algo_dhx942_enc

    # Prime-based signatures
    algo_prime_sig     ::= algo_rsa_sig | algo_dsa | algo_elg_es

#### Prime-based crypto status predicate

The status of prime-based-crypto algorithms, according to RFC4880:

    let \algo_status x = CASE DH_X942 THEN "reserved"
                         CASE ELG_ES  THEN "formerly"
                         CASE RSA_ES  THEN "deprecated"

### Elliptic-curve crypto

The EC algorithms defined by RFC 6637 s. 5:

    algo_ecdh          ::= ECDH=18
    algo_ecdsa         ::= ECDSA=19

### Unspecified crypto algorithms

    PK_EXPERIMENTAL = 100..110
    PK_UNKNOWN      = 4..15 | 22..99 | 111..255

    let \algo_pk_shouldnt_process x = (   x \in PK_EXPERIMENTAL
                                       || x \in PK_UNKNOWN
                                       || x == ELG_ES)

## Symmetric-key algorithms

The symmetric-key encryption algorithms defined in RFC 4880 s. 9.1,
extended by RFC 5581.

    algo_symm           ::= algo_symm_modern | algo_symm_old | algo_symm_other

The "plaintext" algorithm, also known as (\rot13)^2:

    algo_symm_plaintext ::= PLAINTEXT=0

AES has to be broken out from other algorithms to support RFC 6637's
constraints on KEK algorithm:

    # Algorithms with < 128-bit security strength
    algo_symm_old       ::= IDEA=1 | TDES=2 | CAST5=3 | BLOWFISH=4
    # Advanced Encryption Standard
    algo_symm_aes       ::= AES128=7 | AES192=8 | AES256=9

RFC 5581's extension to add Camellia:

    algo_symm_camellia  ::= CAMELLIA128=11 | CAMELLIA192=12 | CAMELLIA256=13

We also define a set of modern(-ish) crypto algorithms:

    # Algorithms with >= 128-bit security strength, no weak keys
    algo_symm_modern    ::= (  algo_symm_aes
                             | TWOFISH=10
                             | algo_symm_camellia )

### Unspecified symmetric crypto algorithms

We differentiate reserved, private, and undefined crypto algorithm
numbers:

    SYMM_RESERVED       ::= 5..6
    SYMM_PRIVATE        ::= 100..109
    SYMM_UNDEFINED      ::= 14..99 | 111..255
    algo_symm_other     ::= SYMM_RESERVED | SYMM_PRIVATE | SYMM_UNDEFINED

 
## Hash algorithms

    algo_hash          ::=  algo_hash_old
                          | algo_hash_sha1
                          | algo_hash_sha2
                          | algo_hash_other

### Hash algorithms, oldest

    algo_hash_old      ::= MD5=1 | RIPEMD160=3
    algo_hash_sha1     ::= SHA1=2


### Hash algorithms, SHA-2

SHA2-512/384 is broken out separately; its use is required for the RFC 6637
s. 12.2.1 profile.

    algo_hash_sha2_512 ::= SHA2_384=9 | SHA2_512=10
    algo_hash_sha2     ::= SHA2_224=11 | SHA2_256=8 | algo_hash_sha2_512

### Unspecified hash algorithms

    HASH_RESERVED      ::= 4..7
    HASH_PRIVATE       ::= 100..110
    HASH_UNDEFINED     ::= 111..255
    algo_hash_other    ::= HASH_RESERVED | HASH_PRIVATE | HASH_UNDEFINED


## String-to-key (S2K) specifiers

String-to-key (S2K) specifiers are used to combine a "password" and,
optionally, salt into a symmetric encryption key. The specifier format
is defined by RFC 4880 s. 3.7.1.

### Common definitions

If salt is used, it is always 8 bytes long:

   s2k_salt          ::= bytes[8]

### S2K specifier types

S2K *specifiers* should not be confused with S2K *conventions*; an S2K
convention contains an S2K specifier.

#### Undefined S2K specifiers

Because the length of an S2K specifier is determined by its definition,
undefined S2K specifiers result in the remainder of the packet becoming
unparseable.

    s2k_error         ::= (2 | 4..255) error

#### Simple S2K

Simple S2K specifiers (3.7.1.1):

    s2k_simple        ::= S2K_SIMPLE=0x00   hash_algo

#### Salted S2K

Salted S2Ks specifiers (3.7.1.2):

    s2k_salted        ::= S2K_SALTED=0x01   hash_algo s2k_salt

#### Iterated and salted S2K

Iterated and salted S2K specifiers are defined by RFC 4480 s. 3.7.1.3.

A helper function to decode the encoded bytecount of hashed material,

    \decode_s2k_c : Nat -> (Nat -> Nat)
    let \decode_s2k_c c =
      let \bytecount passlen =
        max(passlen + saltlen=8,
            (16 + (c&15)) << ((c>>4) + 6))

and the specifier definition:

    s2k_iterated      ::= S2K_ITERATED=0x03
                          hash_algo
                          s2k_salt
                          s2k_encoded_count

### EC private key S2K specifiers

RFC 6637 requires that, when used for protecting a private EC key, only
the I&S S2K specifiers are used:

    # RFC 6637 s. 13
    s2k_ec           ::= s2k_iterated

Since SHA1 only provides 180-bits of output, it is impossible to achieve
the 192-bit security strength required by RFC 6637 s. 12.2.1 using it:

    # RFC 6637 s. 12.2.1
    s2k_ec_192b       ::= S2K_ITERATED=0x03
                          hash_algo_sha2_512
                          s2k_salt
                          s2k_encoded_count

RFC 6637 apparently does not forbid the use of SHA1 as the S2K hash function;
but it dosn't state that it may be used, either. QQQQ: sha2 acceptable?


### S2K specifiers, generally

    s2k_rfc4880       ::= s2k_simple | s2k_salted | s2k_iterated | s2k_error



# Packet bodies

## Tag 1: Public-key encrypted session key

RFC 4880 s. 5.1:

### Prime based crypto

    # RSA-E/RSA-ES
    pkesk_rsa_asf         ::= algo_rsa_enc rsa_memodn:mpi
    # ELG-E
    pkesk_elge_asf        ::= algo_elg_enc elge_gkmodp:mpi elge_mykmodp:mpi
    # X942DH
    # TODO

### Elliptic curve crypto

RFC 6637 s. 8:

    pkesk_ecdh_wrappedkey ::= wrappedkeylen:32..254 bytes[wrappedkeylen]
    pkesk_ecdh_asf        ::= ec_ephem_pubkey:mpi pkesk_ecdh_wrappedkey

### Public-key encrypted session key

    pkesk_v               ::= 3
    pkesk_asf             ::= (pkesk_elge_asf | pkesk_rsa_asf | pkesk_ecdh_asf)
    pkesk_body            ::= pkesk_v keyid pkesk_asf


## Tag 2: Signature (tag 2)

RFC 4880 s. 5.2.1

### Common definitions

Some definitions common to all signature formats:

    sig_creation_time  ::= timestamp
    sig_signer_keyid   ::= keyid

The left 16-bits of the signed hash:

    sig_left2          ::= byte byte

### Signature types

RFC 4880 defines a limited number of signature types:

    SIG_V3 ::= (  SIG_BINARY         = 0x00
                | SIG_TEXT           = 0x01
                | SIG_GENERIC        = 0x10
                | SIG_PERSONA        = 0x11
                | SIG_CASUAL         = 0x12
                | SIG_POSITIVE       = 0x13
                | SIG_SUBKEYBIND     = 0x18
                | SIG_PRIMARYKEYBIND = 0x19
                | SIG_KEY            = 0x1f
                | SIG_REVOKE         = 0x20
                | SIG_SUBKEYREVOKE   = 0x28
                | SIG_CERTREVOKE     = 0x30
                | SIG_TIMESTAMP      = 0x40
                | SIG_THIRDPARTY     = 0x50 )
    SIG_V4 ::= SIG_V3 | SIG_STANDALONE=0x02

    sig_err_v3         ::= {SIG_V4}/{SIG_V3} error
    sig_type_v3        ::= SIG_V3 | sig_type_unknown | sig_type_err_v3
    sig_type_v4        ::= SIG_V4 | sig_type_unknown
    sig_type_unknown   ::= (0x03..0x09 | 0x14..0x17 | 0x1a..0x1e | 0x21..0x27
                            | 0x29 | 0x31..0x39 | 0x41..0x49 | 0x51..0xff)

QQQQ: Should an unknown signature type produce an error here?

### Algorithm specific fields

#### Prime-based crypto algorithm-specific fields

RFC 4880 s. 5.2.2:

    # RSA-S/RSA-ES
    sig_asf_rsa        ::= &(is_rsas pubkey_algo_rsa)
                           rsa_mdmodn:mpi
    # DSA
    sig_asf_dsa        ::= &pubkey_algo==DSA
                           dsa_r:mpi
                           dsa_s:mpi
    # ELG-ES
    # only version 2

#### Elliptic-curve crypto algorithm-specific fields

RFC 6637 s. 10 (incorporating RFC 4880 s. 5.2.2 by reference):

    # ECDSA
    sig_asf_ecdsa      ::= &pubkey_algo==ECDSA ecdsa_r:mpi ecdsa_s:mpi


### Version 4 signature subpackets

Version 4 signatures can contain both signed and unsigned subpackets:

    # RFC 4880 s. 5.2.3
    hashed_subpackets   ::= hashed_subpacketlen:len_old2
                            bytes[hashed_subpacketlen]
    unhashed_subpackets ::= unhashed_subpacketlen:len_old2
                            bytes[unhashed_subpacketlen]

#### Subpacket format

RFC 4880 s. 5.2.3.1

    len_new'  ::= len_new -- len_new_partial
    subpacket ::= subpacket_length:len_new'
                  subpacket_type
                  subpacket_data

#### Subpacket types

RFC 4880 s. 5.2.3.1:

    subpacket_type ::=   subpacket_type_placehold
                       | subpacket_type_reserved
                       | subpacket_type_specified
                       | subpacket_type_undefined
                    >>= \critical=(critbit_set x0)

A subpacket is "critical" if bit 7 is set:

    let \critbit_set x = (64&x) == 64

Several types of subpacket, each with its own syntax, are defined:

    subpacket_type_placehold ::= 10|74
    subpacket_type_reserved  ::= 0..1|64..65|8|72|13..15|74..79|17..19|81..83
    subpacket_type_private   ::= 100..110|164..174
    subpacket_type_defined   ::=   SP_SIG_CREATION_TIME        = ( 2|66)
                                 | SP_SIG_EXPIRATION_TIME      = ( 3|67)
                                 | SP_EXPORTABLE_CERTIFICATION = ( 4|68)
                                 | SP_TRUST_SIGNATURE          = ( 5|69)
                                 | SP_REGULAR_EXPRESSION       = ( 6|70)
                                 | SP_REVOCABLE                = ( 7|71)
                                 | SP_KEY_EXPIRATION_TIME      = ( 9|73)
                                 | SP_PREF_SYMM_ALGO           = (11|75)
                                 | SP_PREF_REVOCATION_KEY      = (12|76)
                                 | SP_PREF_ISSURE              = (16|80)
                                 | SP_PREF_NOTATION_DATA       = (20|84)
                                 | SP_PREF_HASH_ALGO           = (21|85)
                                 | SP_PREF_COMP_ALGO           = (22|86)
                                 | SP_PREF_KEY_SERVER          = (24|88)
                                 | SP_PRIMARY_USER_ID          = (25|89)
                                 | SP_POLICY_URI               = (26|90)
                                 | SP_KEY_FLAGS                = (27|91)
                                 | SP_SIGNERS_USER_ID          = (28|92)
                                 | SP_REASON_FOR_REVOCATION    = (29|93)
                                 | SP_FEATURES                 = (30|94)
                                 | SP_SIGNATURE_TARGET         = (31|95)
                                 | SP_EMBEDDED_SIGNATURE       = (32|96)
    subpacket_type_specified  ::=   subpacket_type_placehold
                                  | subpacket_type_reserved
                                  | subpacket_type_private
                                  | subpacket_type_defined
    subpacket_type_undefined  ::= {0..255}--subpacket_type_specified


*Subtype 2:* Signature creation time (5.2.3.4):

    sp_signature_creation_time_body ::= signature_creation_time:timestamp

*Subtype 3:* Issuer (5.2.3.5):

    sp_signature_issuer ::= issuer:keyid

*Subtype 3*: Signature expiration time (5.2.3.10):

    sp_signature_creation_time ::= sig_expiration_time':timestamp_or_inf

*Subtype 4*: Exportable certification (5.2.3.11):

    sp_exportable_certification ::= 0x0|0x1
                                >>= \exportable'=Bool(x0)

    \exportable = IF /exportable' THEN \exportable' ELSE True

*Subtype 5:* Trust signature (5.2.3.13):

    sp_trust_signature ::= level:byte amount:byte

    let \trust_partial = level >= 60
    let \trust_complete = level >= 120

*Subtype 6:* Regular expression (5.2.3.14):

    sp_regular_expression ::= regex:byte[subpacketlen-1] 0x00

*Subtype 7:* Revocable (5.2.3.12):

    sp_revocable ::= 0x00|0x01
    \revocable = IF \revocable' THEN \revocable' ELSE True

*Subtype 9:* Key expiration time (5.2.3.6):

    sp_key_expiration_time ::= key_expiration_time':timestamp
    # additional condition: only on self-signature

*Subtype 11:* Preferred symmetric algorithms (5.2.3.7):

    sp_pref_symm_algo ::= Sequence[symm_algo]

*Subtype 12:* Revocation key (5.2.3.15):

    sp_revocation_key ::= 0x80|0xc0 algo_pubkey revocation_key:fingerprint
                      >>= \sensitive = x0 == 0xc0

*Subtype 20:* Notation data (5.2.3.16):

    sp_notation_flags ::= 0x80|0x00 0x00 0x00 0x00
                      >>= \human_readable = x0 == 0x80
    sp_notation_name_iana ::= (utf8_text--'@')*
    dns_domain_name ::= # TODO
    sp_notation_name_user ::= (utf8_text--'@') '@' dns_domain_name
    sp_notation_data ::= sp_notation_flags
                         namelen:len_old2
                         valuelen:len_old2
                         &((namelen+valuelen+8) == subpacketlen)
                         name:utf8_text[namelen]
                         value:bytes[valuelen]

*Subtype 21:* Preferred hash algorithms (5.2.3.8);

    sp_pref_hash_algo ::= Sequence[hash_algo]

*Subtype 22:* Preferred compression algorithms (5.2.3.9):

    sp_pref_comp_algo ::= Sequence[comp_algo]

*Subtype 23:* Key server preferences (5.2.3.17):

    sp_keyserver_prefs ::= 0x80|0x00 0x00[subpacketlen-1]
    #selfsig-only

*Subtype 24:* Preferred key server (5.2.3.18):

    sp_preferred_keyserver ::= uri:bytes[subpacketlen]

*Subtype 25:* Primary user id (5.2.3.19):

    sp_primary_userid ::= 0x00|0x01
                      >>= \is_primary' = (x0 == 0x01)
    \is_primary = IF /is_primary' THEN \is_primary ELSE False

*Subtype 26:* Policy URI (5.2.3.20):

    sp_policy_uri ::= policy_uri:bytes[subpacketlen]

*Subtype 27:* Key flags (5.2.3.21):

    \kf_defined = {KF_CERTIFY                = 0x01,
                   KF_SIGN                   = 0x02,
                   KF_ENCRYPT_COMMUNICATIONS = 0x04,
                   KF_ENCRYPT_STORAGE        = 0x08,
                   KF_SPLIT_BY_SECRET_SHARE  = 0x10,
                   KF_AUTHENTICATION         = 0x20,
                   KF_PRIVATE_IS_MULTIHOLDER = 0x80}
    sp_key_flags ::= (map binary_or (poset kf_defined)) bytes[subpacketlen-1]

    # 0x10, 0x80 self-sig only for 0x1f 0x18 sig types

*Subtype 28:* Signer's user id (5.2.3.22):

    sp_signers_userid ::= userid

*Subtype 29:* Reasons for revocation (5.2.3.23):

A few machine-readable revocation-reason codes are defined:

    rr_code_both ::=   RR_NO_REASON      =  0
    rr_code_key  ::=   RR_SUPERSEDED     =  1
                     | RR_COMPROMISED    =  2
                     | RR_RETIRED        =  3
    rr_code_cert ::=   RR_USERID_INVALID = 32
    rr_code_priv ::= 100..110
    rr_code ::=   rr_code_both
                | &(is_overkey sigtype) rr_code_key
                | &(is_certification sigtype) rr_code_cert
                | rr_code_priv

    sp_reason_for_revocation ::= rr_code utf8_text[subpacketlen-1]

*Subtype 30:* Features (5.2.3.24):

    feat_mdc    ::= 0x00|0x01
                >>= \use_mdc = x0 == 0x01
    sp_features ::= feat_mdc bytes[subpacketlen-1]

*Subtype 31:* Signature target (5.2.3.25):

    target_hash_algo ::= algo_hash
                     >>= \=targethashlen = hashlen
    sp_signature_target ::= algo_pubkey
                            target_hash_algo
                            hash:bytes[targethashlen]

    # revocation, third-party, timestamp

*Subtype 32:* Embedded signature (5.2.3.26):

    sp_embedded_signature ::= signature_packet_body


### Version 3 signatures

The version 3 signature packet format (5.2.2):

    sig_asfs_v3        ::= sig_asf_rsa | sig_asf_dsa
    sig_body_hashed_v3 ::= sig_type_v3 sig_creation_time
    sig_body_v3        ::= 0x03
                           0x05
                           sig_body_hashed_v3
                           sig_signer_keyid:keyid
                           pubkey_algo
                           hash_algo
                           sig_left2
                           sig_asfs_v3

### Version 4 signatures

The version 4 signature packet format (5.2.3):

    sig_asfs_v4        ::= sig_asf_rsa | sig_asf_dsa | sig_asf_ecdsa
    sig_body_v4        ::= 0x04
                           sig_type_v4
                           pubkey_algo
                           hash_algo
                           hashed_subpackets
                           unhashed_subpackets
                           sig_left2
                           sig_asfs_v4

### Signature body

    sig_body           ::= sig_body_v3 || sig_body_v4


## Tag 3: Symmetrically encrypted session key

RFC 4880 s. 5.3:

    skesk_esk   ::= bytes[length - 3]
    skesk_body  ::= 0x04 symm_algo s2k_spec skesk_esk

QQQQ: RFC 6337 limitations?


## Tag 4: One-pass signature (tag 4)

A useful new packet type introduced in version 4.

    onepass_sig_nested ::= 0x00|0x01
                       >>= \x = Bool(x)
    onepass_sig_body ::= 0x03
                         sig_type_v4
                         hash_algo
                         pubkey_algo
                         onepass_sig_signer_keyid:keyid
                         onepass_sig_nested


## Tags 5,6,7,14: Asymmetric keys

### Packet tags

*Tag 6. Public-key:*

    publickey_body    ::= pubkey

*Tag 14. Public-subkey:*

    publicsubkey_body ::= pubkey

*Tag 5. Secret-key:*

    secretkey_body    ::= pubkey secretkey

*Tag 7. Secret-subkey:*

    secretsubkey_body ::= pubkey secretkey


### Definitions common to public and secret keys

#### Algorithm-specific fields

##### Prime-based crypto

    rsa_n, rsa_e          = mpi, mpi
    pubkey_asf_rsa_v3   ::= rsa_n rsa_e
    pubkey_asf_rsa      ::= &(is_rsa pubkey_algo)

    dsa_p, dsa_q, dsa_y   = mpi, mpi, mpi
    pubkey_asf_dsa      ::= &pubkey_algo==DSA dsa_p:mpi dsa_q:mpi dsa_y:mpi

    pubkey_asf_elg      ::= &pubkey_algo==ELG_E elg_p:mpi elg_q:mpi

    # TODOX942


##### Elliptic-curve crypto

RFC 6637 s. 9:

    pubkey_asf_ecdsa    ::= &pubkey_algo==ECDSA
                            curveoid
                            ec_pubpoint:mpi
    pubkey_asf_ecdh     ::= &pubkey_algo==ECDH
                            curveoid
                            ec_pubpoint:mpi
                            0x03 0x01
                            ecdh_kdf_params
    pubkey_asf_ec       ::= pubkey_asf_ecdsa | pubkey_asf_ecdh

#### pubkey_asfs

    pubkey_asfs         ::= (  pubkey_asf_elg
                             | pubkey_asf_dsa
                             | pubkey_asf_rsa
                             | pubkey_asf_ec  )

### Public key version 3

RFC 4880 s. 5.5.2:

The key's expiration is embedded in the key packet for V3 keys:

    let \creation_plus_days = IF x0!=0 | x1!=0
                              THEN (Nat(x0)<<8 + Nat(x1))*(24*3600)
                              ELSE Inf
    pubkey_expiration_days ::= bytes bytes
                           >>= \pubkey_expiration_time =
                                  (creation_plus_days x0 x1)
                                  + pubkey_creation_time

The key format:

    pubkey_v3              ::= 0x03
                               pubkey_creation_time:timestamp
                               pubkey_expiration_days
                               pubkey_asf_rsa

### Public key version 4

RFC 4880 s. 5.5.2:

V4 keys are somewhat simpler:

    pubkey_v4              ::= 0x04
                               pubkey_creation_time:timestamp
                               pubkey_algo
                               pubkey_asfs

### Secret keys

RFC 4880 s. 5.5.3.

#### Secret key S2K

##### Secret key checksum conventions

    s2k_checksum   ::= &convention="cksum" cksum=two_octet
    s2k_hash       ::= &convention="mdc" sha1_hash
    s2k_sum        ::= s2k_checksum | s2k_hash | \epsilon

##### Secret key S2K conventions

    seckey_enc_iv  ::= bytes[blocksize(symm_algo)]
    s2k_convention_unencrypted ::= S2K_UNENCRYPTED=0
                               >>= \sumtype = ??
    s2k_convention_encrypted   ::= (254 | 255)
                                   symm_algo
                                   s2k_spec
                                   seckey_enc_iv?
                               >>= \sumtype = IF 254 THEN "mdc" ELSE "cksum",
                                   \enc = true
    s2k_convention_otherenc    ::= symm_algo seckey_enc_iv?
                               >>= \sumtype = "cksum",
                                   \enc = true,
                                   \hash_algo = MD5,
                                   \s2k_type = S2K_SIMPLE

##### s2k_convention

    s2k_convention ::= (   S2K_UNENCRYPTED
                        | s2k_convention_encrypted
                        | s2k_convention_otherenc )
                       s2k_sum

##### RFC 6637 S2K convention limitations

RFC 6637 s. 13, seems to be on the verge of requiring MDCs for EC private
keys. QQQQ: Some impls do; is this mandatory? QQQQ: Does the
hash-algorithm limitation apply for the RFCs?


#### Secret key algorithm-specific fields

    # RSA_ES, RSA_E, RSA_S
    seckey_asf_rsa ::= &(is_rsa pubkey_algo)
                       rsa_d:mpi
                       rsa_p:mpi
                       rsa_q:mpi
                       rsa_u:mpi
    # DSA
    seckey_asf_dsa ::= &pubkey_algo==DSA
                       dsa_x:mpi
    # ELG_E
    seckey_asf_elg ::= &pubkey_algo==ELG_E
                       elg_x:mpi
    # ECDH/ECDSA (RFC 6637 s. 9)
    seckey_asf_ec  ::= &(is_ec pubkey_algo)
                       ec_privat_scalar:mpi

#### Secret keys

TODO: parameterize length of enckey by enclosur and overhead

    seckey_enckey  ::= &enc bytes*
    seckey_asfs    ::= seckey_asf_rsa | seckey_asf_dsa | seckey_asf_elg
    seckey_unencrypted ::= seckey_asfs (s2k_cksum | s2k_hash)
    seckey         ::= s2k_convention  (seckey_enckey | seckey_unencrypted)


# Tag 8: Compressed data

    # RFC 4880 s. 5.6
    compressed_data ::= bytes[length-1]
    compressed_body ::= comp_algo compressed_data


# Tag 9: Symmetrically encrypted data packet

     # RFC 4880 s. 5.7
     sedp_body       ::= bytes[length]


# Tag 10: Marker

     # RFC 4880 s. 5.8
     marker_body     ::= "PGP"


# Tag 11: Literal

    # RFC 4880 s. 5.9
    LITERAL_LOCAL = 'l' | '1'
    # The compatibility predicate for 'local' format
    let \islocal x = x \in {'l', '1'}
    literal_format      ::= (  LITERAL_BINARY='b'
                             | LITERAL_TEXT='t'
                             | LITERAL_UTF8='u'
                             | literal_local )
    literal_filenamelen ::= len_old1
    literal_filename    ::= bytes[literal_filenamelen]
                        >>= \literal_datalen = length-literal_filenamelen-6
    literal_date        ::= timestamp
    literal_data        ::= (  &literal_format='b'       bytes[literal_datalen]
                             | &literal_format='t'       latin1_text[literal_datalen]
                             | &literal_format='u'       utf8_text[literal_datalen]
                             | &(islocal literal_format) local_text[literal_datalen])
    literal_body        ::= literal_format literal_filenamelen literal_filename
                            literal_date literal_data


# Tag 12: Trust

    # RFC 4880 s. 5.10
    trust_body          ::= bytes[length]


# Tag 13: User ID (tag 13)

    # RFC 4880 s. 5.11
    userid_body         ::= utf8_text[length]


# Tag 17: User attribute

    # RFC 4880 s. 5.12
    USERATTRIB_SUBPACKET_IMAGE = 1
    USERATTRIB_SUBPACKET_EXPERIMENTAL = 100..110
    USERATTRIB_SUBPACKET_IGNORED = 0 | 1..99 | 111..255

For image user attributes, the image header length is encoded as a
little-endian ulint16:

    image_header_len           ::= byte byte
                               >>= \x = x0 + x1<<8

The only format supported by the standard is JFIF:

    IMAGE_FORMAT_JPEG            = 1
    image_format               ::= IMAGE_FORMAT_JPEG | 100..110
    image_header               ::= 0x10 0x00 0x01 image_format
                                   0x00 0x00 0x00 0x00
                                   0x00 0x00 0x00 0x00
                                   0x00 0x00 0x00 0x00
    userattrib_subpacket_image ::= image_header bytes[subpacketlen-20]
    userattrib_subpacket_type  ::= (  userattrib_subpacket_image
                                    | USERATTRIB_SUBPACKET_EXPERIMENTAL
                                    | USERATTRIB_SUBPACKET_IGNORED)
    userattrib_subpacket       ::= newlen userattrib_subpacket_type bytes[newlen]
                               >>= \data = x2,
                                   \type = x1,
                                   \subpacketlen = x0
    userattrib_body            ::= userattrib_subpacket* nil


# Tag 18: Symmetrically encrypted integrity protected data

    # RFC 4880 s. 5.13
    seipd_encdata ::= bytes[length-1]
    seipd_body    ::= 1 seipd_encdata


# Tag 19: Modification detection code

    # RFC 4880 s. 5.14
    mdc           ::= sha1_hash
    mdc_body      ::= mdc


# ASCII armor and cleartext signatures

## ASCII Armor

RFC 4880 s. 6.

    ascii_armor   ::= armor_header_line
                      armor_header*
                      blank_line
                      armored_data
                      armor_checksum
                      armor_tail_line

## Types of ASCII armor

    ascii_message ::= (  "PGP MESSAGE"
                       | "PGP PUBLIC KEY BLOCK"
                       | "PGP PRIVATE KEY BLOCK"
                       | "PGP MESSAGE, PART X/Y"
                       | "PGP SIGNATURE")

TODO (additional semantic constraints) | "PGP MESSAGE, PART X"


## ASCII Armor common definitions

    blank_line        ::= whitespace* "\n"
    base64_line       ::= base64[76] "\n"
    last_base64       ::= base64[len] "="[padlen]
                          &((padlen<=3) && ((len+padlen)<=76))
    armored_data      ::= base64_line* last_base64 "\n"
    armor_checksum    ::= "=" base64[4] "\n"

## Header and tail lines

    armor_header_line ::= "-----BEGIN " ascii_message "-----" CRLF
                      >>= \message = ascii_message,
                          \armor_keys = nil,
                          \armor_values = nil
    armor_tail_line   ::= "-----END " \message "-----\n"
    armor_key_other   ::= latin1_text - {':'}
    armor_key         ::=   "Version"
                          | "Comment"
                          | "MessageID"
                          | "Hash"
                          | "Charset"
                          | armor_key_other
    armor_header      ::= armor_key ": " armor_value
                      >>= \armor_keys   = \armor_keys ++ [armor_key],
                          \armor_values = \armor_values ++ [armor_value]


## Cleartext signatures

RFC 4880 s. 7 defines a procedure for forming cleartext signatures.

It requires "dash-encoding" of the signed message, to avoid parsing
ambiguity.

    let \dash_escape' line   = IF (head line) == "-"
                               THEN "- " ++ (tail line)
                               ELSE line
    let \dash_escape lines   = (map \dash_escape) lines
    let \dash_unescape' line = IF (select line 0 3) == "- -"
                               THEN "-" ++ (tail tail tail line)
                               ELSE line
    let \dash_unescape lines = (map \dash_unescape) lines
    dash_escaped_text    ::= (dash_escape utf8_crlf_text*)        CRLF?
                         >>= \=x = (dash_unescape x0)

The cleartext signature format is then given by:

    cleartext_header     ::= "-----BEGIN PGP SIGNED MESSAGE-----" CRLF
    cleartext_sig        ::= ascii_armor &message=="PGP SIGNATURE"

    cleartext_signature  ::= cleartext_header
                             dash_escaped_text
                             cleartext_sig

# Packet composition

TODO

## Transferrable key packets

## Sign-then-encrypt

## Encrypt-then-sign

## Encrypt-only

## Sign-only
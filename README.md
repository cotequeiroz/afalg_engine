afalg_engine
============

This is an alternate AF_ALG engine for openssl versions 1.1.0 and up.

It was based on the devcrypto engine from OpenSSL 1.1.1, but using AF_ALG
instead of the /dev/crypto interface.

It is different than the AF_ALG engine that ships with OpenSSL:
 - it uses sync calls, instead of async
 - it supports more ciphers, and digests

This engine requires AF_ALG support from the kernel.  In order to decide if
an algorithm is using hardware acceleration or not, it needs the crypto-user
module as well.

There are some caveats when using this engine, which apply to the hardware
crypto engines that ship with OpenSSL as well:
 - engines that keep open kernel contexts (AF_ALG, and /dev/crypto sessions,
   for example) will not behave well across fork calls, since both processes
   will operate on the same open kernel context.
   This is especially important with digests, since many programs will open
   a digest context to perform HMAC, send the key, which will be the same
   across clients, then fork when a new connection is open--openssh does this,
   for example.  There are many other cases.   For this reason, digests are
   off by default.
 - In most cases, the performance when using small blocks is poor.  ECB-mode
   ciphers are rarely used for encryption, but they are employed for RNG, using
   a single block at a time, where the performance is poorest.  For this reason,
   ECB-mode ciphers are off by default.

Configuration
-------------

To use the engine by default, you must configure the engine in openssl.cnf.
See [openssl-config(5)](https://www.openssl.org/docs/man1.1.1/man5/config.html)
for details about openssl configuration.

You should include the following definition in the default section--the first
section before any other bracketed section header:

    openssl_conf=openssl_conf

This section, which contains the global openssl defaults, should include an
engines section for engine configuration:

    [openssl_conf]
    engines=engines

The engines section will have a list of engines to enable, pointing to that
engine's configuration section:

    [engines]
    afalg=afalg

Now, in the afalg section, we can configure the engine itself.  The
`default_algorithms` option is only used to enable the engine.  The selection
of ciphers and digests to enable is different:

    [afalg]
    # Leave this alone and configure algorithms with CIPERS/DIGESTS below
    default_algorithms=ALL

    # Configuration commands:
    # Run 'openssl engine -t -c -vv -pre DUMP_INFO afalg' to see a list of
    # supported algorithms, along with their driver, wether they are hw
    # accelerated or not, and the engine's configuration commands.

    # USE SOFTDRIVERS: specifies whether to use software (not accelerated)
    # drivers (0=use only accelerated drivers, 1=allow all drivers, 2=use
    # if acceleration can't be determined) [default=2]
    USE_SOFTDRIVERS=2

    # CIPHERS: either ALL, NONE, NO_ECB (all except ECB-mode) or a
    # comma-separated list of ciphers to enable [default=NO_ECB]
    CIPHERS=NO_ECB

    # DIGESTS: either ALL, NONE, or a comma-separated list of digests to
    # enable [default=NONE]
    #DIGESTS = NONE

To test the configuration, run the following command:

    openssl engine -t -c -v

It should display the engine as available, along with the list of algorithms
enabled and the configuration commands accepted by the engine:

    (dynamic) Dynamic engine loading support
         [ unavailable ]
         SO_PATH, NO_VCHECK, ID, LIST_ADD, DIR_LOAD, DIR_ADD, LOAD
    (afalg) AF_ALG engine
     [DES-CBC, DES-EDE3-CBC, AES-128-CBC, AES-192-CBC, AES-256-CBC]
         [ available ]
         USE_SOFTDRIVERS, CIPHERS, DIGESTS, DUMP_INFO


Obtaining Information about the Engine
--------------------------------------

You will need to have the `crypto_user` kernel module to see the driver and
acceleration information.

To see a list of algorithms supported by engine, and some diagnostic info,
such as the kernel driver being used and whether or not it is
hardware-accelerated or not, use the following openssl command:

    openssl engine -pre DUMP_INFO afalg

Here's a sample output:

    (afalg) AF_ALG engine
    Information about ciphers supported by the AF_ALG engine:
    Cipher DES-CBC, NID=31, AF_ALG info: name=cbc(des),  driver=mv-cbc-des (hw accelerated)
    Cipher DES-EDE3-CBC, NID=44, AF_ALG info: name=cbc(des3_ede),  driver=mv-cbc-des3-ede (hw accelerated)
    Cipher BF-CBC, NID=91, AF_ALG info: name=cbc(blowfish), AF_ALG socket bind failed.
    Cipher CAST5-CBC, NID=108, AF_ALG info: name=cbc(cast5), AF_ALG socket bind failed.
    Cipher AES-128-CBC, NID=419, AF_ALG info: name=cbc(aes),  driver=mv-cbc-aes (hw accelerated)
    Cipher AES-192-CBC, NID=423, AF_ALG info: name=cbc(aes),  driver=mv-cbc-aes (hw accelerated)
    Cipher AES-256-CBC, NID=427, AF_ALG info: name=cbc(aes),  driver=mv-cbc-aes (hw accelerated)
    Cipher AES-128-CTR, NID=904, AF_ALG info: name=ctr(ecb(aes)), AF_ALG socket bind failed.
    Cipher AES-192-CTR, NID=905, AF_ALG info: name=ctr(ecb(aes)), AF_ALG socket bind failed.
    Cipher AES-256-CTR, NID=906, AF_ALG info: name=ctr(ecb(aes)), AF_ALG socket bind failed.
    Cipher AES-128-ECB, NID=418, AF_ALG info: name=ecb(aes),  driver=mv-ecb-aes (hw accelerated)
    Cipher AES-192-ECB, NID=422, AF_ALG info: name=ecb(aes),  driver=mv-ecb-aes (hw accelerated)
    Cipher AES-256-ECB, NID=426, AF_ALG info: name=ecb(aes),  driver=mv-ecb-aes (hw accelerated)

    Information about digests supported by the AF_ALG engine:
    Digest MD5, NID=4, AF_ALG info: name=md5,  driver=mv-md5 (hw accelerated)
    Digest SHA1, NID=64, AF_ALG info: name=sha1,  driver=mv-sha1 (hw accelerated)
    Digest RIPEMD160, NID=117, AF_ALG info: name=rmd160, AF_ALG socket bind failed.
    Digest SHA224, NID=675, AF_ALG info: name=sha224,  driver=sha224-neon (software)
    Digest SHA256, NID=672, AF_ALG info: name=sha256,  driver=mv-sha256 (hw accelerated)
    Digest SHA384, NID=673, AF_ALG info: name=sha384,  driver=sha384-neon (software)
    Digest SHA512, NID=674, AF_ALG info: name=sha512,  driver=sha512-neon (software)

    [Success]: DUMP_INFO

Performance Measurement & Expectation
-------------------------------------

You can use `openssl speed` command to measure the crypto speed.  Make sure to
use the `-elapsed` option, so you don't count only user-time, which will give
you unrealistic high speeds.  Remember, with the AF_ALG engine, even sotware
drivers will spend CPU time in kernel-mode, not in user-mode, and thus will
not show up without the `-elapsed` flag.  Here's an example run:

    openssl speed -evp AES-256-CBC -elapsed -engine afalg
    OpenSSL 1.1.1d  10 Sep 2019
    The 'numbers' are in 1000s of bytes per second processed.
    type             16 bytes     64 bytes    256 bytes   1024 bytes   8192 bytes  16384 bytes
    aes-256-cbc       1136.69k     4420.03k    16057.86k    44762.11k    89817.09k    96234.15k

You don't need to specify `-engine afalg` if it is properly configured.  Here
is the same run without the engine:

    openssl speed -evp AES-256-CBC -elapsed
    OpenSSL 1.1.1d  10 Sep 2019
    The 'numbers' are in 1000s of bytes per second processed.
    type             16 bytes     64 bytes    256 bytes   1024 bytes   8192 bytes  16384 bytes
    aes-256-gcm      32369.07k    37509.76k    41272.06k    45794.99k    46907.39k    46912.85k

This is typical for hw-accelerated ciphers.  Notice the poor performance when
using small blocks, compared to larger ones.  For this reason, don't expect
a performance gain with TLS.  In fact, prefer to use the AEAD ciphersuites,
which are currently not supported by the engine, rather than lowering the
security and selecting CBC ciphers.  The blocks are all lower than 1500 bytes
because of the regular MTU.  If you're able to use jumbo frames, then you may
want to give it a try, but measure the speed first with something other than
just `openssl speed`.


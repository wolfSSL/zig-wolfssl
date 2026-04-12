# wolfssl-zig

Idiomatic Zig bindings for wolfSSL and wolfCrypt.

**License:** GPL-3.0 or commercial (wolfSSL Inc.)

Links against a system-installed wolfSSL library via `pkg-config` and provides a native Zig API for TLS, cryptography, X.509 certificates, key derivation, and secure random number generation.

## Features

**TLS** -- Client/server connections, context management, session resumption (TLS 1.2/1.3)

**Symmetric ciphers** -- AES-GCM (one-shot and streaming), AES-CBC, AES-CTR, ChaCha20-Poly1305

**Hashes and MACs** -- SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-384, SHA3-512, BLAKE2b-512, BLAKE2s-256, MD5, HMAC, AES-CMAC

**Asymmetric crypto** -- RSA (PKCS#1 v1.5, PSS, OAEP), ECC (ECDSA/ECDH P-256/P-384/P-521/SECP256K1), Ed25519, Ed448, Curve25519, X448, Diffie-Hellman (FFDHE-2048/3072/4096)

**X.509** -- Certificate parsing, chain verification, PEM/DER/file loading

**KDF** -- HKDF, PBKDF1, PBKDF2, scrypt

**RNG** -- Cryptographically secure random number generation

## Prerequisites

wolfSSL must be installed on the system and discoverable via `pkg-config`:

```bash
cd ~/wolfssl
./configure --enable-tls13 --enable-ecc --enable-ed25519 --enable-curve25519 \
            --enable-ed448 --enable-curve448 --enable-secp256k1 \
            --enable-aesgcm --enable-aesgcm-stream --enable-chacha \
            --enable-aescbc --enable-aesctr \
            --enable-sha512 --enable-sha224 --enable-sha3 --enable-blake2 \
            --enable-hkdf --enable-pwdbased --enable-scrypt \
            --enable-cmac --enable-rsapss --enable-keygen \
            --enable-certgen --enable-dh --enable-md5 \
            --enable-pss-salt-len-discover
make
sudo make install
sudo ldconfig
```

Verify the installation:

```bash
pkg-config --modversion wolfssl
```

The Zig wrapper does not compile wolfSSL from source. It links against the pre-installed system library. Available algorithms depend on the `./configure` flags used when building wolfSSL. The wrapper detects available features at comptime via `@hasDecl`.

## Minimum Zig Version

0.16.0-dev.2877+627f03af9

## Building

```bash
zig build
```

## Testing

```bash
zig build test
```

To run tests that need wolfSSL test certificates:

```bash
zig build test -Dwolfssl-src=/path/to/wolfssl
```

## Usage

```zig
const wolfssl = @import("wolfssl");

// Initialize the library
try wolfssl.init();
defer wolfssl.deinit();

// SHA-256 hash
var hasher = try wolfssl.crypto.hash.Hash(.sha256).init();
defer hasher.deinit();
try hasher.update("hello");
var digest: [wolfssl.crypto.hash.Hash(.sha256).digest_length]u8 = undefined;
try hasher.final(&digest);

// TLS 1.3 client context with system CA certificates
const config = wolfssl.tls.Config{
    .role = .client,
    .min_version = .tls_1_3,
    .max_version = .tls_1_3,
    .ca_certs = .system,
};
var ctx = try wolfssl.tls.Context.init(config);
defer ctx.deinit();
```

## Project Structure

```
src/
  root.zig        -- Public API entry point
  c.zig           -- @cImport of wolfSSL C headers
  tls/            -- TLS context, connection, session
  crypto/         -- Symmetric ciphers, hashes, MACs, asymmetric crypto
  x509/           -- Certificate parsing and verification
  kdf/            -- HKDF, PBKDF2
  random.zig      -- Secure RNG
build.zig         -- Build system (pkg-config discovery, test setup)
build.zig.zon     -- Package manifest (v0.2.0)
```

## Commercial Support and Licensing

wolfSSL Inc. provides commercial support, consulting, integration services, and NRE for wolfssl-zig and for the wolfSSL ecosystem (wolfCrypt, wolfHSM, wolfProvider) that underlies it. Commercial licenses for wolfSSL are also available for deployments where the GPL-3.0 copyleft terms are not acceptable.

| Need | Contact |
|------|---------|
| General questions, porting, FIPS | facts@wolfssl.com |
| Commercial licensing | licensing@wolfssl.com |
| Technical support | support@wolfssl.com |
| Phone | +1 (425) 245-8247 |
| Web | https://www.wolfssl.com/contact/ |

## License

wolfssl-zig is copyright (C) 2026 wolfSSL Inc. and is licensed under the GNU General Public License v3.0 (GPL-3.0). See
[https://www.gnu.org/licenses/gpl-3.0.html](https://www.gnu.org/licenses/gpl-3.0.html).

**Commercial** -- if the GPL-3.0 copyleft terms are not acceptable for your
deployment (proprietary product, closed-source distribution, OEM embedding),
wolfSSL Inc. sells commercial licenses that remove the copyleft obligation.
Contact [licensing@wolfssl.com](mailto:licensing@wolfssl.com) or
+1 (425) 245-8247.

**wolfSSL / wolfCrypt** (required dependency): the same dual-license applies --
GPL-3.0 for open-source use, or a commercial license from wolfSSL Inc. for
proprietary deployments. Distributing a product that links wolfssl-zig against
wolfSSL under GPL-3.0 subjects the combined work to GPL-3.0 copyleft.

**FIPS 140-3**: wolfCrypt holds a current FIPS 140-3 certificate (#4718).
FIPS-ready deployments require the separately licensed wolfCrypt FIPS boundary
build; the standard open-source wolfSSL build is not a validated module.

# wolfssl-zig

Idiomatic Zig bindings for wolfSSL and wolfCrypt.

Links against a system-installed wolfSSL library via `pkg-config` and provides a native Zig API for TLS, cryptography, X.509 certificates, key derivation, and secure random number generation.

## Features

**TLS** -- Client/server connections, context management, session resumption (TLS 1.2/1.3)

**Symmetric ciphers** -- AES-GCM, ChaCha20-Poly1305

**Hashes and MACs** -- SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-384, SHA3-512, MD5, HMAC

**Asymmetric crypto** -- RSA, ECC (ECDSA/ECDH), Ed25519, Ed448, Curve25519, Diffie-Hellman

**X.509** -- Certificate parsing, chain verification, PEM encoding

**KDF** -- HKDF, PBKDF2

**RNG** -- Cryptographically secure random number generation

## Prerequisites

wolfSSL must be installed on the system and discoverable via `pkg-config`:

```bash
cd ~/wolfssl
./configure --enable-tls13 --enable-ecc --enable-ed25519 --enable-curve25519 \
            --enable-aesgcm --enable-chacha --enable-sha512 --enable-hkdf \
            --enable-certgen --enable-keygen --enable-ed448 --enable-dh \
            --enable-sha3 --enable-pwdbased --enable-md5
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
zig build test -Dwolfssl-certs-dir=/path/to/wolfssl/certs/
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
build.zig.zon     -- Package manifest (v0.1.0)
```

## License

This project is licensed under the GNU General Public License v2.0. See [LICENSE](LICENSE) for details.

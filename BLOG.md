# Idiomatic Zig Bindings for wolfSSL

wolfSSL now has a community-maintained Zig binding — `zig-wolfssl` — that wraps wolfSSL and wolfCrypt behind a native Zig API. If you are building a Zig application that needs TLS, X.509, or wolfCrypt algorithms, this binding gives you type-safe access without dropping to raw C.

## What's Covered

The binding exposes five modules:

- **tls** — TLS 1.2/1.3 and DTLS, client and server, with SNI, ALPN, session resumption, and certificate chain verification
- **crypto** — AES-GCM/CBC/CTR, ChaCha20-Poly1305, RSA, ECC (P-256/384/521, SECP256K1), Ed25519/Ed448, Curve25519/X448, FFDHE, SHA-1/2/3, BLAKE2, HMAC, AES-CMAC
- **x509** — certificate parsing and chain verification, PEM/DER, certificate manager
- **kdf** — HKDF, PBKDF1, PBKDF2, scrypt
- **random** — CSPRNG

## Zig-Native Design

The binding is more than a thin `@cImport` wrapper. A few design choices worth noting:

**Single C import point.** All wolfSSL C types flow through one `src/c.zig` module. This prevents the type-identity problems that arise when multiple `@cImport` blocks produce incompatible struct definitions for the same underlying C type.

**Comptime feature detection.** The binding uses `@hasDecl()` at compile time to probe which algorithms your wolfSSL build was configured with. Code that calls a disabled algorithm fails at compile time, not at runtime.

**Zig allocator bridge.** You can hook wolfCrypt's internal malloc/realloc/free into any Zig allocator — including the provided `SecureAllocator`, which zeroes memory before freeing. Useful for key material.

**Errors are error sets.** wolfSSL's numeric error codes are mapped to named Zig error values (`TlsError`, `CryptoError`) so you get exhaustive switch coverage and readable stack traces.

## FIPS

The binding links against your installed wolfSSL library and inherits whatever that build provides. If you are running against a FIPS-validated wolfSSL build, the algorithms route through the validated boundary as they normally would. The binding does not interpose on that path.

## FFI Escape Hatch

Not everything is wrapped yet. The binding exposes `pub const ffi` for direct access to the underlying C API. DTLS server, post-quantum KEMs, PKCS#12, certificate generation, and hardware backends are noted as current gaps. The `ffi` surface is explicitly not stable across wolfSSL versions.

## Getting Started

```
zig build test -Dwolfssl-src=/path/to/wolfssl
```

The build locates wolfSSL via the `-Dwolfssl-src` option, `WOLFSSL_SRC` environment variable, or pkg-config. The library is licensed under GPL-3.0 with commercial licensing available from wolfSSL.

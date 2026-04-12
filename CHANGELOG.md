# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Pre-1.0 releases may contain breaking changes in any MINOR version bump.

---

## [0.2.0] - 2026-04-12

### Breaking Changes

- **All `verify()` functions now return `!void` instead of `!bool`.**
  Authentication failure is now `error.AuthenticationFailed`; callers no longer
  receive a boolean.

  Before:
  ```zig
  const ok = try key.verify(hash, sig);
  if (!ok) return error.BadSignature;
  ```
  After:
  ```zig
  try key.verify(hash, sig); // raises error.AuthenticationFailed on mismatch
  ```
  Affected: `EccPublicKey.verify`, `EccKeyPair.verify`, `Ed25519.PublicKey.verify`,
  `Ed448.PublicKey.verify`, `RsaPublicKey.verify`, `RsaPublicKey.verifyPss`,
  `AesCmac.verify`.

- **`signPss`, `verifyPss`, `encryptOaep`, `decryptOaep`: replaced separate
  `hash_type`/`mgf` parameters with a `PaddingHash` enum.**
  This prevents silent hash/MGF mismatches (e.g. SHA-256 hash with SHA-384 MGF).

  Before:
  ```zig
  try key.verifyPss(hash, sig, c.WC_HASH_TYPE_SHA256, c.WC_MGF1SHA256, 32);
  ```
  After:
  ```zig
  try key.verifyPss(hash, sig, .sha256, 32);
  ```

- **`signPss` and `verifyPss`: `salt_len` changed from `c_int` to `?u32`.**
  Pass `null` for hash-length salt (recommended); explicit byte counts are
  non-negative integers.  The old sentinel `c.RSA_PSS_SALT_LEN_DEFAULT` (-1)
  is replaced by `null`.

- **`Certificate.certVersion()` now returns `?u8` instead of `u8`.**
  Returns `null` if the version field is unavailable or outside the expected
  range.  Callers must unwrap the optional.

- **`Certificate.notBefore()`, `Certificate.notAfter()`,
  `Connection.cipherSuite()`, `Connection.version()` now return `?[]const u8`
  instead of `?[*:0]const u8`.**
  The length is now computed by the library; callers no longer need to call
  `std.mem.sliceTo`.

- **`Name.oneLine()` now requires a caller-provided buffer.**

  Before:
  ```zig
  const s = name.oneLine() orelse return error.Unavailable;
  ```
  After:
  ```zig
  var buf: [256]u8 = undefined;
  const s = name.oneLine(&buf) orelse return error.Unavailable;
  ```
  The previous zero-argument form heap-allocated via wolfSSL's `XMALLOC` and
  leaked the result on every call.

- **`AesGcmDecryptor.final()` now requires a `plaintext []u8` argument.**
  On authentication failure the library zeroes the caller's plaintext buffer
  before returning, preventing accidental use of unauthenticated data.

  Before:
  ```zig
  try dec.final(&tag);
  ```
  After:
  ```zig
  try dec.final(&plaintext_buf, &tag); // zeroed on error.AesGcmAuth
  ```

- **The raw wolfSSL C namespace moved from `wolfssl.c` to `wolfssl.ffi`.**
  The old name made it look like a first-class part of the API.  The new name
  signals that it is an escape hatch for wolfSSL features not yet covered by
  the Zig wrappers (DTLS, post-quantum, PKCS#12, certificate generation, etc.).
  `wolfssl.ffi` is not subject to semver guarantees — wolfSSL C API changes
  will not be treated as breaking changes to this library.

### Known Limitations

- **`hash.wcType()` is technically visible as `wolfssl.crypto.hash.wcType()`**
  and returns a `c_int` (a wolfSSL hash-type constant).  It cannot be made
  file-private because Zig has no package-private scope — it must be `pub` so
  that `hmac`, `hkdf`, `pbkdf1`, and `pbkdf2` can call it across file
  boundaries.

- **`errors.mapTlsError`, `errors.mapCryptoError`, `errors.isBadSignatureError`,
  and `errors.checkCrypto` are `pub`** for the same reason: they are called
  from many modules across the library.  These functions map raw wolfSSL C
  error codes and are not intended for external use.

### Added

- `PaddingHash` enum for RSA-PSS and RSA-OAEP hash selection
- `error.AuthenticationFailed` in `CryptoError` for signature and MAC failures
- `RsaPublicKey.verifyPssDiscover()`: PSS verify with auto-detected salt length
  (requires wolfSSL built with `WOLFSSL_PSS_SALT_LEN_DISCOVER`; needed for
  cross-implementation verification against OpenSSL's default max-salt PSS)
- BLAKE2b-512 and BLAKE2s-256 (incremental and one-shot)
- Streaming AES-GCM (`AesGcm.Encryptor` / `AesGcm.Decryptor`)
- AES-CMAC (`AesCmac.generate` / `AesCmac.verify`)
- PBKDF1
- scrypt
- SHA-1
- AES-128/256-CBC and AES-128/256-CTR
- X448 / Ed448
- SECP256K1
- Additional FFDHE groups and KDF variants
- SHA-224 and HMAC-SHA-224
- Private key DER export for all asymmetric key types (`exportDer`)
- wolfSSL source tree resolution via `-Dwolfssl-src=`, `WOLFSSL_SRC` env var,
  or pkg-config heuristic; certs directory resolved from source tree
- 54 additional wolfCrypt error code mappings

### Fixed

- **`Name.oneLine()` leaked one heap allocation per call** (wolfSSL
  `X509_NAME_oneline(name, NULL, 0)` calls `XMALLOC`; the old wrapper never
  freed the result)
- **`certVersion()` could panic in safe builds** on adversarially-crafted
  certificates with an out-of-range version field; now uses a safe cast
- **`verifyPss` leaked `PSS_SALTLEN_E` and `BAD_PADDING_E` as operational errors.**
  Both error codes originate in `RsaUnPad_PSS` and are structural signature
  failures; they now map to `error.AuthenticationFailed`.
- **`isBadSignatureError()` incorrectly classified `BAD_FUNC_ARG`** as an
  authentication failure; programming errors (wrong sizes, null pointers) now
  propagate as `error.BadFuncArg`
- X25519 shared-secret endianness bug
- P-521 and P-384 known-answer test vectors
- Various API boundary hardening (input validation before C FFI calls)

---

## [0.1.0] - 2026-03-22

Initial release.

### Added

- TLS 1.2 and 1.3 client and server (`Connection`, `Context`)
- AES-GCM and ChaCha20-Poly1305 symmetric ciphers
- SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-384, SHA3-512, MD5 hash functions
- HMAC (SHA-1, SHA-256, SHA-384, SHA-512, MD5)
- RSA key generation, PKCS#1 v1.5 sign/verify, PSS sign/verify, OAEP
  encrypt/decrypt
- ECC key generation, ECDSA sign/verify, ECDH (P-256, P-384, P-521)
- Ed25519 and Ed448 sign/verify
- X25519 and Curve448 key exchange
- Finite-field Diffie-Hellman (FFDHE-2048, FFDHE-3072, FFDHE-4096)
- X.509 certificate parsing from PEM, DER, and file (`Certificate`)
- X.509 distinguished name access (`Name`)
- HKDF and PBKDF2 key derivation
- `SecureAllocator` with volatile zeroing on free/shrink
- Single `@cImport` in `c.zig` to avoid type-incompatibility across modules
- Comptime-generic `Hash`, `Hmac`, `Hkdf`, `Pbkdf2`, `EccKeyPair` for
  zero-cost algorithm dispatch

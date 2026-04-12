//! wolfssl-zig: Idiomatic Zig bindings for wolfSSL / wolfCrypt.
//!
//! Provides:
//!  - `tls`: TLS client/server connections (Context, Connection, Session)
//!  - `crypto`: Symmetric ciphers, hashes, MACs, asymmetric crypto
//!  - `x509`: Certificate parsing, chain verification, PEM encoding
//!  - `kdf`: Key derivation functions (HKDF, PBKDF2)
//!  - `random`: Cryptographically secure RNG
//!
//! Usage:
//! ```zig
//! const wolfssl = @import("wolfssl");
//! try wolfssl.init();
//! defer wolfssl.deinit();
//! ```

const std = @import("std");
const c = @import("c.zig").c;
pub const errors = @import("errors.zig");
pub const alloc = @import("allocator.zig");

// -- TLS --
pub const tls = struct {
    pub const Config = @import("tls/Config.zig").Config;
    pub const Context = @import("tls/Context.zig").Context;
    pub const Connection = @import("tls/Connection.zig").Connection;
    pub const Session = @import("tls/Session.zig").Session;
};

// -- Crypto --
pub const crypto = struct {
    pub const aes = @import("crypto/aes.zig");
    pub const chacha = @import("crypto/chacha.zig");
    pub const rsa = @import("crypto/rsa.zig");
    pub const ecc = @import("crypto/ecc.zig");
    pub const ed25519 = @import("crypto/ed25519.zig");
    pub const ed448 = @import("crypto/ed448.zig");
    pub const curve25519 = @import("crypto/curve25519.zig");
    pub const x448 = @import("crypto/x448.zig");
    pub const dh = @import("crypto/dh.zig");
    pub const hmac = @import("crypto/hmac.zig");
    pub const cmac = @import("crypto/cmac.zig");
    pub const hash = @import("crypto/hash.zig");
};

// -- X.509 --
pub const x509 = struct {
    pub const Certificate = @import("x509/Certificate.zig").Certificate;
    pub const CertManager = @import("x509/CertManager.zig").CertManager;
    pub const Name = @import("x509/Name.zig").Name;
    pub const Pem = @import("x509/Pem.zig").Pem;
};

// -- KDF --
pub const kdf = struct {
    pub const hkdf = @import("kdf/hkdf.zig");
    pub const pbkdf1 = @import("kdf/pbkdf1.zig");
    pub const pbkdf2 = @import("kdf/pbkdf2.zig");
    pub const scrypt = @import("kdf/scrypt.zig");
};

// -- Random --
pub const random = @import("random.zig");

/// Initialize the wolfSSL library. Must be called once before any other operation.
/// Optionally pass a Zig allocator to bridge into wolfSSL's internal allocations.
pub fn init() !void {
    const ret = c.wolfSSL_Init();
    if (ret != c.WOLFSSL_SUCCESS) return error.InitFailed;
    alloc.markInitialized();
}

/// Initialize with a custom Zig allocator bridged into wolfSSL.
///
/// Note: Some opaque wolfCrypt types — hash states, HMAC, DH, Ed448, and Curve448 — are
/// allocated via libc `malloc` rather than through this allocator bridge. This is
/// because wolfCrypt does not provide `wc_*_new` / `wc_*_delete` functions for
/// those types, so the Zig bindings fall back to `@cImport`-provided `malloc`/`free`.
pub fn initWithAllocator(ally: std.mem.Allocator) !void {
    alloc.setAllocator(ally);
    try init();
}

/// Cleanup the wolfSSL library. Call on shutdown.
pub fn deinit() void {
    _ = c.wolfSSL_Cleanup();
}

// -- FFI escape hatch --
//
// Direct access to the raw wolfSSL/wolfCrypt C API.
// Use this only when the Zig wrappers above do not cover your use case
// (e.g. DTLS, post-quantum, PKCS#12, certificate generation, hardware backends).
//
// This namespace is NOT part of the stable API. wolfSSL may rename, remove,
// or change the signatures of C functions across releases, and those changes
// will not be reflected in this library's semver version.
pub const ffi = @import("c.zig").c;

// -- Pull in all tests from submodules --
test {
    _ = random;
    _ = crypto.hash;
    _ = crypto.hmac;
    _ = crypto.cmac;
    _ = crypto.aes;
    _ = crypto.chacha;
    _ = crypto.rsa;
    _ = crypto.ecc;
    _ = crypto.ed25519;
    _ = crypto.ed448;
    _ = crypto.curve25519;
    _ = crypto.x448;
    _ = crypto.dh;
    _ = kdf.hkdf;
    _ = kdf.pbkdf1;
    _ = kdf.pbkdf2;
    _ = kdf.scrypt;
    _ = @import("tests.zig");
}

test "wolfSSL init/deinit" {
    try init();
    defer deinit();
}

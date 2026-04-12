const std = @import("std");
const c = @import("../c.zig").c;
const errors = @import("../errors.zig");
const random = @import("../random.zig");

pub const Curve = enum {
    secp256k1,
    secp256r1,
    secp384r1,
    secp521r1,
};

fn curveId(comptime curve: Curve) c_int {
    return switch (curve) {
        .secp256k1 => c.ECC_SECP256K1,
        .secp256r1 => c.ECC_SECP256R1,
        .secp384r1 => c.ECC_SECP384R1,
        .secp521r1 => c.ECC_SECP521R1,
    };
}

fn keySize(comptime curve: Curve) usize {
    return switch (curve) {
        .secp256k1 => 32,
        .secp256r1 => 32,
        .secp384r1 => 48,
        .secp521r1 => 66,
    };
}

/// Maximum DER-encoded ECDSA signature length for a given curve.
pub fn maxSigLen(comptime curve: Curve) usize {
    // ECDSA DER signature: 2 * key_size + overhead (up to ~8 bytes)
    return keySize(curve) * 2 + 16;
}

/// Comptime-generic ECC public key for signature verification and ECDH.
pub fn EccPublicKey(comptime curve: Curve) type {
    return struct {
        key: *c.ecc_key,
        owned: bool,

        const Self = @This();
        /// Size of an X9.63 uncompressed public key: 0x04 || x || y
        pub const uncompressed_size = 1 + keySize(curve) * 2;

        /// Import from an X9.63 uncompressed public key (0x04 || x || y).
        /// Validates that the key belongs to the expected curve.
        pub fn fromBytes(bytes: *const [uncompressed_size]u8) !Self {
            const key = c.wc_ecc_key_new(null) orelse return error.OutOfMemory;
            errdefer c.wc_ecc_key_free(key);
            const ret = c.wc_ecc_import_x963_ex(bytes, @intCast(bytes.len), key, curveId(curve));
            if (ret != 0) return errors.mapCryptoError(ret);
            return .{ .key = key, .owned = true };
        }

        pub fn deinit(self: *Self) void {
            if (self.owned) c.wc_ecc_key_free(self.key);
        }

        /// ECDSA verify a DER-encoded signature against a message hash.
        /// Returns error.AuthenticationFailed if the signature does not match.
        pub fn verify(self: Self, msg_hash: []const u8, sig: []const u8) !void {
            var stat: c_int = 0;
            const ret = c.wc_ecc_verify_hash(
                sig.ptr,
                @intCast(sig.len),
                msg_hash.ptr,
                @intCast(msg_hash.len),
                &stat,
                self.key,
            );
            if (ret != 0) return errors.mapCryptoError(ret);
            if (stat != 1) return error.AuthenticationFailed;
        }
    };
}

/// Comptime-generic ECC key pair for signing and ECDH.
pub fn EccKeyPair(comptime curve: Curve) type {
    return struct {
        key: *c.ecc_key,

        const Self = @This();
        pub const key_size = keySize(curve);
        pub const PublicKey = EccPublicKey(curve);

        /// Generate a new ECC key pair on the specified curve.
        pub fn generate(rng: *random.SecureRng) !Self {
            const key = c.wc_ecc_key_new(null) orelse return error.OutOfMemory;
            errdefer c.wc_ecc_key_free(key);

            const ret = c.wc_ecc_make_key_ex(rng.rng, @intCast(key_size), key, curveId(curve));
            if (ret != 0) return errors.mapCryptoError(ret);
            return .{ .key = key };
        }

        pub fn deinit(self: *Self) void {
            // wc_ecc_key_free handles secure zeroing of private key material internally.
            c.wc_ecc_key_free(self.key);
        }

        /// Return a borrowed view of this key pair's public key.
        /// Do NOT call deinit() on the returned PublicKey.
        pub fn publicKey(self: *Self) PublicKey {
            return .{ .key = self.key, .owned = false };
        }

        /// Export the public key as X9.63 uncompressed bytes (0x04 || x || y).
        pub fn publicKeyBytes(self: *Self) ![PublicKey.uncompressed_size]u8 {
            var out: [PublicKey.uncompressed_size]u8 = undefined;
            var out_len: c.word32 = PublicKey.uncompressed_size;
            const ret = c.wc_ecc_export_x963(self.key, &out, &out_len);
            if (ret != 0) return errors.mapCryptoError(ret);
            return out;
        }

        /// ECDSA sign a hash. Returns the DER-encoded signature as a slice of `sig_buf`.
        pub fn sign(self: *Self, msg_hash: []const u8, sig_buf: []u8, rng: *random.SecureRng) ![]u8 {
            var sig_len: c.word32 = @intCast(sig_buf.len);
            const ret = c.wc_ecc_sign_hash(
                msg_hash.ptr,
                @intCast(msg_hash.len),
                sig_buf.ptr,
                &sig_len,
                rng.rng,
                self.key,
            );
            if (ret != 0) return errors.mapCryptoError(ret);
            return sig_buf[0..sig_len];
        }

        /// ECDSA verify a signature against a hash.
        /// Returns error.AuthenticationFailed if the signature does not match.
        pub fn verify(self: *Self, msg_hash: []const u8, sig: []const u8) !void {
            return self.publicKey().verify(msg_hash, sig);
        }

        /// Export the private key as raw big-endian bytes (the scalar d, key_size bytes).
        ///
        /// CALLER RESPONSIBILITY: The returned array contains sensitive key material.
        /// Zero it after use:
        ///   var priv = try kp.exportPrivateRaw();
        ///   defer std.crypto.secureZero(u8, @as([]volatile u8, @volatileCast(&priv)));
        pub fn exportPrivateRaw(self: *Self) ![key_size]u8 {
            var out: [key_size]u8 = undefined;
            // Zero the scratch buffer on any error path: wc_ecc_export_private_only
            // does not clear its output on failure (verified in wolfcrypt/src/ecc.c).
            errdefer std.crypto.secureZero(u8, @as([]volatile u8, @volatileCast(&out)));
            var out_len: c.word32 = key_size;
            const ret = c.wc_ecc_export_private_only(self.key, &out, &out_len);
            if (ret != 0) return errors.mapCryptoError(ret);
            return out;
        }

        /// ECDH: compute shared secret with a peer's public key.
        /// Returns both the buffer and the actual length, as leading zero bytes
        /// may be stripped by wolfCrypt, making len < key_size possible.
        ///
        /// NOTE: secp256k1 (K256) ECDH is not supported in this wolfSSL build.
        /// Calling K256.sharedSecret() produces a compile error. Use P-256,
        /// P-384, or P-521 for ECDH.
        ///
        /// CALLER RESPONSIBILITY: The returned struct contains sensitive key material in `secret`.
        /// Zero it after use:
        ///   var result = try kp.sharedSecret(peer_pub);
        ///   defer std.crypto.secureZero(u8, @as([]volatile u8, @volatileCast(&result.secret)));
        pub fn sharedSecret(self: *Self, peer_pub: PublicKey) !struct { secret: [key_size]u8, len: usize } {
            if (comptime curve == .secp256k1) @compileError("secp256k1 ECDH is not supported in this wolfSSL build (HAVE_ECC_KOBLITZ + FP_ECC conflict; no SP_ECC path for secp256k1). Use P-256, P-384, or P-521 for ECDH.");
            var out: [key_size]u8 = undefined;
            // Zero the scratch buffer on any error path: wc_ecc_shared_secret only
            // zeroes its output on the SUCCESS path (ecc.c:4993); error paths leave
            // whatever partial computation was written. The internal intermediate point
            // (result->x/y) IS cleared via mp_forcezero (ecc.c:4999-5001), but the
            // caller-visible output buffer is not. Clear it before propagating the error.
            errdefer std.crypto.secureZero(u8, @as([]volatile u8, @volatileCast(&out)));
            var out_len: c.word32 = key_size;
            const ret = c.wc_ecc_shared_secret(self.key, peer_pub.key, &out, &out_len);
            if (ret != 0) return errors.mapCryptoError(ret);
            return .{ .secret = out, .len = out_len };
        }
    };
}

pub const K256 = EccKeyPair(.secp256k1);
pub const P256 = EccKeyPair(.secp256r1);
pub const P384 = EccKeyPair(.secp384r1);
pub const P521 = EccKeyPair(.secp521r1);
pub const K256PublicKey = EccPublicKey(.secp256k1);
pub const P256PublicKey = EccPublicKey(.secp256r1);
pub const P384PublicKey = EccPublicKey(.secp384r1);
pub const P521PublicKey = EccPublicKey(.secp521r1);

// RFC 6979 §A.2.5 ECDSA P-256/SHA-256 known-answer verification test.
// Exercises EccPublicKey.fromBytes — imports the uncompressed X9.63 public key
// and verifies the RFC 6979 signature, confirming the import and verify paths.
// The private key, public key, message hash (SHA-256 of "sample"), and
// DER-encoded signature (r, s) are all from RFC 6979 Appendix A.2.5.
// Signature verification was independently confirmed with Python pyca/cryptography.
test "ECC P-256 RFC 6979 §A.2.5 KAT (verify)" {
    // Uncompressed X9.63 public key: 0x04 || Qx || Qy (65 bytes)
    const pub_uncompressed = [P256PublicKey.uncompressed_size]u8{
        0x04,
        0x60, 0xfe, 0xd4, 0xba, 0x25, 0x5a, 0x9d, 0x31,
        0xc9, 0x61, 0xeb, 0x74, 0xc6, 0x35, 0x6d, 0x68,
        0xc0, 0x49, 0xb8, 0x92, 0x3b, 0x61, 0xfa, 0x6c,
        0xe6, 0x69, 0x62, 0x2e, 0x60, 0xf2, 0x9f, 0xb6,
        0x79, 0x03, 0xfe, 0x10, 0x08, 0xb8, 0xbc, 0x99,
        0xa4, 0x1a, 0xe9, 0xe9, 0x56, 0x28, 0xbc, 0x64,
        0xf2, 0xf1, 0xb2, 0x0c, 0x2d, 0x7e, 0x9f, 0x51,
        0x77, 0xa3, 0xc2, 0x94, 0xd4, 0x46, 0x22, 0x99,
    };
    // SHA-256("sample") per RFC 6979 §A.2.5
    const msg_hash = [32]u8{
        0xaf, 0x2b, 0xdb, 0xe1, 0xaa, 0x9b, 0x6e, 0xc1,
        0xe2, 0xad, 0xe1, 0xd6, 0x94, 0xf4, 0x1f, 0xc7,
        0x1a, 0x83, 0x1d, 0x02, 0x68, 0xe9, 0x89, 0x15,
        0x62, 0x11, 0x3d, 0x8a, 0x62, 0xad, 0xd1, 0xbf,
    };
    // DER-encoded ECDSA signature (r, s) from RFC 6979 §A.2.5 (72 bytes)
    const sig_der = [72]u8{
        0x30, 0x46,
        0x02, 0x21, 0x00,
        0xef, 0xd4, 0x8b, 0x2a, 0xac, 0xb6, 0xa8, 0xfd,
        0x11, 0x40, 0xdd, 0x9c, 0xd4, 0x5e, 0x81, 0xd6,
        0x9d, 0x2c, 0x87, 0x7b, 0x56, 0xaa, 0xf9, 0x91,
        0xc3, 0x4d, 0x0e, 0xa8, 0x4e, 0xaf, 0x37, 0x16,
        0x02, 0x21, 0x00,
        0xf7, 0xcb, 0x1c, 0x94, 0x2d, 0x65, 0x7c, 0x41,
        0xd4, 0x36, 0xc7, 0xa1, 0xb6, 0xe2, 0x9f, 0x65,
        0xf3, 0xe9, 0x00, 0xdb, 0xb9, 0xaf, 0xf4, 0x06,
        0x4d, 0xc4, 0xab, 0x2f, 0x84, 0x3a, 0xcd, 0xa8,
    };

    var pub_key = try P256PublicKey.fromBytes(&pub_uncompressed);
    defer pub_key.deinit();

    try pub_key.verify(&msg_hash, &sig_der);

    // Tampered hash must not verify
    var bad_hash = msg_hash;
    bad_hash[0] ^= 0xff;
    try std.testing.expectError(error.AuthenticationFailed, pub_key.verify(&bad_hash, &sig_der));
}

test "ECC P-256 sign/verify" {
    var rng = try random.SecureRng.init();
    defer rng.deinit();

    var kp = try P256.generate(&rng);
    defer kp.deinit();

    const msg_hash = [_]u8{0xde} ** 32;
    var sig_buf: [maxSigLen(.secp256r1)]u8 = undefined;
    const sig = try kp.sign(&msg_hash, &sig_buf, &rng);

    try kp.verify(&msg_hash, sig);

    // Tampered hash should fail
    var bad = msg_hash;
    bad[0] ^= 0xff;
    try std.testing.expectError(error.AuthenticationFailed, kp.verify(&bad, sig));
}

test "ECDH P-256 shared secret" {
    var rng = try random.SecureRng.init();
    defer rng.deinit();

    var alice = try P256.generate(&rng);
    defer alice.deinit();
    var bob = try P256.generate(&rng);
    defer bob.deinit();

    const secret_a = try alice.sharedSecret(bob.publicKey());
    const secret_b = try bob.sharedSecret(alice.publicKey());

    try std.testing.expectEqualSlices(u8, secret_a.secret[0..secret_a.len], secret_b.secret[0..secret_b.len]);
}

// ECDH interop test: exercises the publicKeyBytes → EccPublicKey.fromBytes → sharedSecret path.
// Exports Bob's public key, imports it fresh via fromBytes, and verifies that ECDH with the
// imported key produces the same shared secret as ECDH with the borrowed key.
test "ECDH P-256 imported public key round-trip" {
    var rng = try random.SecureRng.init();
    defer rng.deinit();

    var alice = try P256.generate(&rng);
    defer alice.deinit();
    var bob = try P256.generate(&rng);
    defer bob.deinit();

    // Compute ECDH using borrowed public key (baseline)
    const secret_borrowed = try alice.sharedSecret(bob.publicKey());

    // Export Bob's public key bytes, then import them fresh
    const bob_pub_bytes = try bob.publicKeyBytes();
    var bob_imported = try P256PublicKey.fromBytes(&bob_pub_bytes);
    defer bob_imported.deinit();

    // Compute ECDH using the imported public key
    const secret_imported = try alice.sharedSecret(bob_imported);

    try std.testing.expectEqualSlices(
        u8,
        secret_borrowed.secret[0..secret_borrowed.len],
        secret_imported.secret[0..secret_imported.len],
    );
}

// ECC P-256 private key export KAT.
// Uses RFC 6979 §A.2.5 private key (scalar d). Imports via wc_ecc_import_private_key_ex,
// exports via exportPrivateRaw, and confirms the bytes match the RFC vector.
// Independent oracle: RFC 6979 Appendix A.2.5.
test "ECC P-256 exportPrivateRaw KAT" {
    // Private scalar d from RFC 6979 §A.2.5 (big-endian, 32 bytes)
    const priv_d = [P256.key_size]u8{
        0xc9, 0xaf, 0xa9, 0xd8, 0x45, 0xba, 0x75, 0x16,
        0x6b, 0x5c, 0x21, 0x57, 0x67, 0xb1, 0xd6, 0x93,
        0x4e, 0x50, 0xc3, 0xdb, 0x36, 0xe8, 0x9b, 0x12,
        0x7b, 0x8a, 0x62, 0x2b, 0x12, 0x0f, 0x67, 0x21,
    };
    // Uncompressed public key from RFC 6979 §A.2.5 (0x04 || Qx || Qy, 65 bytes)
    const pub_uncompressed = [P256PublicKey.uncompressed_size]u8{
        0x04,
        0x60, 0xfe, 0xd4, 0xba, 0x25, 0x5a, 0x9d, 0x31,
        0xc9, 0x61, 0xeb, 0x74, 0xc6, 0x35, 0x6d, 0x68,
        0xc0, 0x49, 0xb8, 0x92, 0x3b, 0x61, 0xfa, 0x6c,
        0xe6, 0x69, 0x62, 0x2e, 0x60, 0xf2, 0x9f, 0xb6,
        0x79, 0x03, 0xfe, 0x10, 0x08, 0xb8, 0xbc, 0x99,
        0xa4, 0x1a, 0xe9, 0xe9, 0x56, 0x28, 0xbc, 0x64,
        0xf2, 0xf1, 0xb2, 0x0c, 0x2d, 0x7e, 0x9f, 0x51,
        0x77, 0xa3, 0xc2, 0x94, 0xd4, 0x46, 0x22, 0x99,
    };

    const key = c.wc_ecc_key_new(null) orelse return error.OutOfMemory;
    defer c.wc_ecc_key_free(key);
    {
        const ret = c.wc_ecc_import_private_key_ex(
            &priv_d, @intCast(priv_d.len),
            &pub_uncompressed, @intCast(pub_uncompressed.len),
            key, c.ECC_SECP256R1,
        );
        if (ret != 0) return errors.mapCryptoError(ret);
    }

    var kp = P256{ .key = key };
    const exported = try kp.exportPrivateRaw();
    try std.testing.expectEqualSlices(u8, &priv_d, &exported);
}

// SECP256K1 verify KAT: OpenSSL-generated key pair and ECDSA signature verified by wolfSSL.
// Key generation: openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp256k1
// Signature: echo -n "test message for SECP256K1" | openssl dgst -sha256 | openssl pkeyutl -sign
// This cross-implementation test proves wolfSSL correctly verifies OpenSSL SECP256K1 signatures.
test "ECC SECP256K1 verify KAT (OpenSSL cross-verify)" {
    // X9.63 uncompressed public key (0x04 || x || y, 65 bytes)
    const pub_key_bytes = [65]u8{
        0x04, 0x77, 0x33, 0xe1, 0x11, 0xd1, 0xb6, 0x52,
        0x44, 0x4f, 0x05, 0xa8, 0x1d, 0x33, 0x9a, 0x83,
        0x0d, 0xca, 0x3a, 0xd6, 0xac, 0xa9, 0x18, 0xc2,
        0x15, 0x9c, 0x98, 0x54, 0xc0, 0xf2, 0xf1, 0x97,
        0x8c, 0x01, 0x2b, 0xfe, 0xde, 0xcf, 0x3e, 0xe4,
        0x5b, 0xb6, 0xe7, 0x37, 0x26, 0x14, 0xb2, 0x6f,
        0x9a, 0x14, 0x0a, 0xbe, 0xa3, 0x0f, 0xe4, 0x82,
        0x85, 0xf5, 0xfe, 0x65, 0xe9, 0x25, 0xbb, 0x13,
        0xf7,
    };
    // SHA-256("test message for SECP256K1")
    const msg_hash = [32]u8{
        0x1d, 0x39, 0xb6, 0x3d, 0xa3, 0x1b, 0x75, 0x18,
        0xcc, 0xca, 0xdc, 0x33, 0xfc, 0x97, 0x95, 0x7b,
        0x4d, 0xd4, 0x45, 0xaa, 0x3a, 0xde, 0x50, 0xfd,
        0x47, 0x3d, 0x40, 0xcd, 0x4f, 0xb9, 0xa5, 0x1f,
    };
    // DER-encoded ECDSA signature from OpenSSL (71 bytes)
    const sig = [71]u8{
        0x30, 0x45, 0x02, 0x20, 0x69, 0x7a, 0xc7, 0xcc,
        0x03, 0x9a, 0xc6, 0xd1, 0xed, 0xf5, 0x1f, 0xbe,
        0xc5, 0xaa, 0x41, 0x91, 0x20, 0x7d, 0x15, 0xd3,
        0x02, 0x61, 0xe1, 0x62, 0x22, 0x3e, 0x50, 0x3d,
        0xa2, 0x84, 0x2a, 0x19, 0x02, 0x21, 0x00, 0xbf,
        0x4d, 0x3a, 0x94, 0x3b, 0x49, 0xb1, 0x1e, 0x55,
        0xfb, 0x70, 0x3e, 0xf3, 0x75, 0x2f, 0x6b, 0x18,
        0xda, 0x93, 0x58, 0x20, 0x60, 0x85, 0xc1, 0x52,
        0x0d, 0x33, 0x36, 0xa4, 0x71, 0x6b, 0xd0,
    };

    var pub_key = try K256PublicKey.fromBytes(&pub_key_bytes);
    defer pub_key.deinit();

    try pub_key.verify(&msg_hash, &sig);

    // Tampered hash must not verify
    var bad_hash = msg_hash;
    bad_hash[0] ^= 0xff;
    try std.testing.expectError(error.AuthenticationFailed, pub_key.verify(&bad_hash, &sig));
}

test "ECC SECP256K1 sign/verify round-trip" {
    var rng = try random.SecureRng.init();
    defer rng.deinit();

    var kp = try K256.generate(&rng);
    defer kp.deinit();

    const msg_hash = [_]u8{0xab} ** 32;
    var sig_buf: [maxSigLen(.secp256k1)]u8 = undefined;
    const sig = try kp.sign(&msg_hash, &sig_buf, &rng);

    const pub_key = kp.publicKey();
    try pub_key.verify(&msg_hash, sig);
}

// P-521 verify KAT: pyca/cryptography-generated signature verified by wolfSSL.
// Key pair: RFC 6979 §A.2.7 private key d (66-byte zero-padded) with the public key
// Q computed by pyca from d. The hash is SHA-512("sample") per RFC 6979 §A.2.7.
// The DER signature was generated by pyca (random nonce) and confirmed valid by pyca
// before embedding — wolfSSL verifying it proves cross-implementation P-521 compatibility.
test "ECC P-521 verify KAT (pyca cross-verify)" {
    // X9.63 uncompressed public key (0x04 || x || y, 133 bytes)
    const pub_uncompressed = [P521PublicKey.uncompressed_size]u8{
        0x04,
        // x (66 bytes)
        0x01, 0xac, 0x89, 0x42, 0xa8, 0x71, 0xda, 0x5e,
        0xf6, 0xb6, 0x97, 0xdf, 0x37, 0xbf, 0x1c, 0x36,
        0x90, 0x54, 0xe6, 0x2d, 0xd1, 0x44, 0x2f, 0x58,
        0x85, 0x6c, 0xce, 0x5c, 0x82, 0x07, 0x07, 0x15,
        0x7d, 0x5b, 0xb7, 0xb9, 0x09, 0x8e, 0x3d, 0x48,
        0x09, 0x91, 0xee, 0xf6, 0xad, 0xcc, 0x36, 0x7b,
        0x31, 0x68, 0xa6, 0xc6, 0xa1, 0xc4, 0xb7, 0x34,
        0x39, 0xdb, 0x2b, 0xc8, 0xe5, 0x59, 0x95, 0x8e,
        0x9a, 0x29,
        // y (66 bytes)
        0x00, 0x5a, 0xef, 0x1f, 0xda, 0xcc, 0x29, 0xba,
        0xac, 0x72, 0xbf, 0xd7, 0x4a, 0xac, 0xa1, 0x61,
        0x8c, 0xda, 0x3c, 0xdb, 0xfa, 0x9a, 0x41, 0x8f,
        0x4e, 0x8a, 0x89, 0x21, 0xa6, 0xcf, 0xff, 0x71,
        0x81, 0x5e, 0x71, 0xcb, 0x48, 0x9f, 0x93, 0x5b,
        0xbc, 0xe9, 0xff, 0xd5, 0x8a, 0x5a, 0x9e, 0xbf,
        0xf7, 0x5c, 0xcf, 0xcf, 0xba, 0x58, 0x71, 0x49,
        0x12, 0xe9, 0x5f, 0x77, 0x79, 0x0a, 0x71, 0xce,
        0x48, 0x76,
    };
    // SHA-512("sample") per RFC 6979 §A.2.7 (64 bytes)
    const msg_hash = [64]u8{
        0x39, 0xa5, 0xe0, 0x4a, 0xaf, 0xf7, 0x45, 0x5d,
        0x98, 0x50, 0xc6, 0x05, 0x36, 0x4f, 0x51, 0x4c,
        0x11, 0x32, 0x4c, 0xe6, 0x40, 0x16, 0x96, 0x0d,
        0x23, 0xd5, 0xdc, 0x57, 0xd3, 0xff, 0xd8, 0xf4,
        0x9a, 0x73, 0x94, 0x68, 0xab, 0x80, 0x49, 0xbf,
        0x18, 0xee, 0xf8, 0x20, 0xcd, 0xb1, 0xad, 0x6c,
        0x90, 0x15, 0xf8, 0x38, 0x55, 0x6b, 0xc7, 0xfa,
        0xd4, 0x13, 0x8b, 0x23, 0xfd, 0xf9, 0x86, 0xc7,
    };
    // DER-encoded ECDSA signature from pyca/cryptography (138 bytes).
    // SEQUENCE(0x87=135): INTEGER(r, 65 bytes with leading 0x00) || INTEGER(s, 65 bytes)
    const sig = [138]u8{
        0x30, 0x81, 0x87,
        0x02, 0x42, 0x00,
        0xa3, 0x7f, 0xe7, 0xcf, 0x79, 0x70, 0x1b, 0x91,
        0xdc, 0x84, 0x6a, 0x22, 0xe6, 0xea, 0xeb, 0x43,
        0x81, 0x1f, 0x68, 0x2e, 0xa1, 0xef, 0xe2, 0x31,
        0xd0, 0xad, 0x31, 0x9a, 0xf2, 0x4c, 0xf7, 0x47,
        0xdd, 0x8d, 0x38, 0x6a, 0x2a, 0xc6, 0x29, 0xe3,
        0x4e, 0x7c, 0xeb, 0x93, 0x9f, 0x2a, 0x17, 0xcd,
        0xbd, 0x1f, 0x8e, 0x81, 0xb8, 0x8d, 0x79, 0x3b,
        0x22, 0xfd, 0x5f, 0xfe, 0x40, 0x93, 0x01, 0xbe,
        0x06,
        0x02, 0x41,
        0x05, 0x56, 0x01, 0x4f, 0x2b, 0xfc, 0x09, 0xf8,
        0x25, 0x97, 0x6b, 0x3a, 0x13, 0x6b, 0xa8, 0x13,
        0x4a, 0xa5, 0x7e, 0x66, 0x8c, 0x23, 0x29, 0x47,
        0x50, 0x16, 0xcc, 0x4d, 0xc7, 0xf0, 0x7f, 0xe2,
        0x23, 0x07, 0x0b, 0x7f, 0xd7, 0xf5, 0x77, 0x14,
        0x40, 0x9a, 0xec, 0x93, 0xe4, 0x41, 0x33, 0x4e,
        0x23, 0x5b, 0xdf, 0x25, 0x10, 0x3b, 0xa0, 0x67,
        0xf2, 0x8d, 0x45, 0xa9, 0x47, 0x04, 0x0f, 0xcf,
        0xf9,
    };

    var pub_key = try P521PublicKey.fromBytes(&pub_uncompressed);
    defer pub_key.deinit();

    try pub_key.verify(&msg_hash, &sig);

    // Tampered hash must not verify
    var bad_hash = msg_hash;
    bad_hash[0] ^= 0xff;
    try std.testing.expectError(error.AuthenticationFailed, pub_key.verify(&bad_hash, &sig));
}

// ECC P-521 private key export KAT.
// Private key d is RFC 6979 §A.2.7 (521-bit scalar, zero-padded to 66 bytes big-endian).
// The corresponding public key Q was computed by pyca from d. Imports via
// wc_ecc_import_private_key_ex, exports via exportPrivateRaw, and confirms the bytes match.
// Independent oracle: RFC 6979 Appendix A.2.7.
test "ECC P-521 exportPrivateRaw KAT" {
    // RFC 6979 §A.2.7 private scalar d (66 bytes, big-endian, leading zero-padded)
    const priv_d = [P521.key_size]u8{
        0x00, 0xfa, 0xd0, 0x6d, 0xaa, 0x62, 0xba, 0x3b,
        0x25, 0xd2, 0xfb, 0x40, 0x13, 0x3d, 0xa7, 0x57,
        0x20, 0x5d, 0xe6, 0x7f, 0x5b, 0xb0, 0x01, 0x8f,
        0xee, 0x8c, 0x86, 0xe1, 0xb6, 0x8c, 0x7e, 0x75,
        0xca, 0xa8, 0x96, 0xeb, 0x32, 0xf1, 0xf4, 0x7c,
        0x70, 0xbe, 0x89, 0xa2, 0xd9, 0x7d, 0x9f, 0xe8,
        0xd4, 0x6e, 0x9f, 0x53, 0xab, 0x4b, 0x26, 0xd1,
        0xb5, 0x7e, 0x43, 0xc8, 0xb3, 0x3e, 0x56, 0xc5,
        0xfd, 0x9e,
    };
    // Corresponding public key Q computed by pyca from d (0x04 || x || y, 133 bytes)
    const pub_uncompressed = [P521PublicKey.uncompressed_size]u8{
        0x04,
        0x01, 0xac, 0x89, 0x42, 0xa8, 0x71, 0xda, 0x5e,
        0xf6, 0xb6, 0x97, 0xdf, 0x37, 0xbf, 0x1c, 0x36,
        0x90, 0x54, 0xe6, 0x2d, 0xd1, 0x44, 0x2f, 0x58,
        0x85, 0x6c, 0xce, 0x5c, 0x82, 0x07, 0x07, 0x15,
        0x7d, 0x5b, 0xb7, 0xb9, 0x09, 0x8e, 0x3d, 0x48,
        0x09, 0x91, 0xee, 0xf6, 0xad, 0xcc, 0x36, 0x7b,
        0x31, 0x68, 0xa6, 0xc6, 0xa1, 0xc4, 0xb7, 0x34,
        0x39, 0xdb, 0x2b, 0xc8, 0xe5, 0x59, 0x95, 0x8e,
        0x9a, 0x29,
        0x00, 0x5a, 0xef, 0x1f, 0xda, 0xcc, 0x29, 0xba,
        0xac, 0x72, 0xbf, 0xd7, 0x4a, 0xac, 0xa1, 0x61,
        0x8c, 0xda, 0x3c, 0xdb, 0xfa, 0x9a, 0x41, 0x8f,
        0x4e, 0x8a, 0x89, 0x21, 0xa6, 0xcf, 0xff, 0x71,
        0x81, 0x5e, 0x71, 0xcb, 0x48, 0x9f, 0x93, 0x5b,
        0xbc, 0xe9, 0xff, 0xd5, 0x8a, 0x5a, 0x9e, 0xbf,
        0xf7, 0x5c, 0xcf, 0xcf, 0xba, 0x58, 0x71, 0x49,
        0x12, 0xe9, 0x5f, 0x77, 0x79, 0x0a, 0x71, 0xce,
        0x48, 0x76,
    };

    const key = c.wc_ecc_key_new(null) orelse return error.OutOfMemory;
    defer c.wc_ecc_key_free(key);
    {
        const ret = c.wc_ecc_import_private_key_ex(
            &priv_d, @intCast(priv_d.len),
            &pub_uncompressed, @intCast(pub_uncompressed.len),
            key, c.ECC_SECP521R1,
        );
        if (ret != 0) return errors.mapCryptoError(ret);
    }

    var kp = P521{ .key = key };
    const exported = try kp.exportPrivateRaw();
    try std.testing.expectEqualSlices(u8, &priv_d, &exported);
}

test "ECC P-521 sign/verify round-trip" {
    var rng = try random.SecureRng.init();
    defer rng.deinit();

    var kp = try P521.generate(&rng);
    defer kp.deinit();

    // 64-byte hash (SHA-512 size, appropriate for P-521)
    const msg_hash = [_]u8{0xab} ** 64;
    var sig_buf: [maxSigLen(.secp521r1)]u8 = undefined;
    const sig = try kp.sign(&msg_hash, &sig_buf, &rng);

    const pub_key = kp.publicKey();
    try pub_key.verify(&msg_hash, sig);
}

test "ECDH P-521 round-trip" {
    var rng = try random.SecureRng.init();
    defer rng.deinit();

    var alice = try P521.generate(&rng);
    defer alice.deinit();
    var bob = try P521.generate(&rng);
    defer bob.deinit();

    const secret_a = try alice.sharedSecret(bob.publicKey());
    const secret_b = try bob.sharedSecret(alice.publicKey());

    try std.testing.expectEqualSlices(u8, secret_a.secret[0..secret_a.len], secret_b.secret[0..secret_b.len]);
}

// P-384 verify KAT: pyca/cryptography-generated signature verified by wolfSSL.
// Public and private key generated by pyca; hash is SHA-384("sample").
// The DER signature was generated by pyca (random nonce) and verified by pyca
// before embedding — wolfSSL verifying it proves cross-implementation P-384 compatibility.
test "ECC P-384 verify KAT (pyca cross-verify)" {
    // X9.63 uncompressed public key (0x04 || x || y, 97 bytes)
    const pub_uncompressed = [P384PublicKey.uncompressed_size]u8{
        0x04,
        // x (48 bytes)
        0xec, 0x3a, 0x4e, 0x41, 0x5b, 0x4e, 0x19, 0xa4,
        0x56, 0x86, 0x18, 0x02, 0x9f, 0x42, 0x7f, 0xa5,
        0xda, 0x9a, 0x8b, 0xc4, 0xae, 0x92, 0xe0, 0x2e,
        0x06, 0xaa, 0xe5, 0x28, 0x6b, 0x30, 0x0c, 0x64,
        0xde, 0xf8, 0xf0, 0xea, 0x90, 0x55, 0x86, 0x60,
        0x64, 0xa2, 0x54, 0x51, 0x54, 0x80, 0xbc, 0x13,
        // y (48 bytes)
        0x80, 0x15, 0xd9, 0xb7, 0x2d, 0x7d, 0x57, 0x24,
        0x4e, 0xa8, 0xef, 0x9a, 0xc0, 0xc6, 0x21, 0x89,
        0x67, 0x08, 0xa5, 0x93, 0x67, 0xf9, 0xdf, 0xb9,
        0xf5, 0x4c, 0xa8, 0x4b, 0x3f, 0x1c, 0x9d, 0xb1,
        0x28, 0x8b, 0x23, 0x1c, 0x3a, 0xe0, 0xd4, 0xfe,
        0x73, 0x44, 0xfd, 0x25, 0x33, 0x26, 0x47, 0x20,
    };
    // SHA-384("sample") (48 bytes)
    const msg_hash = [48]u8{
        0x9a, 0x90, 0x83, 0x50, 0x5b, 0xc9, 0x22, 0x76,
        0xae, 0xc4, 0xbe, 0x31, 0x26, 0x96, 0xef, 0x7b,
        0xf3, 0xbf, 0x60, 0x3f, 0x4b, 0xbd, 0x38, 0x11,
        0x96, 0xa0, 0x29, 0xf3, 0x40, 0x58, 0x53, 0x12,
        0x31, 0x3b, 0xca, 0x4a, 0x9b, 0x5b, 0x89, 0x0e,
        0xfe, 0xe4, 0x2c, 0x77, 0xb1, 0xee, 0x25, 0xfe,
    };
    // DER-encoded ECDSA signature from pyca/cryptography (103 bytes).
    // SEQUENCE(0x65=101): INTEGER(r, 48 bytes) || INTEGER(s, 48 bytes with leading 0x00)
    const sig = [103]u8{
        0x30, 0x65,
        0x02, 0x30,
        0x66, 0xb4, 0x60, 0xaa, 0xcd, 0xfa, 0xc9, 0xfc,
        0xc3, 0x04, 0xa7, 0xdf, 0x37, 0xe9, 0x57, 0xe9,
        0x4d, 0x45, 0xe9, 0xa3, 0x19, 0xe7, 0xc6, 0x6b,
        0xc8, 0x86, 0x51, 0x36, 0xfe, 0x58, 0xbc, 0x72,
        0xda, 0xf4, 0x7b, 0x7a, 0x58, 0x25, 0x4b, 0xea,
        0x01, 0x4d, 0x8b, 0x5c, 0x4d, 0x8d, 0x36, 0x95,
        0x02, 0x31, 0x00,
        0x9d, 0x5f, 0xef, 0x84, 0x71, 0x9a, 0x1a, 0xfc,
        0x0b, 0x11, 0xed, 0x0f, 0xd6, 0x0b, 0xce, 0x41,
        0x3f, 0xa6, 0xe1, 0x20, 0xa7, 0x31, 0x7f, 0x7a,
        0x5c, 0x32, 0xdf, 0x17, 0xea, 0x66, 0x97, 0x3a,
        0xa6, 0x53, 0x19, 0xd8, 0xc9, 0xd8, 0x6c, 0xb7,
        0xd0, 0xfd, 0xeb, 0x4d, 0xf8, 0x25, 0x22, 0x59,
    };

    var pub_key = try P384PublicKey.fromBytes(&pub_uncompressed);
    defer pub_key.deinit();

    try pub_key.verify(&msg_hash, &sig);

    // Tampered hash must not verify
    var bad_hash = msg_hash;
    bad_hash[0] ^= 0xff;
    try std.testing.expectError(error.AuthenticationFailed, pub_key.verify(&bad_hash, &sig));
}

test "ECDH P-384 round-trip" {
    var rng = try random.SecureRng.init();
    defer rng.deinit();

    var alice = try P384.generate(&rng);
    defer alice.deinit();
    var bob = try P384.generate(&rng);
    defer bob.deinit();

    const secret_a = try alice.sharedSecret(bob.publicKey());
    const secret_b = try bob.sharedSecret(alice.publicKey());

    try std.testing.expectEqualSlices(u8, secret_a.secret[0..secret_a.len], secret_b.secret[0..secret_b.len]);
}

// NOTE: secp256k1 (K256) ECDH is not supported in this wolfSSL build. Root cause:
// wolfSSL's ECDH implementation (wc_ecc_shared_secret_gen_sync in ecc.c) has
// dedicated SP_ECC paths only for P-256, SM2, P-384, and P-521. secp256k1 falls
// through to the generic wc_ecc_mulmod_ex2 path, which fails when both
// HAVE_ECC_KOBLITZ and FP_ECC are defined. Sign/verify work because they use a
// different code path. K256.sharedSecret() is guarded with @compileError.

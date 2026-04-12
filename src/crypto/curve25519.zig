const std = @import("std");
const c = @import("../c.zig").c;
const errors = @import("../errors.zig");
const random = @import("../random.zig");

/// X25519 Diffie-Hellman key agreement.
pub const X25519 = struct {
    pub const KEY_SIZE = c.CURVE25519_KEYSIZE;

    /// An X25519 public key (little-endian u-coordinate).
    pub const PublicKey = struct {
        key: *c.curve25519_key,
        owned: bool,

        /// Import a public key from little-endian u-coordinate bytes.
        pub fn fromBytes(bytes: *const [KEY_SIZE]u8) !PublicKey {
            const key = c.wc_curve25519_new(null, c.INVALID_DEVID, null) orelse return error.OutOfMemory;
            errdefer _ = c.wc_curve25519_delete(key, null);
            const ret = c.wc_curve25519_import_public_ex(bytes, KEY_SIZE, key, c.EC25519_LITTLE_ENDIAN);
            if (ret != 0) return errors.mapCryptoError(ret);
            return .{ .key = key, .owned = true };
        }

        pub fn deinit(self: *PublicKey) void {
            if (self.owned) _ = c.wc_curve25519_delete(self.key, null);
        }
    };

    pub const KeyPair = struct {
        key: *c.curve25519_key,

        pub fn generate(rng: *random.SecureRng) !KeyPair {
            const key = c.wc_curve25519_new(null, c.INVALID_DEVID, null) orelse return error.OutOfMemory;
            errdefer _ = c.wc_curve25519_delete(key, null);

            const ret = c.wc_curve25519_make_key(rng.rng, KEY_SIZE, key);
            if (ret != 0) return errors.mapCryptoError(ret);
            return .{ .key = key };
        }

        pub fn deinit(self: *KeyPair) void {
            // wc_curve25519_delete calls wc_curve25519_free internally, which calls
            // ForceZero(key, sizeof(*key)) — verified in wolfcrypt/src/curve25519.c:1181.
            _ = c.wc_curve25519_delete(self.key, null);
        }

        /// Return a borrowed view of this key pair's public key.
        /// Do NOT call deinit() on the returned PublicKey.
        pub fn publicKey(self: *KeyPair) PublicKey {
            return .{ .key = self.key, .owned = false };
        }

        /// Export the public key as little-endian u-coordinate bytes.
        pub fn publicKeyBytes(self: *KeyPair) ![KEY_SIZE]u8 {
            var pub_key: [KEY_SIZE]u8 = undefined;
            var pub_len: c.word32 = KEY_SIZE;
            const ret = c.wc_curve25519_export_public_ex(self.key, &pub_key, &pub_len, c.EC25519_LITTLE_ENDIAN);
            if (ret != 0) return errors.mapCryptoError(ret);
            return pub_key;
        }

        /// Compute the shared secret with a peer's public key.
        /// Uses EC25519_LITTLE_ENDIAN to match RFC 7748 and publicKeyBytes() byte order.
        pub fn sharedSecret(self: *KeyPair, peer_pub: PublicKey) ![KEY_SIZE]u8 {
            var secret: [KEY_SIZE]u8 = undefined;
            var secret_len: c.word32 = KEY_SIZE;
            const ret = c.wc_curve25519_shared_secret_ex(self.key, peer_pub.key, &secret, &secret_len, c.EC25519_LITTLE_ENDIAN);
            if (ret != 0) return errors.mapCryptoError(ret);
            return secret;
        }

        /// Export the private key as little-endian raw bytes.
        /// Uses EC25519_LITTLE_ENDIAN to match the byte order of the RFC 7748 test vectors
        /// and publicKeyBytes().
        pub fn exportPrivateRaw(self: *KeyPair) ![KEY_SIZE]u8 {
            var out: [KEY_SIZE]u8 = undefined;
            var out_len: c.word32 = KEY_SIZE;
            const ret = c.wc_curve25519_export_private_raw_ex(self.key, &out, &out_len, c.EC25519_LITTLE_ENDIAN);
            if (ret != 0) return errors.mapCryptoError(ret);
            return out;
        }
    };
};

test "X25519 key agreement" {
    var rng = try random.SecureRng.init();
    defer rng.deinit();

    var alice = try X25519.KeyPair.generate(&rng);
    defer alice.deinit();
    var bob = try X25519.KeyPair.generate(&rng);
    defer bob.deinit();

    const secret_a = try alice.sharedSecret(bob.publicKey());
    const secret_b = try bob.sharedSecret(alice.publicKey());

    try std.testing.expectEqualSlices(u8, &secret_a, &secret_b);

    // Shared secret should not be all zeros
    var all_zero = true;
    for (secret_a) |b| {
        if (b != 0) { all_zero = false; break; }
    }
    try std.testing.expect(!all_zero);
}

// RFC 7748 §6.1 known-answer test for X25519.
// Vectors are authoritative little-endian u-coordinates from the RFC.
// Exercises PublicKey.fromBytes — imports Bob's public key via the new API
// and verifies the shared secret matches the RFC expected value.
test "X25519 RFC 7748 §6.1 KAT" {
    // Test vectors from RFC 7748 §6.1 (all little-endian byte order)
    const KSZ = X25519.KEY_SIZE;
    const alice_priv = [KSZ]u8{
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
        0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
        0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
        0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
    };
    const alice_pub = [KSZ]u8{
        0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54,
        0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a,
        0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4,
        0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a,
    };
    const bob_pub = [KSZ]u8{
        0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4,
        0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
        0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d,
        0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f,
    };
    const expected_shared = [KSZ]u8{
        0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1,
        0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35, 0x0f, 0x25,
        0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33,
        0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16, 0x17, 0x42,
    };

    // Import Alice's key pair (private + public, little-endian)
    const alice_c_key = c.wc_curve25519_new(null, c.INVALID_DEVID, null) orelse return error.OutOfMemory;
    defer _ = c.wc_curve25519_delete(alice_c_key, null);
    {
        const ret = c.wc_curve25519_import_private_raw_ex(
            &alice_priv, KSZ, &alice_pub, KSZ,
            alice_c_key, c.EC25519_LITTLE_ENDIAN,
        );
        if (ret != 0) return errors.mapCryptoError(ret);
    }

    // Import Bob's public key via PublicKey.fromBytes (exercises the new API)
    var bob_pub_key = try X25519.PublicKey.fromBytes(&bob_pub);
    defer bob_pub_key.deinit();

    // Wrap Alice in a KeyPair view (borrowed — do NOT call .deinit(), C key freed above)
    var alice_kp = X25519.KeyPair{ .key = alice_c_key };

    const shared = try alice_kp.sharedSecret(bob_pub_key);
    try std.testing.expectEqualSlices(u8, &expected_shared, &shared);
}

// X25519 private key export round-trip: re-uses the RFC 7748 §6.1 vectors.
// Imports Alice's private key, exports it raw (little-endian), then re-imports
// the exported bytes into a fresh key and verifies it produces the RFC shared secret.
// wolfSSL may clamp the scalar on import, so the exported bytes may differ from
// the raw input; the oracle is the RFC 7748 expected shared secret, not the bytes.
test "X25519 exportPrivateRaw round-trip" {
    const KSZ = X25519.KEY_SIZE;
    const alice_priv = [KSZ]u8{
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
        0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
        0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
        0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
    };
    const alice_pub = [KSZ]u8{
        0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54,
        0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a,
        0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4,
        0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a,
    };
    const bob_pub = [KSZ]u8{
        0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4,
        0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
        0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d,
        0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f,
    };
    const expected_shared = [KSZ]u8{
        0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1,
        0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35, 0x0f, 0x25,
        0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33,
        0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16, 0x17, 0x42,
    };

    // Import Alice's key pair
    const alice_c_key = c.wc_curve25519_new(null, c.INVALID_DEVID, null) orelse return error.OutOfMemory;
    defer _ = c.wc_curve25519_delete(alice_c_key, null);
    {
        const ret = c.wc_curve25519_import_private_raw_ex(
            &alice_priv, KSZ, &alice_pub, KSZ,
            alice_c_key, c.EC25519_LITTLE_ENDIAN,
        );
        if (ret != 0) return errors.mapCryptoError(ret);
    }
    var alice_kp = X25519.KeyPair{ .key = alice_c_key };

    // Export the private key raw bytes (may be clamped by wolfSSL)
    const exported_priv = try alice_kp.exportPrivateRaw();

    // Re-import the exported bytes into a fresh key; pair with the original public key
    const alice2_c_key = c.wc_curve25519_new(null, c.INVALID_DEVID, null) orelse return error.OutOfMemory;
    defer _ = c.wc_curve25519_delete(alice2_c_key, null);
    {
        const ret = c.wc_curve25519_import_private_raw_ex(
            &exported_priv, KSZ, &alice_pub, KSZ,
            alice2_c_key, c.EC25519_LITTLE_ENDIAN,
        );
        if (ret != 0) return errors.mapCryptoError(ret);
    }
    var alice2_kp = X25519.KeyPair{ .key = alice2_c_key };

    // Verify the re-imported key produces the RFC 7748 shared secret
    var bob_pub_key = try X25519.PublicKey.fromBytes(&bob_pub);
    defer bob_pub_key.deinit();
    const shared = try alice2_kp.sharedSecret(bob_pub_key);
    try std.testing.expectEqualSlices(u8, &expected_shared, &shared);
}

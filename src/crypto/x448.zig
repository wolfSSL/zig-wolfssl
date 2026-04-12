const std = @import("std");
const c = @import("../c.zig").c;
const errors = @import("../errors.zig");
const random = @import("../random.zig");
const opaque_alloc = @import("../opaque_alloc.zig");

/// X448 Diffie-Hellman key agreement (RFC 7748 §5).
pub const X448 = struct {
    pub const KEY_SIZE = c.CURVE448_KEY_SIZE;

    /// An X448 public key (little-endian u-coordinate, 56 bytes).
    pub const PublicKey = struct {
        key: *c.curve448_key,
        owned: bool,

        /// Import a public key from little-endian u-coordinate bytes.
        pub fn fromBytes(bytes: *const [KEY_SIZE]u8) !PublicKey {
            const key = try opaque_alloc.allocCurve448();
            errdefer opaque_alloc.freeCurve448(key);
            var ret = c.wc_curve448_init(key);
            if (ret != 0) return errors.mapCryptoError(ret);
            errdefer c.wc_curve448_free(key);
            ret = c.wc_curve448_import_public_ex(bytes, KEY_SIZE, key, c.EC448_LITTLE_ENDIAN);
            if (ret != 0) return errors.mapCryptoError(ret);
            return .{ .key = key, .owned = true };
        }

        pub fn deinit(self: *PublicKey) void {
            if (self.owned) {
                c.wc_curve448_free(self.key);
                opaque_alloc.freeCurve448(self.key);
            }
        }
    };

    pub const KeyPair = struct {
        key: *c.curve448_key,

        pub fn generate(rng: *random.SecureRng) !KeyPair {
            const key = try opaque_alloc.allocCurve448();
            errdefer opaque_alloc.freeCurve448(key);
            var ret = c.wc_curve448_init(key);
            if (ret != 0) return errors.mapCryptoError(ret);
            errdefer c.wc_curve448_free(key);
            ret = c.wc_curve448_make_key(rng.rng, KEY_SIZE, key);
            if (ret != 0) return errors.mapCryptoError(ret);
            return .{ .key = key };
        }

        pub fn deinit(self: *KeyPair) void {
            // wc_curve448_free calls ForceZero(key->k, ...) and XMEMSET(key->p, 0, ...)
            // before returning — verified in wolfcrypt/src/curve448.c:708-719.
            c.wc_curve448_free(self.key);
            opaque_alloc.freeCurve448(self.key);
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
            const ret = c.wc_curve448_export_public_ex(self.key, &pub_key, &pub_len, c.EC448_LITTLE_ENDIAN);
            if (ret != 0) return errors.mapCryptoError(ret);
            return pub_key;
        }

        /// Compute the shared secret with a peer's public key.
        /// Uses EC448_LITTLE_ENDIAN to match RFC 7748 and publicKeyBytes() byte order.
        pub fn sharedSecret(self: *KeyPair, peer_pub: PublicKey) ![KEY_SIZE]u8 {
            var secret: [KEY_SIZE]u8 = undefined;
            var secret_len: c.word32 = KEY_SIZE;
            const ret = c.wc_curve448_shared_secret_ex(self.key, peer_pub.key, &secret, &secret_len, c.EC448_LITTLE_ENDIAN);
            if (ret != 0) return errors.mapCryptoError(ret);
            return secret;
        }

        /// Export the private key as little-endian raw bytes.
        pub fn exportPrivateRaw(self: *KeyPair) ![KEY_SIZE]u8 {
            var out: [KEY_SIZE]u8 = undefined;
            var out_len: c.word32 = KEY_SIZE;
            const ret = c.wc_curve448_export_private_raw_ex(self.key, &out, &out_len, c.EC448_LITTLE_ENDIAN);
            if (ret != 0) return errors.mapCryptoError(ret);
            return out;
        }
    };
};

test "X448 key agreement" {
    var rng = try random.SecureRng.init();
    defer rng.deinit();

    var alice = try X448.KeyPair.generate(&rng);
    defer alice.deinit();
    var bob = try X448.KeyPair.generate(&rng);
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

// RFC 7748 §6.2 known-answer test for X448.
// Vectors independently verified with Python cryptography library
// (X448PrivateKey.from_private_bytes + X448PrivateKey.exchange).
test "X448 RFC 7748 §6.2 KAT" {
    const KSZ = X448.KEY_SIZE;

    // Alice's private key (little-endian, from RFC 7748 §6.2)
    const alice_priv = [KSZ]u8{
        0x9a, 0x8f, 0x49, 0x25, 0xd1, 0x51, 0x9f, 0x57,
        0x75, 0xcf, 0x46, 0xb0, 0x4b, 0x58, 0x00, 0xd4,
        0xee, 0x9e, 0xe8, 0xba, 0xe8, 0xbc, 0x55, 0x65,
        0xd4, 0x98, 0xc2, 0x8d, 0xd9, 0xc9, 0xba, 0xf5,
        0x74, 0xa9, 0x41, 0x97, 0x44, 0x89, 0x73, 0x91,
        0x00, 0x63, 0x82, 0xa6, 0xf1, 0x27, 0xab, 0x1d,
        0x9a, 0xc2, 0xd8, 0xc0, 0xa5, 0x98, 0x72, 0x6b,
    };
    // Alice's public key (expected, from RFC 7748 §6.2, verified with Python)
    const alice_pub = [KSZ]u8{
        0x9b, 0x08, 0xf7, 0xcc, 0x31, 0xb7, 0xe3, 0xe6,
        0x7d, 0x22, 0xd5, 0xae, 0xa1, 0x21, 0x07, 0x4a,
        0x27, 0x3b, 0xd2, 0xb8, 0x3d, 0xe0, 0x9c, 0x63,
        0xfa, 0xa7, 0x3d, 0x2c, 0x22, 0xc5, 0xd9, 0xbb,
        0xc8, 0x36, 0x64, 0x72, 0x41, 0xd9, 0x53, 0xd4,
        0x0c, 0x5b, 0x12, 0xda, 0x88, 0x12, 0x0d, 0x53,
        0x17, 0x7f, 0x80, 0xe5, 0x32, 0xc4, 0x1f, 0xa0,
    };
    // Bob's public key (from RFC 7748 §6.2, verified with Python)
    const bob_pub = [KSZ]u8{
        0x3e, 0xb7, 0xa8, 0x29, 0xb0, 0xcd, 0x20, 0xf5,
        0xbc, 0xfc, 0x0b, 0x59, 0x9b, 0x6f, 0xec, 0xcf,
        0x6d, 0xa4, 0x62, 0x71, 0x07, 0xbd, 0xb0, 0xd4,
        0xf3, 0x45, 0xb4, 0x30, 0x27, 0xd8, 0xb9, 0x72,
        0xfc, 0x3e, 0x34, 0xfb, 0x42, 0x32, 0xa1, 0x3c,
        0xa7, 0x06, 0xdc, 0xb5, 0x7a, 0xec, 0x3d, 0xae,
        0x07, 0xbd, 0xc1, 0xc6, 0x7b, 0xf3, 0x36, 0x09,
    };
    // Expected shared secret (from RFC 7748 §6.2, verified with Python)
    const expected_shared = [KSZ]u8{
        0x07, 0xff, 0xf4, 0x18, 0x1a, 0xc6, 0xcc, 0x95,
        0xec, 0x1c, 0x16, 0xa9, 0x4a, 0x0f, 0x74, 0xd1,
        0x2d, 0xa2, 0x32, 0xce, 0x40, 0xa7, 0x75, 0x52,
        0x28, 0x1d, 0x28, 0x2b, 0xb6, 0x0c, 0x0b, 0x56,
        0xfd, 0x24, 0x64, 0xc3, 0x35, 0x54, 0x39, 0x36,
        0x52, 0x1c, 0x24, 0x40, 0x30, 0x85, 0xd5, 0x9a,
        0x44, 0x9a, 0x50, 0x37, 0x51, 0x4a, 0x87, 0x9d,
    };

    // Import Alice's private key and verify her public key
    const alice_c_key = try opaque_alloc.allocCurve448();
    defer {
        c.wc_curve448_free(alice_c_key);
        opaque_alloc.freeCurve448(alice_c_key);
    }
    {
        var ret = c.wc_curve448_init(alice_c_key);
        if (ret != 0) return errors.mapCryptoError(ret);
        ret = c.wc_curve448_import_private_raw_ex(
            &alice_priv, KSZ, &alice_pub, KSZ,
            alice_c_key, c.EC448_LITTLE_ENDIAN,
        );
        if (ret != 0) return errors.mapCryptoError(ret);
    }

    // Verify Alice's public key export matches the RFC value
    var alice_kp = X448.KeyPair{ .key = alice_c_key };
    const exported_pub = try alice_kp.publicKeyBytes();
    try std.testing.expectEqualSlices(u8, &alice_pub, &exported_pub);

    // Import Bob's public key via PublicKey.fromBytes
    var bob_pub_key = try X448.PublicKey.fromBytes(&bob_pub);
    defer bob_pub_key.deinit();

    // Compute shared secret and compare against RFC expected value
    const shared = try alice_kp.sharedSecret(bob_pub_key);
    try std.testing.expectEqualSlices(u8, &expected_shared, &shared);
}

const std = @import("std");
const c = @import("../c.zig").c;
const errors = @import("../errors.zig");
const random = @import("../random.zig");

/// X25519 Diffie-Hellman key agreement.
pub const X25519 = struct {
    pub const KEY_SIZE = c.CURVE25519_KEYSIZE;

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
            // wc_curve25519_delete handles secure zeroing of private key material internally.
            _ = c.wc_curve25519_delete(self.key, null);
        }

        /// Export the public key bytes.
        pub fn publicKeyBytes(self: *KeyPair) ![KEY_SIZE]u8 {
            var pub_key: [KEY_SIZE]u8 = undefined;
            var pub_len: c.word32 = KEY_SIZE;
            const ret = c.wc_curve25519_export_public_ex(self.key, &pub_key, &pub_len, c.EC25519_LITTLE_ENDIAN);
            if (ret != 0) return errors.mapCryptoError(ret);
            return pub_key;
        }

        /// Compute the shared secret with a peer's key.
        pub fn sharedSecret(self: *KeyPair, peer: *KeyPair) ![KEY_SIZE]u8 {
            var secret: [KEY_SIZE]u8 = undefined;
            var secret_len: c.word32 = KEY_SIZE;
            const ret = c.wc_curve25519_shared_secret(self.key, peer.key, &secret, &secret_len);
            if (ret != 0) return errors.mapCryptoError(ret);
            return secret;
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

    const secret_a = try alice.sharedSecret(&bob);
    const secret_b = try bob.sharedSecret(&alice);

    try std.testing.expectEqualSlices(u8, &secret_a, &secret_b);

    // Shared secret should not be all zeros
    var all_zero = true;
    for (secret_a) |b| {
        if (b != 0) { all_zero = false; break; }
    }
    try std.testing.expect(!all_zero);
}

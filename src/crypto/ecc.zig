const std = @import("std");
const c = @import("../c.zig").c;
const errors = @import("../errors.zig");
const random = @import("../random.zig");

pub const Curve = enum {
    secp256r1,
    secp384r1,
    secp521r1,
};

fn curveId(comptime curve: Curve) c_int {
    return switch (curve) {
        .secp256r1 => c.ECC_SECP256R1,
        .secp384r1 => c.ECC_SECP384R1,
        .secp521r1 => c.ECC_SECP521R1,
    };
}

fn keySize(comptime curve: Curve) usize {
    return switch (curve) {
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

/// Comptime-generic ECC key pair.
pub fn EccKeyPair(comptime curve: Curve) type {
    return struct {
        key: *c.ecc_key,

        const Self = @This();
        pub const key_size = keySize(curve);

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
        pub fn verify(self: *Self, msg_hash: []const u8, sig: []const u8) !bool {
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
            return stat == 1;
        }

        /// ECDH: compute shared secret with a peer's public key.
        /// Returns both the buffer and the actual length, as leading zero bytes
        /// may be stripped by wolfCrypt, making len < key_size possible.
        pub fn sharedSecret(self: *Self, peer: *Self) !struct { secret: [key_size]u8, len: usize } {
            var out: [key_size]u8 = undefined;
            var out_len: c.word32 = key_size;
            const ret = c.wc_ecc_shared_secret(self.key, peer.key, &out, &out_len);
            if (ret != 0) return errors.mapCryptoError(ret);
            return .{ .secret = out, .len = out_len };
        }
    };
}

pub const P256 = EccKeyPair(.secp256r1);
pub const P384 = EccKeyPair(.secp384r1);
pub const P521 = EccKeyPair(.secp521r1);

test "ECC P-256 sign/verify" {
    var rng = try random.SecureRng.init();
    defer rng.deinit();

    var kp = try P256.generate(&rng);
    defer kp.deinit();

    const msg_hash = [_]u8{0xde} ** 32;
    var sig_buf: [maxSigLen(.secp256r1)]u8 = undefined;
    const sig = try kp.sign(&msg_hash, &sig_buf, &rng);

    const valid = try kp.verify(&msg_hash, sig);
    try std.testing.expect(valid);

    // Tampered hash should fail
    var bad = msg_hash;
    bad[0] ^= 0xff;
    const invalid = try kp.verify(&bad, sig);
    try std.testing.expect(!invalid);
}

test "ECDH P-256 shared secret" {
    var rng = try random.SecureRng.init();
    defer rng.deinit();

    var alice = try P256.generate(&rng);
    defer alice.deinit();
    var bob = try P256.generate(&rng);
    defer bob.deinit();

    const secret_a = try alice.sharedSecret(&bob);
    const secret_b = try bob.sharedSecret(&alice);

    try std.testing.expectEqualSlices(u8, secret_a.secret[0..secret_a.len], secret_b.secret[0..secret_b.len]);
}

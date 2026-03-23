const std = @import("std");
const c = @import("../c.zig").c;
const errors = @import("../errors.zig");
const random = @import("../random.zig");

pub const Ed25519 = struct {
    pub const PUBLIC_KEY_SIZE = c.ED25519_PUB_KEY_SIZE;
    pub const SECRET_KEY_SIZE = c.ED25519_KEY_SIZE;
    pub const SIGNATURE_SIZE = c.ED25519_SIG_SIZE;

    pub const PublicKey = struct {
        bytes: [PUBLIC_KEY_SIZE]u8,

        /// Verify an Ed25519 signature.
        /// Note: allocates a temporary key handle per call for stateless verification.
        /// For batch verification of many signatures with the same key, consider
        /// caching at the call site.
        pub fn verify(self: *const PublicKey, msg: []const u8, sig: *const [SIGNATURE_SIZE]u8) !bool {
            const key = c.wc_ed25519_new(null, c.INVALID_DEVID, null) orelse return error.OutOfMemory;
            defer _ = c.wc_ed25519_delete(key, null);

            var ret = c.wc_ed25519_import_public(&self.bytes, PUBLIC_KEY_SIZE, key);
            if (ret != 0) return errors.mapCryptoError(ret);

            var stat: c_int = 0;
            ret = c.wc_ed25519_verify_msg(sig, SIGNATURE_SIZE, msg.ptr, @intCast(msg.len), &stat, key);
            if (ret != 0) {
                if (errors.isBadSignatureError(ret)) return false;
                return errors.mapCryptoError(ret);
            }
            return stat == 1;
        }
    };

    pub const KeyPair = struct {
        key: *c.ed25519_key,

        pub fn generate(rng: *random.SecureRng) !KeyPair {
            const key = c.wc_ed25519_new(null, c.INVALID_DEVID, null) orelse return error.OutOfMemory;
            errdefer _ = c.wc_ed25519_delete(key, null);

            const ret = c.wc_ed25519_make_key(rng.rng, c.ED25519_KEY_SIZE, key);
            if (ret != 0) return errors.mapCryptoError(ret);
            return .{ .key = key };
        }

        pub fn deinit(self: *KeyPair) void {
            _ = c.wc_ed25519_delete(self.key, null);
        }

        /// Sign a message.
        pub fn sign(self: *KeyPair, msg: []const u8) ![SIGNATURE_SIZE]u8 {
            var sig: [SIGNATURE_SIZE]u8 = undefined;
            var sig_len: c.word32 = SIGNATURE_SIZE;
            const ret = c.wc_ed25519_sign_msg(msg.ptr, @intCast(msg.len), &sig, &sig_len, self.key);
            if (ret != 0) return errors.mapCryptoError(ret);
            return sig;
        }

        /// Export the public key bytes.
        pub fn publicKey(self: *KeyPair) !PublicKey {
            var pk: PublicKey = undefined;
            var pk_len: c.word32 = PUBLIC_KEY_SIZE;
            const ret = c.wc_ed25519_export_public(self.key, &pk.bytes, &pk_len);
            if (ret != 0) return errors.mapCryptoError(ret);
            return pk;
        }
    };
};

test "Ed25519 sign/verify" {
    var rng = try random.SecureRng.init();
    defer rng.deinit();

    var kp = try Ed25519.KeyPair.generate(&rng);
    defer kp.deinit();

    const msg = "Ed25519 test message from Zig!";
    const sig = try kp.sign(msg);

    const pk = try kp.publicKey();
    const valid = try pk.verify(msg, &sig);
    try std.testing.expect(valid);

    // Wrong message should fail
    const invalid = try pk.verify("wrong message", &sig);
    try std.testing.expect(!invalid);
}

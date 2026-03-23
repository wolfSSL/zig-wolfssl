const std = @import("std");
const c = @import("../c.zig").c;
const errors = @import("../errors.zig");
const random = @import("../random.zig");
const opaque_alloc = @import("../opaque_alloc.zig");

// Ed448 uses opaque_alloc + manual init/free because wolfSSL does not provide
// wc_ed448_new/wc_ed448_delete allocation functions (unlike Ed25519 which has
// wc_ed25519_new/wc_ed25519_delete). This requires the sizeof_helpers.c shim.
pub const Ed448 = struct {
    pub const PUBLIC_KEY_SIZE = c.ED448_PUB_KEY_SIZE;
    pub const SECRET_KEY_SIZE = c.ED448_KEY_SIZE;
    pub const SIGNATURE_SIZE = c.ED448_SIG_SIZE;

    pub const PublicKey = struct {
        bytes: [PUBLIC_KEY_SIZE]u8,

        /// Verify an Ed448 signature.
        /// Note: allocates a temporary key handle per call for stateless verification.
        /// For batch verification of many signatures with the same key, consider
        /// caching at the call site.
        pub fn verify(self: *const PublicKey, msg: []const u8, sig: *const [SIGNATURE_SIZE]u8) !bool {
            const key = try opaque_alloc.allocEd448();
            defer {
                c.wc_ed448_free(key);
                opaque_alloc.freeEd448(key);
            }

            var ret = c.wc_ed448_init(key);
            if (ret != 0) return errors.mapCryptoError(ret);

            ret = c.wc_ed448_import_public(&self.bytes, PUBLIC_KEY_SIZE, key);
            if (ret != 0) return errors.mapCryptoError(ret);

            var stat: c_int = 0;
            ret = c.wc_ed448_verify_msg(sig, SIGNATURE_SIZE, msg.ptr, @intCast(msg.len), &stat, key, null, 0);
            if (ret != 0) {
                if (errors.isBadSignatureError(ret)) return false;
                return errors.mapCryptoError(ret);
            }
            return stat == 1;
        }
    };

    pub const KeyPair = struct {
        key: *c.ed448_key,

        pub fn generate(rng: *random.SecureRng) !KeyPair {
            const key = try opaque_alloc.allocEd448();
            errdefer opaque_alloc.freeEd448(key);

            var ret = c.wc_ed448_init(key);
            if (ret != 0) return errors.mapCryptoError(ret);
            errdefer c.wc_ed448_free(key);

            ret = c.wc_ed448_make_key(rng.rng, c.ED448_KEY_SIZE, key);
            if (ret != 0) return errors.mapCryptoError(ret);
            return .{ .key = key };
        }

        pub fn deinit(self: *KeyPair) void {
            c.wc_ed448_free(self.key);
            opaque_alloc.freeEd448(self.key);
        }

        pub fn sign(self: *KeyPair, msg: []const u8) ![SIGNATURE_SIZE]u8 {
            var sig: [SIGNATURE_SIZE]u8 = undefined;
            var sig_len: c.word32 = SIGNATURE_SIZE;
            const ret = c.wc_ed448_sign_msg(msg.ptr, @intCast(msg.len), &sig, &sig_len, self.key, null, 0);
            if (ret != 0) return errors.mapCryptoError(ret);
            return sig;
        }

        pub fn publicKey(self: *KeyPair) !PublicKey {
            var pk: PublicKey = undefined;
            var pk_len: c.word32 = PUBLIC_KEY_SIZE;
            const ret = c.wc_ed448_export_public(self.key, &pk.bytes, &pk_len);
            if (ret != 0) return errors.mapCryptoError(ret);
            return pk;
        }
    };
};

test "Ed448 sign/verify" {
    var rng = try random.SecureRng.init();
    defer rng.deinit();

    var kp = try Ed448.KeyPair.generate(&rng);
    defer kp.deinit();

    const msg = "Ed448 test message from Zig!";
    const sig = try kp.sign(msg);

    const pk = try kp.publicKey();
    const valid = try pk.verify(msg, &sig);
    try std.testing.expect(valid);

    const invalid = try pk.verify("wrong message", &sig);
    try std.testing.expect(!invalid);
}

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
        /// Returns error.AuthenticationFailed if the signature does not match.
        pub fn verify(self: *const PublicKey, msg: []const u8, sig: *const [SIGNATURE_SIZE]u8) !void {
            const key = c.wc_ed25519_new(null, c.INVALID_DEVID, null) orelse return error.OutOfMemory;
            defer _ = c.wc_ed25519_delete(key, null);

            var ret = c.wc_ed25519_import_public(&self.bytes, PUBLIC_KEY_SIZE, key);
            if (ret != 0) return errors.mapCryptoError(ret);

            var stat: c_int = 0;
            ret = c.wc_ed25519_verify_msg(sig, SIGNATURE_SIZE, msg.ptr, @intCast(msg.len), &stat, key);
            if (ret != 0) {
                if (errors.isBadSignatureError(ret)) return error.AuthenticationFailed;
                return errors.mapCryptoError(ret);
            }
            if (stat != 1) return error.AuthenticationFailed;
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
            // wc_ed25519_delete calls wc_ed25519_free internally, which calls
            // ForceZero(key, sizeof(ed25519_key)) — verified in wolfcrypt/src/ed25519.c:1115.
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

        /// Export the private key seed (32 bytes).
        /// wc_ed25519_export_private_only returns only the 32-byte seed,
        /// not the concatenated private+public form.
        pub fn exportPrivate(self: *KeyPair) ![SECRET_KEY_SIZE]u8 {
            var out: [SECRET_KEY_SIZE]u8 = undefined;
            var out_len: c.word32 = SECRET_KEY_SIZE;
            const ret = c.wc_ed25519_export_private_only(self.key, &out, &out_len);
            if (ret != 0) return errors.mapCryptoError(ret);
            return out;
        }
    };
};

// RFC 8032 §6.1 TEST 1 known-answer test.
// Private key seed, public key, and expected signature are taken from the RFC.
// Expected signature independently verified with Python pyca/cryptography.
// A deterministic Ed25519 implementation must produce this exact 64-byte signature.
test "Ed25519 RFC 8032 §6.1 TEST 1 KAT" {
    const priv_seed = [32]u8{
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
        0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
        0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
        0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
    };
    const pub_key_bytes = [32]u8{
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
        0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
        0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
        0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
    };
    const expected_sig = [Ed25519.SIGNATURE_SIZE]u8{
        0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72,
        0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82, 0x8a,
        0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74,
        0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49, 0x01, 0x55,
        0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac,
        0xc6, 0x1e, 0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b,
        0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24,
        0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b,
    };
    const msg = "";

    // Import the known private+public key pair using C functions directly.
    // wc_ed25519_import_private_key takes: private seed (32B), public key (32B).
    const c_key = c.wc_ed25519_new(null, c.INVALID_DEVID, null) orelse return error.OutOfMemory;
    defer _ = c.wc_ed25519_delete(c_key, null);
    {
        const ret = c.wc_ed25519_import_private_key(
            &priv_seed, Ed25519.SECRET_KEY_SIZE,
            &pub_key_bytes, Ed25519.PUBLIC_KEY_SIZE,
            c_key,
        );
        if (ret != 0) return errors.mapCryptoError(ret);
    }

    // Sign via the Zig API (borrowed KeyPair — do NOT call .deinit())
    var kp = Ed25519.KeyPair{ .key = c_key };
    const sig = try kp.sign(msg);
    try std.testing.expectEqualSlices(u8, &expected_sig, &sig);

    // Verify that the known public key also accepts this signature
    const pk = Ed25519.PublicKey{ .bytes = pub_key_bytes };
    try pk.verify(msg, &sig);

    // Wrong message must not verify
    try std.testing.expectError(error.AuthenticationFailed, pk.verify("wrong", &sig));
}

test "Ed25519 sign/verify" {
    var rng = try random.SecureRng.init();
    defer rng.deinit();

    var kp = try Ed25519.KeyPair.generate(&rng);
    defer kp.deinit();

    const msg = "Ed25519 test message from Zig!";
    const sig = try kp.sign(msg);

    const pk = try kp.publicKey();
    try pk.verify(msg, &sig);

    // Wrong message should fail
    try std.testing.expectError(error.AuthenticationFailed, pk.verify("wrong message", &sig));
}

// Ed25519 private key export KAT: re-uses the RFC 8032 §6.1 TEST 1 key.
// Imports the known seed+public key, exports the private seed, and confirms
// the exported bytes match the original input. Independent oracle: RFC 8032.
test "Ed25519 exportPrivate KAT" {
    const priv_seed = [Ed25519.SECRET_KEY_SIZE]u8{
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
        0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
        0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
        0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
    };
    const pub_key_bytes = [Ed25519.PUBLIC_KEY_SIZE]u8{
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
        0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
        0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
        0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
    };

    const c_key = c.wc_ed25519_new(null, c.INVALID_DEVID, null) orelse return error.OutOfMemory;
    defer _ = c.wc_ed25519_delete(c_key, null);
    {
        const ret = c.wc_ed25519_import_private_key(
            &priv_seed, Ed25519.SECRET_KEY_SIZE,
            &pub_key_bytes, Ed25519.PUBLIC_KEY_SIZE,
            c_key,
        );
        if (ret != 0) return errors.mapCryptoError(ret);
    }

    var kp = Ed25519.KeyPair{ .key = c_key };
    const exported = try kp.exportPrivate();
    try std.testing.expectEqualSlices(u8, &priv_seed, &exported);
}

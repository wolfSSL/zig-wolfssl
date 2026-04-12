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
        /// Returns error.AuthenticationFailed if the signature does not match.
        pub fn verify(self: *const PublicKey, msg: []const u8, sig: *const [SIGNATURE_SIZE]u8) !void {
            const key = try opaque_alloc.allocEd448();
            // wc_ed448_free must only be called if wc_ed448_init succeeded.
            // Calling wc_ed448_free on a partially-initialized struct is unsafe.
            // Use an init_ok flag rather than a plain defer so we can guard the free.
            // (Compare: KeyPair.generate uses errdefer registered after init — that
            //  pattern works for generation but not for the alloc+init+use+free flow here.)
            var ed_initialized = false;
            defer {
                if (ed_initialized) c.wc_ed448_free(key);
                opaque_alloc.freeEd448(key);
            }

            var ret = c.wc_ed448_init(key);
            if (ret != 0) return errors.mapCryptoError(ret);
            ed_initialized = true;

            ret = c.wc_ed448_import_public(&self.bytes, PUBLIC_KEY_SIZE, key);
            if (ret != 0) return errors.mapCryptoError(ret);

            var stat: c_int = 0;
            ret = c.wc_ed448_verify_msg(sig, SIGNATURE_SIZE, msg.ptr, @intCast(msg.len), &stat, key, null, 0);
            if (ret != 0) {
                if (errors.isBadSignatureError(ret)) return error.AuthenticationFailed;
                return errors.mapCryptoError(ret);
            }
            if (stat != 1) return error.AuthenticationFailed;
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

        /// Export the private key seed (57 bytes).
        /// wc_ed448_export_private_only returns only the seed,
        /// not the concatenated private+public form.
        pub fn exportPrivate(self: *KeyPair) ![SECRET_KEY_SIZE]u8 {
            var out: [SECRET_KEY_SIZE]u8 = undefined;
            var out_len: c.word32 = SECRET_KEY_SIZE;
            const ret = c.wc_ed448_export_private_only(self.key, &out, &out_len);
            if (ret != 0) return errors.mapCryptoError(ret);
            return out;
        }
    };
};

// RFC 8032 §6.3 TEST 1 known-answer test.
// Private key, public key, and signature independently verified with
// Python pyca/cryptography. A correct Ed448 implementation must produce
// this exact 114-byte signature for the empty message.
test "Ed448 RFC 8032 §6.3 TEST 1 KAT" {
    const priv_seed = [Ed448.SECRET_KEY_SIZE]u8{
        0x6c, 0x82, 0xa5, 0x62, 0xcb, 0x80, 0x8d, 0x10,
        0xd6, 0x32, 0xbe, 0x89, 0xc8, 0x51, 0x3e, 0xbf,
        0x6c, 0x92, 0x9f, 0x34, 0xdd, 0xfa, 0x8c, 0x9f,
        0x63, 0xc9, 0x96, 0x0e, 0xf6, 0xe3, 0x48, 0xa3,
        0x52, 0x8c, 0x8a, 0x3f, 0xcc, 0x2f, 0x04, 0x4e,
        0x39, 0xa3, 0xfc, 0x5b, 0x94, 0x49, 0x2f, 0x8f,
        0x03, 0x2e, 0x75, 0x49, 0xa2, 0x00, 0x98, 0xf9,
        0x5b,
    };
    const pub_key_bytes = [Ed448.PUBLIC_KEY_SIZE]u8{
        0x5f, 0xd7, 0x44, 0x9b, 0x59, 0xb4, 0x61, 0xfd,
        0x2c, 0xe7, 0x87, 0xec, 0x61, 0x6a, 0xd4, 0x6a,
        0x1d, 0xa1, 0x34, 0x24, 0x85, 0xa7, 0x0e, 0x1f,
        0x8a, 0x0e, 0xa7, 0x5d, 0x80, 0xe9, 0x67, 0x78,
        0xed, 0xf1, 0x24, 0x76, 0x9b, 0x46, 0xc7, 0x06,
        0x1b, 0xd6, 0x78, 0x3d, 0xf1, 0xe5, 0x0f, 0x6c,
        0xd1, 0xfa, 0x1a, 0xbe, 0xaf, 0xe8, 0x25, 0x61,
        0x80,
    };
    const expected_sig = [Ed448.SIGNATURE_SIZE]u8{
        0x53, 0x3a, 0x37, 0xf6, 0xbb, 0xe4, 0x57, 0x25,
        0x1f, 0x02, 0x3c, 0x0d, 0x88, 0xf9, 0x76, 0xae,
        0x2d, 0xfb, 0x50, 0x4a, 0x84, 0x3e, 0x34, 0xd2,
        0x07, 0x4f, 0xd8, 0x23, 0xd4, 0x1a, 0x59, 0x1f,
        0x2b, 0x23, 0x3f, 0x03, 0x4f, 0x62, 0x82, 0x81,
        0xf2, 0xfd, 0x7a, 0x22, 0xdd, 0xd4, 0x7d, 0x78,
        0x28, 0xc5, 0x9b, 0xd0, 0xa2, 0x1b, 0xfd, 0x39,
        0x80, 0xff, 0x0d, 0x20, 0x28, 0xd4, 0xb1, 0x8a,
        0x9d, 0xf6, 0x3e, 0x00, 0x6c, 0x5d, 0x1c, 0x2d,
        0x34, 0x5b, 0x92, 0x5d, 0x8d, 0xc0, 0x0b, 0x41,
        0x04, 0x85, 0x2d, 0xb9, 0x9a, 0xc5, 0xc7, 0xcd,
        0xda, 0x85, 0x30, 0xa1, 0x13, 0xa0, 0xf4, 0xdb,
        0xb6, 0x11, 0x49, 0xf0, 0x5a, 0x73, 0x63, 0x26,
        0x8c, 0x71, 0xd9, 0x58, 0x08, 0xff, 0x2e, 0x65,
        0x26, 0x00,
    };
    const msg = "";

    // Import the known private+public key pair using C functions directly.
    // Ed448 uses opaque_alloc instead of wc_ed448_new (which doesn't exist).
    const c_key = try opaque_alloc.allocEd448();
    defer {
        c.wc_ed448_free(c_key);
        opaque_alloc.freeEd448(c_key);
    }
    {
        var ret = c.wc_ed448_init(c_key);
        if (ret != 0) return errors.mapCryptoError(ret);
        ret = c.wc_ed448_import_private_key(
            &priv_seed, Ed448.SECRET_KEY_SIZE,
            &pub_key_bytes, Ed448.PUBLIC_KEY_SIZE,
            c_key,
        );
        if (ret != 0) return errors.mapCryptoError(ret);
    }

    // Sign via the Zig API (borrowed KeyPair — do NOT call .deinit())
    var kp = Ed448.KeyPair{ .key = c_key };
    const sig = try kp.sign(msg);
    try std.testing.expectEqualSlices(u8, &expected_sig, &sig);

    // Verify via the Zig PublicKey path
    const pk = Ed448.PublicKey{ .bytes = pub_key_bytes };
    try pk.verify(msg, &sig);

    try std.testing.expectError(error.AuthenticationFailed, pk.verify("wrong", &sig));
}

test "Ed448 sign/verify" {
    var rng = try random.SecureRng.init();
    defer rng.deinit();

    var kp = try Ed448.KeyPair.generate(&rng);
    defer kp.deinit();

    const msg = "Ed448 test message from Zig!";
    const sig = try kp.sign(msg);

    const pk = try kp.publicKey();
    try pk.verify(msg, &sig);

    try std.testing.expectError(error.AuthenticationFailed, pk.verify("wrong message", &sig));
}

// Ed448 private key export KAT: re-uses the RFC 8032 §6.3 TEST 1 key.
// Imports the known seed+public key, exports the private seed, and confirms
// the exported bytes match the original input. Independent oracle: RFC 8032.
test "Ed448 exportPrivate KAT" {
    const priv_seed = [Ed448.SECRET_KEY_SIZE]u8{
        0x6c, 0x82, 0xa5, 0x62, 0xcb, 0x80, 0x8d, 0x10,
        0xd6, 0x32, 0xbe, 0x89, 0xc8, 0x51, 0x3e, 0xbf,
        0x6c, 0x92, 0x9f, 0x34, 0xdd, 0xfa, 0x8c, 0x9f,
        0x63, 0xc9, 0x96, 0x0e, 0xf6, 0xe3, 0x48, 0xa3,
        0x52, 0x8c, 0x8a, 0x3f, 0xcc, 0x2f, 0x04, 0x4e,
        0x39, 0xa3, 0xfc, 0x5b, 0x94, 0x49, 0x2f, 0x8f,
        0x03, 0x2e, 0x75, 0x49, 0xa2, 0x00, 0x98, 0xf9,
        0x5b,
    };
    const pub_key_bytes = [Ed448.PUBLIC_KEY_SIZE]u8{
        0x5f, 0xd7, 0x44, 0x9b, 0x59, 0xb4, 0x61, 0xfd,
        0x2c, 0xe7, 0x87, 0xec, 0x61, 0x6a, 0xd4, 0x6a,
        0x1d, 0xa1, 0x34, 0x24, 0x85, 0xa7, 0x0e, 0x1f,
        0x8a, 0x0e, 0xa7, 0x5d, 0x80, 0xe9, 0x67, 0x78,
        0xed, 0xf1, 0x24, 0x76, 0x9b, 0x46, 0xc7, 0x06,
        0x1b, 0xd6, 0x78, 0x3d, 0xf1, 0xe5, 0x0f, 0x6c,
        0xd1, 0xfa, 0x1a, 0xbe, 0xaf, 0xe8, 0x25, 0x61,
        0x80,
    };

    const c_key = try opaque_alloc.allocEd448();
    defer {
        c.wc_ed448_free(c_key);
        opaque_alloc.freeEd448(c_key);
    }
    {
        var ret = c.wc_ed448_init(c_key);
        if (ret != 0) return errors.mapCryptoError(ret);
        ret = c.wc_ed448_import_private_key(
            &priv_seed, Ed448.SECRET_KEY_SIZE,
            &pub_key_bytes, Ed448.PUBLIC_KEY_SIZE,
            c_key,
        );
        if (ret != 0) return errors.mapCryptoError(ret);
    }

    var kp = Ed448.KeyPair{ .key = c_key };
    const exported = try kp.exportPrivate();
    try std.testing.expectEqualSlices(u8, &priv_seed, &exported);
}

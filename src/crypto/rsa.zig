const std = @import("std");
const c = @import("../c.zig").c;
const errors = @import("../errors.zig");
const random = @import("../random.zig");

/// RSA key pair for signing, verification, encryption, and decryption.
pub const RsaKeyPair = struct {
    key: *c.RsaKey,

    /// Generate a new RSA key pair of the given bit size (e.g., 2048, 4096).
    pub fn generate(rng: *random.SecureRng, bits: u32) !RsaKeyPair {
        const key = c.wc_NewRsaKey(null, c.INVALID_DEVID, null) orelse return error.OutOfMemory;
        errdefer _ = c.wc_DeleteRsaKey(key, null);

        var ret = c.wc_MakeRsaKey(key, @intCast(bits), c.WC_RSA_EXPONENT, rng.rng);
        if (ret != 0) return errors.mapCryptoError(ret);

        // Associate RNG with key for operations that need blinding (e.g. decrypt)
        ret = c.wc_RsaSetRNG(key, rng.rng);
        if (ret != 0) return errors.mapCryptoError(ret);

        return .{ .key = key };
    }

    /// Import an RSA private key from DER encoding.
    pub fn fromDer(der: []const u8) !RsaKeyPair {
        const key = c.wc_NewRsaKey(null, c.INVALID_DEVID, null) orelse return error.OutOfMemory;
        errdefer _ = c.wc_DeleteRsaKey(key, null);

        var idx: c.word32 = 0;
        const ret = c.wc_RsaPrivateKeyDecode(der.ptr, &idx, key, @intCast(der.len));
        if (ret != 0) return errors.mapCryptoError(ret);
        return .{ .key = key };
    }

    /// Associate an RNG with this key (needed for decrypt/sign blinding).
    pub fn setRng(self: *RsaKeyPair, rng: *random.SecureRng) !void {
        const ret = c.wc_RsaSetRNG(self.key, rng.rng);
        if (ret != 0) return errors.mapCryptoError(ret);
    }

    pub fn deinit(self: *RsaKeyPair) void {
        _ = c.wc_DeleteRsaKey(self.key, null);
    }

    /// Sign a message hash with PKCS#1 v1.5.
    /// Returns a slice of `out` containing the signature.
    pub fn sign(self: *RsaKeyPair, msg_hash: []const u8, out: []u8, rng: *random.SecureRng) ![]u8 {
        const ret = c.wc_RsaSSL_Sign(
            msg_hash.ptr,
            @intCast(msg_hash.len),
            out.ptr,
            @intCast(out.len),
            self.key,
            rng.rng,
        );
        if (ret < 0) return errors.mapCryptoError(ret);
        return out[0..@intCast(ret)];
    }

    /// Decrypt ciphertext with RSA private key.
    /// Returns a slice of `out` containing the plaintext.
    pub fn decrypt(self: *RsaKeyPair, ciphertext: []const u8, out: []u8) ![]u8 {
        const ret = c.wc_RsaPrivateDecrypt(
            ciphertext.ptr,
            @intCast(ciphertext.len),
            out.ptr,
            @intCast(out.len),
            self.key,
        );
        if (ret < 0) return errors.mapCryptoError(ret);
        return out[0..@intCast(ret)];
    }

    /// Get the RSA key size in bytes.
    pub fn size(self: *RsaKeyPair) usize {
        const s = c.wc_RsaEncryptSize(self.key);
        return if (s < 0) 0 else @intCast(s);
    }

    /// Get a public-key-only view (borrows the key).
    pub fn publicKey(self: *RsaKeyPair) RsaPublicKey {
        return .{ .key = self.key };
    }
};

/// Read-only view of an RSA public key (borrowed from a RsaKeyPair).
pub const RsaPublicKey = struct {
    key: *c.RsaKey,

    /// Verify a PKCS#1 v1.5 signature.
    /// Supports RSA keys up to 4096 bits. Returns `error.BufferTooSmall`
    /// for larger keys (e.g., RSA-8192).
    pub fn verify(self: RsaPublicKey, msg_hash: []const u8, signature: []const u8) !bool {
        // Stack buffer for decoded hash. 512 bytes supports RSA up to 4096 bits.
        // A runtime check rejects keys larger than the buffer rather than
        // silently overflowing (e.g. RSA-8192 would need 1024 bytes).
        var out: [512]u8 = undefined;

        const key_size = c.wc_RsaEncryptSize(self.key);
        if (key_size < 0) return errors.mapCryptoError(key_size);
        if (@as(usize, @intCast(key_size)) > out.len) return error.BufferTooSmall;
        const ret = c.wc_RsaSSL_Verify(
            signature.ptr,
            @intCast(signature.len),
            &out,
            @intCast(out.len),
            self.key,
        );
        if (ret < 0) return errors.mapCryptoError(ret);
        const verified_hash = out[0..@intCast(ret)];
        return std.mem.eql(u8, msg_hash, verified_hash);
    }

    /// Encrypt plaintext with RSA public key.
    /// Returns a slice of `out` containing the ciphertext.
    pub fn encrypt(self: RsaPublicKey, plaintext: []const u8, out: []u8, rng: *random.SecureRng) ![]u8 {
        const ret = c.wc_RsaPublicEncrypt(
            plaintext.ptr,
            @intCast(plaintext.len),
            out.ptr,
            @intCast(out.len),
            self.key,
            rng.rng,
        );
        if (ret < 0) return errors.mapCryptoError(ret);
        return out[0..@intCast(ret)];
    }
};

test "RSA generate, sign, verify" {
    var rng = try random.SecureRng.init();
    defer rng.deinit();

    var kp = try RsaKeyPair.generate(&rng, 2048);
    defer kp.deinit();

    // Hash a message
    const msg_hash = [_]u8{0xab} ** 32; // pretend SHA-256 hash

    var sig_buf: [256]u8 = undefined;
    const sig = try kp.sign(&msg_hash, &sig_buf, &rng);

    const pub_key = kp.publicKey();
    const valid = try pub_key.verify(&msg_hash, sig);
    try std.testing.expect(valid);

    // Tamper with hash -> should not verify
    var bad_hash = msg_hash;
    bad_hash[0] ^= 0xff;
    const invalid = try pub_key.verify(&bad_hash, sig);
    try std.testing.expect(!invalid);
}

test "RSA encrypt/decrypt" {
    var rng = try random.SecureRng.init();
    defer rng.deinit();

    var kp = try RsaKeyPair.generate(&rng, 2048);
    defer kp.deinit();

    const plaintext = "hello RSA";
    const pub_key = kp.publicKey();
    var ct_buf: [256]u8 = undefined;
    const ct = try pub_key.encrypt(plaintext, &ct_buf, &rng);

    var pt_buf: [256]u8 = undefined;
    const pt = try kp.decrypt(ct, &pt_buf);
    try std.testing.expectEqualSlices(u8, plaintext, pt);
}

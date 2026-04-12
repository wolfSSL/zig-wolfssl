const std = @import("std");
const c = @import("../c.zig").c;
const errors = @import("../errors.zig");

/// AES-GCM authenticated encryption.
pub const AesGcm = struct {
    aes: *c.Aes,

    pub fn init(key: []const u8) !AesGcm {
        const aes = c.wc_AesNew(null, c.INVALID_DEVID, null) orelse return error.OutOfMemory;
        errdefer _ = c.wc_AesDelete(aes, null);
        const ret = c.wc_AesGcmSetKey(aes, key.ptr, @intCast(key.len));
        if (ret != 0) return errors.mapCryptoError(ret);
        return .{ .aes = aes };
    }

    pub fn deinit(self: *AesGcm) void {
        _ = c.wc_AesDelete(self.aes, null);
    }

    /// Encrypt plaintext with AES-GCM.
    pub fn encrypt(
        self: *AesGcm,
        plaintext: []const u8,
        nonce: *const [12]u8,
        aad: []const u8,
        ciphertext: []u8,
        tag: *[16]u8,
    ) !void {
        // debug.assert is a no-op in ReleaseFast; an undersized buffer would let
        // wc_AesGcmEncrypt write past the end of ciphertext. Return an error instead.
        if (ciphertext.len < plaintext.len) return error.BufferTooSmall;
        const ret = c.wc_AesGcmEncrypt(
            self.aes,
            ciphertext.ptr,
            plaintext.ptr,
            @intCast(plaintext.len),
            nonce,
            @intCast(nonce.len),
            tag,
            @intCast(tag.len),
            if (aad.len > 0) aad.ptr else null,
            @intCast(aad.len),
        );
        if (ret != 0) return errors.mapCryptoError(ret);
    }

    /// Decrypt ciphertext with AES-GCM. Returns error on authentication failure.
    pub fn decrypt(
        self: *AesGcm,
        ciphertext: []const u8,
        nonce: *const [12]u8,
        aad: []const u8,
        tag: *const [16]u8,
        plaintext: []u8,
    ) !void {
        // Same rationale as encrypt: debug.assert disappears in release builds.
        if (plaintext.len < ciphertext.len) return error.BufferTooSmall;
        const ret = c.wc_AesGcmDecrypt(
            self.aes,
            plaintext.ptr,
            ciphertext.ptr,
            @intCast(ciphertext.len),
            nonce,
            @intCast(nonce.len),
            tag,
            @intCast(tag.len),
            if (aad.len > 0) aad.ptr else null,
            @intCast(aad.len),
        );
        if (ret != 0) return errors.mapCryptoError(ret);
    }
};

test "AES-GCM round-trip" {
    const key = [_]u8{0x01} ** 32;
    var aes = try AesGcm.init(&key);
    defer aes.deinit();

    const plaintext = "Hello, wolfSSL from Zig!";
    const nonce = [_]u8{0xca} ** 12;
    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [16]u8 = undefined;

    try aes.encrypt(plaintext, &nonce, "", &ciphertext, &tag);

    // Ciphertext should differ from plaintext
    try std.testing.expect(!std.mem.eql(u8, plaintext, &ciphertext));

    var decrypted: [plaintext.len]u8 = undefined;
    try aes.decrypt(&ciphertext, &nonce, "", &tag, &decrypted);

    try std.testing.expectEqualSlices(u8, plaintext, &decrypted);
}

// NIST SP 800-38D Test Case 2: AES-128-GCM with 16-byte all-zero plaintext,
// empty AAD, all-zero key and nonce.
// Expected values independently verified with pyca/cryptography (Python).
// A correct implementation must produce the exact ciphertext and tag.
test "AES-128-GCM NIST SP 800-38D KAT" {
    const key = [_]u8{0x00} ** 16;
    const nonce = [_]u8{0x00} ** 12;
    const plaintext = [_]u8{0x00} ** 16;
    const expected_ct = [16]u8{
        0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92,
        0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78,
    };
    const expected_tag = [16]u8{
        0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd,
        0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf,
    };

    var aes = try AesGcm.init(&key);
    defer aes.deinit();

    var ct: [16]u8 = undefined;
    var tag: [16]u8 = undefined;
    try aes.encrypt(&plaintext, &nonce, "", &ct, &tag);

    try std.testing.expectEqualSlices(u8, &expected_ct, &ct);
    try std.testing.expectEqualSlices(u8, &expected_tag, &tag);

    // Decrypt and confirm round-trip
    var pt_out: [16]u8 = undefined;
    try aes.decrypt(&ct, &nonce, "", &tag, &pt_out);
    try std.testing.expectEqualSlices(u8, &plaintext, &pt_out);

    // Tampered tag must be rejected
    var bad_tag = expected_tag;
    bad_tag[0] ^= 0xff;
    const fail = aes.decrypt(&ct, &nonce, "", &bad_tag, &pt_out);
    try std.testing.expectError(errors.CryptoError.AesGcmAuth, fail);
}

test "AES-GCM authentication failure on tampered ciphertext" {
    const key = [_]u8{0x42} ** 16;
    var aes = try AesGcm.init(&key);
    defer aes.deinit();

    const plaintext = "secret data";
    const nonce = [_]u8{0xab} ** 12;
    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [16]u8 = undefined;

    try aes.encrypt(plaintext, &nonce, "", &ciphertext, &tag);

    // Tamper with ciphertext
    ciphertext[0] ^= 0xff;
    var decrypted: [plaintext.len]u8 = undefined;
    const result = aes.decrypt(&ciphertext, &nonce, "", &tag, &decrypted);
    try std.testing.expectError(errors.CryptoError.AesGcmAuth, result);
}

/// AES-CBC encryption. Stateless per message: key is stored, IV is passed on each call.
/// Input length must be a multiple of 16 (no built-in padding).
pub const AesCbcEncrypt = struct {
    aes: *c.Aes,
    key: [32]u8,
    key_len: usize,

    pub fn init(key: []const u8) !AesCbcEncrypt {
        // Reject invalid key sizes as a real error, not an assertion: debug.assert is
        // a no-op in ReleaseFast, and key.len > 32 would overflow the [32]u8 field.
        if (key.len != 16 and key.len != 24 and key.len != 32) return error.InvalidKeyLength;
        const aes = c.wc_AesNew(null, c.INVALID_DEVID, null) orelse return error.OutOfMemory;
        var self = AesCbcEncrypt{ .aes = aes, .key = undefined, .key_len = key.len };
        @memcpy(self.key[0..key.len], key);
        return self;
    }

    pub fn deinit(self: *AesCbcEncrypt) void {
        // Zero the stored key material before freeing — wc_AesDelete clears wolfSSL's
        // internal key schedule copy, but self.key (our plaintext copy used to reset
        // the IV each call) must be explicitly scrubbed.
        std.crypto.secureZero(u8, @as([]volatile u8, @volatileCast(&self.key)));
        _ = c.wc_AesDelete(self.aes, null);
    }

    /// Encrypt plaintext with the given IV. plaintext.len must be a multiple of 16.
    /// ciphertext must be at least plaintext.len bytes.
    pub fn encrypt(self: *AesCbcEncrypt, iv: *const [16]u8, plaintext: []const u8, ciphertext: []u8) !void {
        // Non-block-aligned input is a runtime error (e.g. caller forgot to pad).
        // Buffer undersize is also returned as an error; both would be UB in release
        // if left as debug.assert.
        if (plaintext.len % 16 != 0) return error.InvalidInputLength;
        if (ciphertext.len < plaintext.len) return error.BufferTooSmall;
        var ret = c.wc_AesSetKey(self.aes, &self.key, @intCast(self.key_len), iv, c.AES_ENCRYPTION);
        if (ret != 0) return errors.mapCryptoError(ret);
        ret = c.wc_AesCbcEncrypt(self.aes, ciphertext.ptr, plaintext.ptr, @intCast(plaintext.len));
        if (ret != 0) return errors.mapCryptoError(ret);
    }
};

/// AES-CBC decryption. Stateless per message: key is stored, IV is passed on each call.
/// Input length must be a multiple of 16 (no built-in padding).
pub const AesCbcDecrypt = struct {
    aes: *c.Aes,
    key: [32]u8,
    key_len: usize,

    pub fn init(key: []const u8) !AesCbcDecrypt {
        // Same guard as AesCbcEncrypt: reject invalid sizes as a real error.
        if (key.len != 16 and key.len != 24 and key.len != 32) return error.InvalidKeyLength;
        const aes = c.wc_AesNew(null, c.INVALID_DEVID, null) orelse return error.OutOfMemory;
        var self = AesCbcDecrypt{ .aes = aes, .key = undefined, .key_len = key.len };
        @memcpy(self.key[0..key.len], key);
        return self;
    }

    pub fn deinit(self: *AesCbcDecrypt) void {
        // Scrub the key copy before freeing — see AesCbcEncrypt.deinit for rationale.
        std.crypto.secureZero(u8, @as([]volatile u8, @volatileCast(&self.key)));
        _ = c.wc_AesDelete(self.aes, null);
    }

    /// Decrypt ciphertext with the given IV. ciphertext.len must be a multiple of 16.
    /// plaintext must be at least ciphertext.len bytes.
    pub fn decrypt(self: *AesCbcDecrypt, iv: *const [16]u8, ciphertext: []const u8, plaintext: []u8) !void {
        if (ciphertext.len % 16 != 0) return error.InvalidInputLength;
        if (plaintext.len < ciphertext.len) return error.BufferTooSmall;
        var ret = c.wc_AesSetKey(self.aes, &self.key, @intCast(self.key_len), iv, c.AES_DECRYPTION);
        if (ret != 0) return errors.mapCryptoError(ret);
        ret = c.wc_AesCbcDecrypt(self.aes, plaintext.ptr, ciphertext.ptr, @intCast(ciphertext.len));
        if (ret != 0) return errors.mapCryptoError(ret);
    }
};

// NIST SP 800-38A §F.2.1: AES-128-CBC encrypt, 4 blocks.
test "AES-128-CBC NIST SP 800-38A F.2.1 KAT" {
    const key = [16]u8{ 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    const iv = [16]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    const pt = [64]u8{
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
    };
    const expected_ct = [64]u8{
        0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
        0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2,
        0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16,
        0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09, 0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7,
    };

    var enc = try AesCbcEncrypt.init(&key);
    defer enc.deinit();
    var ct: [64]u8 = undefined;
    try enc.encrypt(&iv, &pt, &ct);
    try std.testing.expectEqualSlices(u8, &expected_ct, &ct);

    var dec = try AesCbcDecrypt.init(&key);
    defer dec.deinit();
    var pt_out: [64]u8 = undefined;
    try dec.decrypt(&iv, &ct, &pt_out);
    try std.testing.expectEqualSlices(u8, &pt, &pt_out);
}

// NIST SP 800-38A §F.2.5: AES-256-CBC encrypt, 4 blocks.
test "AES-256-CBC NIST SP 800-38A F.2.5 KAT" {
    const key = [32]u8{
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
    };
    const iv = [16]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    const pt = [64]u8{
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
    };
    const expected_ct = [64]u8{
        0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba, 0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b, 0xfb, 0xd6,
        0x9c, 0xfc, 0x4e, 0x96, 0x7e, 0xdb, 0x80, 0x8d, 0x67, 0x9f, 0x77, 0x7b, 0xc6, 0x70, 0x2c, 0x7d,
        0x39, 0xf2, 0x33, 0x69, 0xa9, 0xd9, 0xba, 0xcf, 0xa5, 0x30, 0xe2, 0x63, 0x04, 0x23, 0x14, 0x61,
        0xb2, 0xeb, 0x05, 0xe2, 0xc3, 0x9b, 0xe9, 0xfc, 0xda, 0x6c, 0x19, 0x07, 0x8c, 0x6a, 0x9d, 0x1b,
    };

    var enc = try AesCbcEncrypt.init(&key);
    defer enc.deinit();
    var ct: [64]u8 = undefined;
    try enc.encrypt(&iv, &pt, &ct);
    try std.testing.expectEqualSlices(u8, &expected_ct, &ct);

    var dec = try AesCbcDecrypt.init(&key);
    defer dec.deinit();
    var pt_out: [64]u8 = undefined;
    try dec.decrypt(&iv, &ct, &pt_out);
    try std.testing.expectEqualSlices(u8, &pt, &pt_out);
}

/// AES-CTR stream cipher. Key is stored; the nonce (initial counter block) is passed per call.
/// CTR mode is symmetric: the same operation encrypts and decrypts.
pub const AesCtr = struct {
    aes: *c.Aes,
    key: [32]u8,
    key_len: usize,

    pub fn init(key: []const u8) !AesCtr {
        // Same guard as AesCbcEncrypt: reject invalid sizes as a real error.
        if (key.len != 16 and key.len != 24 and key.len != 32) return error.InvalidKeyLength;
        const aes = c.wc_AesNew(null, c.INVALID_DEVID, null) orelse return error.OutOfMemory;
        var self = AesCtr{ .aes = aes, .key = undefined, .key_len = key.len };
        @memcpy(self.key[0..key.len], key);
        return self;
    }

    pub fn deinit(self: *AesCtr) void {
        // Scrub the key copy before freeing — see AesCbcEncrypt.deinit for rationale.
        std.crypto.secureZero(u8, @as([]volatile u8, @volatileCast(&self.key)));
        _ = c.wc_AesDelete(self.aes, null);
    }

    /// Encrypt (or decrypt) in with the given 16-byte initial counter block.
    /// CTR mode is symmetric: decryption is identical to encryption.
    /// out must be at least in.len bytes.
    pub fn encrypt(self: *AesCtr, nonce: *const [16]u8, in: []const u8, out: []u8) !void {
        if (out.len < in.len) return error.BufferTooSmall;
        var ret = c.wc_AesCtrSetKey(self.aes, &self.key, @intCast(self.key_len), nonce, c.AES_ENCRYPTION);
        if (ret != 0) return errors.mapCryptoError(ret);
        ret = c.wc_AesCtrEncrypt(self.aes, out.ptr, in.ptr, @intCast(in.len));
        if (ret != 0) return errors.mapCryptoError(ret);
    }

    pub const decrypt = encrypt;
};

// NIST SP 800-38A §F.5.3: AES-256-CTR encrypt, 4 blocks.
test "AES-256-CTR NIST SP 800-38A F.5.3 KAT" {
    const key = [32]u8{
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
    };
    const nonce = [16]u8{ 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff };
    const pt = [64]u8{
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
    };
    const expected_ct = [64]u8{
        0x60, 0x1e, 0xc3, 0x13, 0x77, 0x57, 0x89, 0xa5, 0xb7, 0xa7, 0xf5, 0x04, 0xbb, 0xf3, 0xd2, 0x28,
        0xf4, 0x43, 0xe3, 0xca, 0x4d, 0x62, 0xb5, 0x9a, 0xca, 0x84, 0xe9, 0x90, 0xca, 0xca, 0xf5, 0xc5,
        0x2b, 0x09, 0x30, 0xda, 0xa2, 0x3d, 0xe9, 0x4c, 0xe8, 0x70, 0x17, 0xba, 0x2d, 0x84, 0x98, 0x8d,
        0xdf, 0xc9, 0xc5, 0x8d, 0xb6, 0x7a, 0xad, 0xa6, 0x13, 0xc2, 0xdd, 0x08, 0x45, 0x79, 0x41, 0xa6,
    };

    var ctr = try AesCtr.init(&key);
    defer ctr.deinit();

    var ct: [64]u8 = undefined;
    try ctr.encrypt(&nonce, &pt, &ct);
    try std.testing.expectEqualSlices(u8, &expected_ct, &ct);

    var pt_out: [64]u8 = undefined;
    try ctr.encrypt(&nonce, &ct, &pt_out);
    try std.testing.expectEqualSlices(u8, &pt, &pt_out);
}

// NIST SP 800-38A §F.5.1: AES-128-CTR encrypt, 4 blocks.
test "AES-128-CTR NIST SP 800-38A F.5.1 KAT" {
    const key = [16]u8{ 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    const nonce = [16]u8{ 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff };
    const pt = [64]u8{
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
    };
    const expected_ct = [64]u8{
        0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26, 0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce,
        0x98, 0x06, 0xf6, 0x6b, 0x79, 0x70, 0xfd, 0xff, 0x86, 0x17, 0x18, 0x7b, 0xb9, 0xff, 0xfd, 0xff,
        0x5a, 0xe4, 0xdf, 0x3e, 0xdb, 0xd5, 0xd3, 0x5e, 0x5b, 0x4f, 0x09, 0x02, 0x0d, 0xb0, 0x3e, 0xab,
        0x1e, 0x03, 0x1d, 0xda, 0x2f, 0xbe, 0x03, 0xd1, 0x79, 0x21, 0x70, 0xa0, 0xf3, 0x00, 0x9c, 0xee,
    };

    var ctr = try AesCtr.init(&key);
    defer ctr.deinit();

    var ct: [64]u8 = undefined;
    try ctr.encrypt(&nonce, &pt, &ct);
    try std.testing.expectEqualSlices(u8, &expected_ct, &ct);

    // Decryption is identical to encryption in CTR mode
    var pt_out: [64]u8 = undefined;
    try ctr.encrypt(&nonce, &ct, &pt_out);
    try std.testing.expectEqualSlices(u8, &pt, &pt_out);
}

/// Streaming AES-GCM encryptor. Allows chunked plaintext and AAD.
/// Call update() one or more times, then final() to produce the authentication tag.
/// Requires wolfSSL built with WOLFSSL_AESGCM_STREAM.
pub const AesGcmEncryptor = struct {
    aes: *c.Aes,

    /// Initialize with key and 12-byte IV (nonce).
    pub fn init(key: []const u8, nonce: *const [12]u8) !AesGcmEncryptor {
        const aes = c.wc_AesNew(null, c.INVALID_DEVID, null) orelse return error.OutOfMemory;
        errdefer _ = c.wc_AesDelete(aes, null);
        const ret = c.wc_AesGcmEncryptInit(aes, key.ptr, @intCast(key.len), nonce, nonce.len);
        if (ret != 0) return errors.mapCryptoError(ret);
        return .{ .aes = aes };
    }

    pub fn deinit(self: *AesGcmEncryptor) void {
        _ = c.wc_AesDelete(self.aes, null);
    }

    /// Encrypt a chunk of plaintext and/or authenticate additional data.
    /// `ciphertext` must be at least `plaintext.len` bytes when plaintext is non-empty.
    /// AAD and plaintext may be passed in the same call or separate calls.
    pub fn update(self: *AesGcmEncryptor, ciphertext: []u8, plaintext: []const u8, aad: []const u8) !void {
        if (plaintext.len > 0 and ciphertext.len < plaintext.len) return error.BufferTooSmall;
        const ret = c.wc_AesGcmEncryptUpdate(
            self.aes,
            if (plaintext.len > 0) ciphertext.ptr else null,
            if (plaintext.len > 0) plaintext.ptr else null,
            @intCast(plaintext.len),
            if (aad.len > 0) aad.ptr else null,
            @intCast(aad.len),
        );
        if (ret != 0) return errors.mapCryptoError(ret);
    }

    /// Finalize and write the 16-byte authentication tag.
    pub fn final(self: *AesGcmEncryptor, tag: *[16]u8) !void {
        const ret = c.wc_AesGcmEncryptFinal(self.aes, tag, tag.len);
        if (ret != 0) return errors.mapCryptoError(ret);
    }
};

/// Streaming AES-GCM decryptor. Allows chunked ciphertext and AAD.
///
/// Usage: call update() one or more times, then final() to verify the tag.
///
/// WARNING: update() writes decrypted bytes before authentication is verified.
/// The decrypted output is NOT authenticated until final() returns successfully.
/// Pass all plaintext output buffers to final() so they can be zeroed on failure:
/// if final() returns error.AesGcmAuth, the plaintext is scrubbed before returning.
///
/// For messages that fit in memory, prefer AesGcm (one-shot), which never exposes
/// unauthenticated plaintext.
///
/// Requires wolfSSL built with WOLFSSL_AESGCM_STREAM.
pub const AesGcmDecryptor = struct {
    aes: *c.Aes,

    /// Initialize with key and 12-byte IV (nonce).
    pub fn init(key: []const u8, nonce: *const [12]u8) !AesGcmDecryptor {
        const aes = c.wc_AesNew(null, c.INVALID_DEVID, null) orelse return error.OutOfMemory;
        errdefer _ = c.wc_AesDelete(aes, null);
        const ret = c.wc_AesGcmDecryptInit(aes, key.ptr, @intCast(key.len), nonce, nonce.len);
        if (ret != 0) return errors.mapCryptoError(ret);
        return .{ .aes = aes };
    }

    pub fn deinit(self: *AesGcmDecryptor) void {
        _ = c.wc_AesDelete(self.aes, null);
    }

    /// Decrypt a chunk of ciphertext and/or authenticate additional data.
    /// `plaintext` must be at least `ciphertext.len` bytes when ciphertext is non-empty.
    /// Output is unauthenticated until final() returns successfully.
    pub fn update(self: *AesGcmDecryptor, plaintext: []u8, ciphertext: []const u8, aad: []const u8) !void {
        if (ciphertext.len > 0 and plaintext.len < ciphertext.len) return error.BufferTooSmall;
        const ret = c.wc_AesGcmDecryptUpdate(
            self.aes,
            if (ciphertext.len > 0) plaintext.ptr else null,
            if (ciphertext.len > 0) ciphertext.ptr else null,
            @intCast(ciphertext.len),
            if (aad.len > 0) aad.ptr else null,
            @intCast(aad.len),
        );
        if (ret != 0) return errors.mapCryptoError(ret);
    }

    /// Verify the authentication tag and scrub `plaintext` on failure.
    ///
    /// `plaintext` must be the complete buffer of all output written by update() calls.
    /// On success: the plaintext is authenticated and safe to use.
    /// On error.AesGcmAuth: `plaintext` is zeroed before returning so unauthenticated
    /// data cannot be used even if the caller ignores the error.
    pub fn final(self: *AesGcmDecryptor, plaintext: []u8, tag: *const [16]u8) !void {
        const ret = c.wc_AesGcmDecryptFinal(self.aes, tag, tag.len);
        if (ret != 0) {
            // Zero the plaintext before returning any error so the caller cannot
            // accidentally use unauthenticated data regardless of error handling.
            std.crypto.secureZero(u8, plaintext);
            return errors.mapCryptoError(ret);
        }
    }
};

// NIST SP 800-38D TC2: AES-128-GCM, empty AAD, 16-byte all-zero plaintext.
// Plaintext split into two 8-byte chunks to verify streaming works.
// Expected ciphertext and tag derived from the one-shot test above (same vectors).
test "AES-128-GCM streaming encrypt/decrypt NIST SP 800-38D KAT" {
    const key = [_]u8{0x00} ** 16;
    const nonce = [_]u8{0x00} ** 12;
    const plaintext = [_]u8{0x00} ** 16;
    const expected_ct = [16]u8{
        0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92,
        0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78,
    };
    const expected_tag = [16]u8{
        0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd,
        0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf,
    };

    // Streaming encrypt: two 8-byte chunks
    var enc = try AesGcmEncryptor.init(&key, &nonce);
    defer enc.deinit();
    var ct: [16]u8 = undefined;
    try enc.update(ct[0..8], plaintext[0..8], "");
    try enc.update(ct[8..16], plaintext[8..16], "");
    var tag: [16]u8 = undefined;
    try enc.final(&tag);

    try std.testing.expectEqualSlices(u8, &expected_ct, &ct);
    try std.testing.expectEqualSlices(u8, &expected_tag, &tag);

    // Streaming decrypt: two 8-byte chunks
    var dec = try AesGcmDecryptor.init(&key, &nonce);
    defer dec.deinit();
    var pt: [16]u8 = undefined;
    try dec.update(pt[0..8], ct[0..8], "");
    try dec.update(pt[8..16], ct[8..16], "");
    try dec.final(&pt, &tag);

    try std.testing.expectEqualSlices(u8, &plaintext, &pt);
}

test "AES-GCM streaming auth failure on tampered ciphertext" {
    const key = [_]u8{0x01} ** 16;
    const nonce = [_]u8{0x02} ** 12;
    const plaintext = "streaming test data!";

    var enc = try AesGcmEncryptor.init(&key, &nonce);
    defer enc.deinit();
    var ct: [plaintext.len]u8 = undefined;
    try enc.update(&ct, plaintext, "");
    var tag: [16]u8 = undefined;
    try enc.final(&tag);

    // Tamper with ciphertext
    ct[0] ^= 0xff;

    var dec = try AesGcmDecryptor.init(&key, &nonce);
    defer dec.deinit();
    var pt: [plaintext.len]u8 = undefined;
    // Fill pt so we can confirm final() zeros it on auth failure.
    @memset(&pt, 0xcd);
    try dec.update(&pt, &ct, "");
    try std.testing.expectError(errors.CryptoError.AesGcmAuth, dec.final(&pt, &tag));
    // final() must have zeroed pt to prevent use of unauthenticated plaintext.
    try std.testing.expect(std.mem.allEqual(u8, &pt, 0));
}

test "AES-GCM streaming with separate AAD and plaintext updates" {
    const key = [_]u8{0x42} ** 32;
    const nonce = [_]u8{0xab} ** 12;
    const aad = "additional data";
    const plaintext = "hello world!";

    // Encrypt: feed AAD then plaintext in separate calls
    var enc = try AesGcmEncryptor.init(&key, &nonce);
    defer enc.deinit();
    try enc.update("", "", aad); // AAD-only pass
    var ct: [plaintext.len]u8 = undefined;
    try enc.update(&ct, plaintext, ""); // plaintext-only pass
    var tag: [16]u8 = undefined;
    try enc.final(&tag);

    // Decrypt: same order
    var dec = try AesGcmDecryptor.init(&key, &nonce);
    defer dec.deinit();
    try dec.update("", "", aad);
    var pt: [plaintext.len]u8 = undefined;
    try dec.update(&pt, &ct, "");
    try dec.final(&pt, &tag);

    try std.testing.expectEqualSlices(u8, plaintext, &pt);
}

// Error path tests: confirm guards fire rather than silently passing bad input to wolfSSL.
// Without these, removing the guards would leave a fully green test suite.
test "AES-CBC/CTR error paths" {
    const good_key = [_]u8{0x01} ** 16;
    const iv = [_]u8{0x00} ** 16;
    var buf: [32]u8 = undefined;

    // InvalidKeyLength: key of wrong size must be rejected before any wolfSSL call.
    try std.testing.expectError(error.InvalidKeyLength, AesCbcEncrypt.init(&([_]u8{0x00} ** 15)));
    try std.testing.expectError(error.InvalidKeyLength, AesCbcDecrypt.init(&([_]u8{0x00} ** 15)));
    try std.testing.expectError(error.InvalidKeyLength, AesCtr.init(&([_]u8{0x00} ** 15)));

    // InvalidInputLength: CBC requires 16-byte-aligned plaintext.
    var enc = try AesCbcEncrypt.init(&good_key);
    defer enc.deinit();
    try std.testing.expectError(error.InvalidInputLength, enc.encrypt(&iv, "not-aligned", &buf));

    var dec = try AesCbcDecrypt.init(&good_key);
    defer dec.deinit();
    try std.testing.expectError(error.InvalidInputLength, dec.decrypt(&iv, "not-aligned", &buf));

    // BufferTooSmall: output buffer shorter than input.
    var tiny: [0]u8 = undefined;
    var ctr = try AesCtr.init(&good_key);
    defer ctr.deinit();
    const nonce = [_]u8{0x00} ** 16;
    try std.testing.expectError(error.BufferTooSmall, ctr.encrypt(&nonce, "x", &tiny));
}

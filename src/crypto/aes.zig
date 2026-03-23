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
        std.debug.assert(ciphertext.len >= plaintext.len);
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
        std.debug.assert(plaintext.len >= ciphertext.len);
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
    try std.testing.expectError(errors.CryptoError.Unexpected, result);
}

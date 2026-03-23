const std = @import("std");
const c = @import("../c.zig").c;
const errors = @import("../errors.zig");

/// ChaCha20-Poly1305 AEAD. Stateless — key and nonce passed per-call.
pub const ChaCha20Poly1305 = struct {
    /// Encrypt plaintext with ChaCha20-Poly1305.
    pub fn encrypt(
        key: *const [32]u8,
        nonce: *const [12]u8,
        aad: []const u8,
        plaintext: []const u8,
        ciphertext: []u8,
        tag: *[16]u8,
    ) !void {
        std.debug.assert(ciphertext.len >= plaintext.len);
        const ret = c.wc_ChaCha20Poly1305_Encrypt(
            key,
            nonce,
            if (aad.len > 0) aad.ptr else null,
            @intCast(aad.len),
            plaintext.ptr,
            @intCast(plaintext.len),
            ciphertext.ptr,
            tag,
        );
        if (ret != 0) return errors.mapCryptoError(ret);
    }

    /// Decrypt ciphertext with ChaCha20-Poly1305.
    pub fn decrypt(
        key: *const [32]u8,
        nonce: *const [12]u8,
        aad: []const u8,
        ciphertext: []const u8,
        tag: *const [16]u8,
        plaintext: []u8,
    ) !void {
        std.debug.assert(plaintext.len >= ciphertext.len);
        const ret = c.wc_ChaCha20Poly1305_Decrypt(
            key,
            nonce,
            if (aad.len > 0) aad.ptr else null,
            @intCast(aad.len),
            ciphertext.ptr,
            @intCast(ciphertext.len),
            tag,
            plaintext.ptr,
        );
        if (ret != 0) return errors.mapCryptoError(ret);
    }
};

test "ChaCha20-Poly1305 round-trip" {
    const key = [_]u8{0x55} ** 32;
    const nonce = [_]u8{0xaa} ** 12;
    const plaintext = "ChaCha20-Poly1305 test from Zig!";

    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [16]u8 = undefined;

    try ChaCha20Poly1305.encrypt(&key, &nonce, "", plaintext, &ciphertext, &tag);
    try std.testing.expect(!std.mem.eql(u8, plaintext, &ciphertext));

    var decrypted: [plaintext.len]u8 = undefined;
    try ChaCha20Poly1305.decrypt(&key, &nonce, "", &ciphertext, &tag, &decrypted);
    try std.testing.expectEqualSlices(u8, plaintext, &decrypted);
}

test "ChaCha20-Poly1305 with AAD" {
    const key = [_]u8{0x11} ** 32;
    const nonce = [_]u8{0x22} ** 12;
    const aad = "additional authenticated data";
    const plaintext = "secret";

    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [16]u8 = undefined;

    try ChaCha20Poly1305.encrypt(&key, &nonce, aad, plaintext, &ciphertext, &tag);

    var decrypted: [plaintext.len]u8 = undefined;
    try ChaCha20Poly1305.decrypt(&key, &nonce, aad, &ciphertext, &tag, &decrypted);
    try std.testing.expectEqualSlices(u8, plaintext, &decrypted);

    // Wrong AAD should fail
    const result = ChaCha20Poly1305.decrypt(&key, &nonce, "wrong aad", &ciphertext, &tag, &decrypted);
    try std.testing.expectError(errors.CryptoError.Unexpected, result);
}

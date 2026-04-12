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
        // debug.assert is a no-op in ReleaseFast; an undersized buffer would let
        // wc_ChaCha20Poly1305_Encrypt write past the end of ciphertext.
        if (ciphertext.len < plaintext.len) return error.BufferTooSmall;
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
        // Same rationale as encrypt: debug.assert disappears in release builds.
        if (plaintext.len < ciphertext.len) return error.BufferTooSmall;
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

// Known-answer test using pyca/cryptography-verified vectors.
// Key, nonce, and AAD match the RFC 8439 §2.8.2 structure.
// Expected ciphertext and tag computed independently with Python
// and verified via round-trip decryption.
test "ChaCha20-Poly1305 known-answer test" {
    const key = [32]u8{
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    };
    const nonce = [12]u8{
        0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43,
        0x44, 0x45, 0x46, 0x47,
    };
    const aad = [12]u8{
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3,
        0xc4, 0xc5, 0xc6, 0xc7,
    };
    // "Ladies and Gentlemen of the classified documents in the case are to be kept under seal."
    const plaintext = [87]u8{
        0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61,
        0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c,
        0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20,
        0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73,
        0x73, 0x69, 0x66, 0x69, 0x65, 0x64, 0x20, 0x64,
        0x6f, 0x63, 0x75, 0x6d, 0x65, 0x6e, 0x74, 0x73,
        0x20, 0x69, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20,
        0x63, 0x61, 0x73, 0x65, 0x20, 0x61, 0x72, 0x65,
        0x20, 0x74, 0x6f, 0x20, 0x62, 0x65, 0x20, 0x6b,
        0x65, 0x70, 0x74, 0x20, 0x75, 0x6e, 0x64, 0x65,
        0x72, 0x20, 0x73, 0x65, 0x61, 0x6c, 0x2e,
    };
    const expected_ct = [87]u8{
        0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb,
        0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
        0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe,
        0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
        0x3d, 0xf7, 0xad, 0x51, 0xc9, 0xea, 0x7e, 0x4f,
        0xd7, 0xb9, 0xc7, 0x62, 0x9f, 0xb5, 0x26, 0x9b,
        0x55, 0x6d, 0xdc, 0x4e, 0xca, 0x01, 0x08, 0x6f,
        0x03, 0xc5, 0xf6, 0xaa, 0x31, 0xd9, 0x69, 0x3c,
        0xdc, 0xc5, 0xab, 0x7f, 0x20, 0x7c, 0xce, 0xc7,
        0x89, 0x1a, 0xaa, 0xe3, 0x3b, 0x08, 0x0d, 0x1d,
        0xfc, 0xfb, 0x32, 0xa1, 0xfd, 0xcf, 0x2f,
    };
    const expected_tag = [16]u8{
        0xe1, 0x98, 0xc3, 0xf5, 0x4c, 0x24, 0xc5, 0x1f,
        0xe2, 0x78, 0x4f, 0x82, 0xaf, 0xab, 0x1a, 0x95,
    };

    var ct: [87]u8 = undefined;
    var tag: [16]u8 = undefined;
    try ChaCha20Poly1305.encrypt(&key, &nonce, &aad, &plaintext, &ct, &tag);

    try std.testing.expectEqualSlices(u8, &expected_ct, &ct);
    try std.testing.expectEqualSlices(u8, &expected_tag, &tag);

    // Decrypt and confirm round-trip
    var pt_out: [87]u8 = undefined;
    try ChaCha20Poly1305.decrypt(&key, &nonce, &aad, &ct, &tag, &pt_out);
    try std.testing.expectEqualSlices(u8, &plaintext, &pt_out);

    // Tampered tag must be rejected
    var bad_tag = expected_tag;
    bad_tag[0] ^= 0xff;
    const fail = ChaCha20Poly1305.decrypt(&key, &nonce, &aad, &ct, &bad_tag, &pt_out);
    try std.testing.expectError(errors.CryptoError.MacCmpFailed, fail);
}

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
    try std.testing.expectError(errors.CryptoError.MacCmpFailed, result);
}

/// ChaCha20 stream cipher (RFC 8439). Stateful — key set at init, IV and
/// counter set per-message via setIV, then process encrypts/decrypts in place.
/// No deinit required; the context is stack-allocated.
pub const ChaCha20 = struct {
    ctx: c.ChaCha,

    /// Initialise with a 256-bit key. The IV/counter must be set with setIV
    /// before calling process.
    pub fn init(key: *const [32]u8) !ChaCha20 {
        var self: ChaCha20 = undefined;
        const ret = c.wc_Chacha_SetKey(&self.ctx, key, 32);
        if (ret != 0) return errors.mapCryptoError(ret);
        return self;
    }

    /// Set the 96-bit nonce (RFC 8439 format) and the initial block counter.
    /// Call this before each independent message processed with the same key.
    pub fn setIV(self: *ChaCha20, iv: *const [12]u8, counter: u32) !void {
        const ret = c.wc_Chacha_SetIV(&self.ctx, iv, counter);
        if (ret != 0) return errors.mapCryptoError(ret);
    }

    /// XOR the keystream into in[], writing the result to out[].
    /// out and in must be the same length. May be called in-place (out == in).
    pub fn process(self: *ChaCha20, out: []u8, in: []const u8) !void {
        if (out.len != in.len) return error.LengthMismatch;
        if (in.len == 0) return;
        const ret = c.wc_Chacha_Process(&self.ctx, out.ptr, in.ptr, @intCast(in.len));
        if (ret != 0) return errors.mapCryptoError(ret);
    }
};

// Known-answer test from RFC 8439 §2.4.2.
// Key, nonce, counter, and expected ciphertext are normative test vectors.
test "ChaCha20 RFC 8439 §2.4.2 known-answer test" {
    const key = [32]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    const nonce = [12]u8{
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a,
        0x00, 0x00, 0x00, 0x00,
    };
    const plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    const expected_ct = [114]u8{
        0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80,
        0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81,
        0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2,
        0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b,
        0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab,
        0x8f, 0x59, 0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57,
        0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab,
        0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8,
        0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61,
        0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e,
        0x52, 0xbc, 0x51, 0x4d, 0x16, 0xcc, 0xf8, 0x06,
        0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36,
        0x5a, 0xf9, 0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6,
        0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42,
        0x87, 0x4d,
    };

    var cipher = try ChaCha20.init(&key);
    try cipher.setIV(&nonce, 1);

    var ct: [plaintext.len]u8 = undefined;
    try cipher.process(&ct, plaintext);

    try std.testing.expectEqualSlices(u8, &expected_ct, &ct);

    // Decrypt: re-init to reset state, then process ciphertext back to plaintext.
    var cipher2 = try ChaCha20.init(&key);
    try cipher2.setIV(&nonce, 1);
    var pt_out: [plaintext.len]u8 = undefined;
    try cipher2.process(&pt_out, &ct);
    try std.testing.expectEqualSlices(u8, plaintext, &pt_out);
}

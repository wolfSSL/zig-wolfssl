const std = @import("std");
const c = @import("../c.zig").c;
const errors = @import("../errors.zig");

/// AES-CMAC (NIST SP 800-38B). Stateless: key and message are passed per call.
pub const AesCmac = struct {
    /// CMAC output is always one AES block (16 bytes).
    pub const tag_length: usize = 16;

    /// Generate an AES-CMAC tag.
    ///
    /// key must be 16, 24, or 32 bytes (AES-128/192/256).
    /// The 16-byte tag is written to out.
    pub fn generate(key: []const u8, msg: []const u8, out: *[tag_length]u8) !void {
        if (key.len != 16 and key.len != 24 and key.len != 32) return error.InvalidKeyLength;
        var out_sz: c.word32 = tag_length;
        const ret = c.wc_AesCmacGenerate(
            out,
            &out_sz,
            if (msg.len > 0) msg.ptr else null,
            @intCast(msg.len),
            key.ptr,
            @intCast(key.len),
        );
        if (ret != 0) return errors.mapCryptoError(ret);
    }

    /// Verify an AES-CMAC tag. Returns error.AuthenticationFailed if the tag does not match.
    ///
    /// key must be 16, 24, or 32 bytes (AES-128/192/256).
    pub fn verify(key: []const u8, msg: []const u8, tag: *const [tag_length]u8) !void {
        if (key.len != 16 and key.len != 24 and key.len != 32) return error.InvalidKeyLength;
        const ret = c.wc_AesCmacVerify(
            tag,
            tag_length,
            if (msg.len > 0) msg.ptr else null,
            @intCast(msg.len),
            key.ptr,
            @intCast(key.len),
        );
        if (ret == 0) return;
        // wc_AesCmacVerify calls wc_AesCmacVerify_ex internally.
        // wc_AesCmacVerify_ex sets ret = (ConstantCompare(...) != 0) ? 1 : 0,
        // so ret=1 (positive) means auth mismatch; negative means operational error.
        // Source: wolfcrypt/src/cmac.c wc_AesCmacVerify_ex line ~498.
        if (ret == 1) return error.AuthenticationFailed;
        return errors.mapCryptoError(ret);
    }
};

// NIST SP 800-38B §D.1 Example 1: AES-128, empty message.
// Key  = 2b7e151628aed2a6abf7158809cf4f3c
// Mlen = 0, M = (empty)
// T    = bb1d6929e95937287fa37d129b756746
test "AES-CMAC NIST SP 800-38B Example 1 (AES-128, empty message)" {
    const key = [16]u8{
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    };
    const expected_tag = [AesCmac.tag_length]u8{
        0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28,
        0x7f, 0xa3, 0x7d, 0x12, 0x9b, 0x75, 0x67, 0x46,
    };

    var tag: [AesCmac.tag_length]u8 = undefined;
    try AesCmac.generate(&key, "", &tag);
    try std.testing.expectEqualSlices(u8, &expected_tag, &tag);

    try AesCmac.verify(&key, "", &expected_tag);
}

// NIST SP 800-38B §D.1 Example 2: AES-128, 16-byte message.
// Key  = 2b7e151628aed2a6abf7158809cf4f3c
// M    = 6bc1bee22e409f96e93d7e117393172a
// T    = 070a16b46b4d4144f79bdd9dd04a287c
test "AES-CMAC NIST SP 800-38B Example 2 (AES-128, 16-byte message)" {
    const key = [16]u8{
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    };
    const msg = [16]u8{
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    };
    const expected_tag = [AesCmac.tag_length]u8{
        0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44,
        0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a, 0x28, 0x7c,
    };

    var tag: [AesCmac.tag_length]u8 = undefined;
    try AesCmac.generate(&key, &msg, &tag);
    try std.testing.expectEqualSlices(u8, &expected_tag, &tag);

    try AesCmac.verify(&key, &msg, &expected_tag);
}

// NIST SP 800-38B §D.1 Example 3: AES-128, 40-byte message.
// Key  = 2b7e151628aed2a6abf7158809cf4f3c
// M    = 6bc1bee22e409f96e93d7e117393172a
//        ae2d8a571e03ac9c9eb76fac45af8e51
//        30c81c46a35ce411
// T    = dfa66747de9ae63030ca32611497c827
test "AES-CMAC NIST SP 800-38B Example 3 (AES-128, 40-byte message)" {
    const key = [16]u8{
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    };
    const msg = [40]u8{
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
    };
    const expected_tag = [AesCmac.tag_length]u8{
        0xdf, 0xa6, 0x67, 0x47, 0xde, 0x9a, 0xe6, 0x30,
        0x30, 0xca, 0x32, 0x61, 0x14, 0x97, 0xc8, 0x27,
    };

    var tag: [AesCmac.tag_length]u8 = undefined;
    try AesCmac.generate(&key, &msg, &tag);
    try std.testing.expectEqualSlices(u8, &expected_tag, &tag);

    try AesCmac.verify(&key, &msg, &expected_tag);
}

// Tampering detection: flipping one byte of the message must cause verify to return false.
test "AES-CMAC tamper detection" {
    const key = [16]u8{
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    };
    const msg = [16]u8{
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    };

    var tag: [AesCmac.tag_length]u8 = undefined;
    try AesCmac.generate(&key, &msg, &tag);

    // Flip one byte in the message; the original tag must no longer verify.
    var tampered = msg;
    tampered[0] ^= 0xff;
    try std.testing.expectError(error.AuthenticationFailed, AesCmac.verify(&key, &tampered, &tag));
}

// Key length guard: non-AES key sizes must be rejected before any wolfSSL call.
test "AES-CMAC invalid key length" {
    var tag: [AesCmac.tag_length]u8 = undefined;
    const bad_key = [_]u8{0x00} ** 15;
    try std.testing.expectError(error.InvalidKeyLength, AesCmac.generate(&bad_key, "", &tag));
    const dummy_tag = [_]u8{0x00} ** AesCmac.tag_length;
    try std.testing.expectError(error.InvalidKeyLength, AesCmac.verify(&bad_key, "", &dummy_tag));
}

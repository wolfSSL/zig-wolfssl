const std = @import("std");
const c = @import("../c.zig").c;
const errors = @import("../errors.zig");
const hash = @import("../crypto/hash.zig");

/// PBKDF1 (RFC 8018 §5.1) parameterized by hash algorithm.
///
/// RFC 8018 defines PBKDF1 only for MD2, MD5, and SHA-1. MD2 is not supported
/// by wolfSSL. Using SHA-1 is the standard choice; MD5 is provided for
/// compatibility but is not recommended.
///
/// PBKDF1 limits the derived key length to the hash output size (20 bytes for
/// SHA-1, 16 bytes for MD5). wolfSSL returns BAD_FUNC_ARG if kLen exceeds
/// the hash digest length.
pub fn Pbkdf1(comptime algo: hash.Algorithm) type {
    return struct {
        /// Derive a key using PBKDF1 (RFC 8018 §5.1).
        ///
        /// `out` must be ≤ the digest length of `algo` (e.g. 20 bytes for SHA-1).
        /// `iterations` must be ≥ 1.
        pub fn deriveKey(password: []const u8, salt: []const u8, iterations: u32, out: []u8) !void {
            const ret = c.wc_PBKDF1(
                out.ptr,
                password.ptr,
                @intCast(password.len),
                salt.ptr,
                @intCast(salt.len),
                @intCast(iterations),
                @intCast(out.len),
                hash.wcType(algo),
            );
            if (ret != 0) return errors.mapCryptoError(ret);
        }
    };
}

pub const Pbkdf1Sha1 = Pbkdf1(.sha1);
pub const Pbkdf1Md5 = Pbkdf1(.md5);

// PBKDF1-SHA-1 KAT from RFC 8018 (PKCS#5 v2.1) Appendix B.1.
// Password = "password" (ASCII), Salt = 0x78578E5A5D63CB06,
// Count = 1000, dkLen = 16.
// DK = DC19847E05C64D2FAF10EBFB4A3D2A20
test "PBKDF1-SHA-1 KAT (RFC 8018 B.1)" {
    var out: [16]u8 = undefined;
    try Pbkdf1Sha1.deriveKey(
        "password",
        &[_]u8{ 0x78, 0x57, 0x8E, 0x5A, 0x5D, 0x63, 0xcb, 0x06 },
        1000,
        &out,
    );
    const expected = [_]u8{
        0xDC, 0x19, 0x84, 0x7E, 0x05, 0xC6, 0x4D, 0x2F,
        0xAF, 0x10, 0xEB, 0xFB, 0x4A, 0x3D, 0x2A, 0x20,
    };
    try std.testing.expectEqualSlices(u8, &expected, &out);
}

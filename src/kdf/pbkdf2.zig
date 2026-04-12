const std = @import("std");
const c = @import("../c.zig").c;
const errors = @import("../errors.zig");
const hash = @import("../crypto/hash.zig");

/// PBKDF2 (RFC 6070) parameterized by hash algorithm.
pub fn Pbkdf2(comptime algo: hash.Algorithm) type {
    return struct {
        /// Derive a key using PBKDF2 (RFC 6070).
        ///
        /// `iterations` must be ≥ 1. wolfSSL (pwdbased.c:79-80) silently clamps
        /// iterations=0 to iterations=1, so passing 0 is not an error but produces
        /// a trivially weak key. SP 800-132 §5.2 recommends ≥ 1000 iterations.
        pub fn deriveKey(password: []const u8, salt: []const u8, iterations: u32, out: []u8) !void {
            const ret = c.wc_PBKDF2(
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

pub const Pbkdf2Sha1 = Pbkdf2(.sha1);
pub const Pbkdf2Sha224 = Pbkdf2(.sha224);
pub const Pbkdf2Sha256 = Pbkdf2(.sha256);
pub const Pbkdf2Sha384 = Pbkdf2(.sha384);
pub const Pbkdf2Sha512 = Pbkdf2(.sha512);

// PBKDF2-SHA-384 with password="password", salt="salt", iterations=4096, dkLen=48.
// Expected value computed with: openssl kdf -keylen 48 -kdfopt digest:SHA384
//   -kdfopt pass:password -kdfopt salt:salt -kdfopt iter:4096 PBKDF2
test "PBKDF2-SHA-384 KAT (OpenSSL-derived)" {
    var out: [48]u8 = undefined;
    try Pbkdf2Sha384.deriveKey("password", "salt", 4096, &out);
    const expected = [_]u8{
        0x55, 0x97, 0x26, 0xbe, 0x38, 0xdb, 0x12, 0x5b,
        0xc8, 0x5e, 0xd7, 0x89, 0x5f, 0x6e, 0x3c, 0xf5,
        0x74, 0xc7, 0xa0, 0x1c, 0x08, 0x0c, 0x34, 0x47,
        0xdb, 0x1e, 0x8a, 0x76, 0x76, 0x4d, 0xeb, 0x3c,
        0x30, 0x7b, 0x94, 0x85, 0x3f, 0xbe, 0x42, 0x4f,
        0x64, 0x88, 0xc5, 0xf4, 0xf1, 0x28, 0x96, 0x26,
    };
    try std.testing.expectEqualSlices(u8, &expected, &out);
}

// PBKDF2-SHA-1 with password="password", salt="salt", iterations=4096, dkLen=20.
// RFC 6070 §2 Test Case 2. Expected value computed with:
// openssl kdf -keylen 20 -kdfopt digest:SHA1
//   -kdfopt pass:password -kdfopt salt:salt -kdfopt iter:4096 PBKDF2
test "PBKDF2-SHA-1 KAT (RFC 6070 TC2)" {
    var out: [20]u8 = undefined;
    try Pbkdf2Sha1.deriveKey("password", "salt", 4096, &out);
    const expected = [_]u8{
        0x4b, 0x00, 0x79, 0x01, 0xb7, 0x65, 0x48, 0x9a,
        0xbe, 0xad, 0x49, 0xd9, 0x26, 0xf7, 0x21, 0xd0,
        0x65, 0xa4, 0x29, 0xc1,
    };
    try std.testing.expectEqualSlices(u8, &expected, &out);
}

test "PBKDF2-SHA-256 basic" {
    var out1: [32]u8 = undefined;
    try Pbkdf2Sha256.deriveKey("password", "salt", 4096, &out1);

    // Same inputs should produce same output
    var out2: [32]u8 = undefined;
    try Pbkdf2Sha256.deriveKey("password", "salt", 4096, &out2);
    try std.testing.expectEqualSlices(u8, &out1, &out2);

    // Different password should produce different output
    var out3: [32]u8 = undefined;
    try Pbkdf2Sha256.deriveKey("different", "salt", 4096, &out3);
    try std.testing.expect(!std.mem.eql(u8, &out1, &out3));
}

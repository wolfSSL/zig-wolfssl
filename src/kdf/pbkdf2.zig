const std = @import("std");
const c = @import("../c.zig").c;
const errors = @import("../errors.zig");
const hash = @import("../crypto/hash.zig");

/// PBKDF2 (RFC 6070) parameterized by hash algorithm.
pub fn Pbkdf2(comptime algo: hash.Algorithm) type {
    return struct {
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

pub const Pbkdf2Sha256 = Pbkdf2(.sha256);
pub const Pbkdf2Sha512 = Pbkdf2(.sha512);

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

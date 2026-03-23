const std = @import("std");
const c = @import("c.zig").c;
const errors = @import("errors.zig");

/// Cryptographically secure random number generator wrapping wolfCrypt's WC_RNG.
pub const SecureRng = struct {
    rng: *c.WC_RNG,

    pub fn init() !SecureRng {
        const rng = c.wc_rng_new(null, 0, null) orelse return error.OutOfMemory;
        return .{ .rng = rng };
    }

    pub fn deinit(self: *SecureRng) void {
        c.wc_rng_free(self.rng);
    }

    /// Fill `buf` with cryptographically secure random bytes.
    pub fn fill(self: *SecureRng, buf: []u8) !void {
        const ret = c.wc_RNG_GenerateBlock(self.rng, buf.ptr, @intCast(buf.len));
        if (ret != 0) return errors.mapCryptoError(ret);
    }

    /// Generate a fixed-size random value.
    pub fn random(self: *SecureRng, comptime N: usize) ![N]u8 {
        var buf: [N]u8 = undefined;
        try self.fill(&buf);
        return buf;
    }
};

test "SecureRng generates non-zero random bytes" {
    var rng = try SecureRng.init();
    defer rng.deinit();

    const bytes = try rng.random(32);
    // Extremely unlikely that 32 random bytes are all zero
    var all_zero = true;
    for (bytes) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try std.testing.expect(!all_zero);

    // Two calls should produce different output
    const bytes2 = try rng.random(32);
    try std.testing.expect(!std.mem.eql(u8, &bytes, &bytes2));
}

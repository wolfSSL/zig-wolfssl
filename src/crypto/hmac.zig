const std = @import("std");
const c = @import("../c.zig").c;
const errors = @import("../errors.zig");
const hash = @import("hash.zig");
const opaque_alloc = @import("../opaque_alloc.zig");

/// Comptime-generic HMAC. Wraps wolfCrypt's Hmac structure.
pub fn Hmac(comptime algo: hash.Algorithm) type {
    return struct {
        hmac: *c.Hmac,

        pub const mac_length = hash.digestLen(algo);

        const Self = @This();

        pub fn init(key: []const u8) !Self {
            const hmac = try opaque_alloc.allocHmac();
            errdefer opaque_alloc.freeHmac(hmac);

            var ret = c.wc_HmacInit(hmac, null, c.INVALID_DEVID);
            if (ret != 0) return errors.mapCryptoError(ret);
            ret = c.wc_HmacSetKey(hmac, hash.wcType(algo), key.ptr, @intCast(key.len));
            if (ret != 0) return errors.mapCryptoError(ret);
            return .{ .hmac = hmac };
        }

        pub fn deinit(self: *Self) void {
            c.wc_HmacFree(self.hmac);
            opaque_alloc.freeHmac(self.hmac);
        }

        pub fn update(self: *Self, data: []const u8) !void {
            const ret = c.wc_HmacUpdate(self.hmac, data.ptr, @intCast(data.len));
            if (ret != 0) return errors.mapCryptoError(ret);
        }

        pub fn final(self: *Self, out: *[mac_length]u8) !void {
            const ret = c.wc_HmacFinal(self.hmac, out);
            if (ret != 0) return errors.mapCryptoError(ret);
        }

        /// One-shot HMAC.
        pub fn mac(key: []const u8, data: []const u8, out: *[mac_length]u8) !void {
            var h = try Self.init(key);
            defer h.deinit();
            try h.update(data);
            try h.final(out);
        }
    };
}

pub const HmacSha256 = Hmac(.sha256);
pub const HmacSha384 = Hmac(.sha384);
pub const HmacSha512 = Hmac(.sha512);

test "HMAC-SHA-256 known answer (RFC 4231 Test Case 2)" {
    // Key = "Jefe", Data = "what do ya want for nothing?"
    const key = "Jefe";
    const data = "what do ya want for nothing?";
    var out: [HmacSha256.mac_length]u8 = undefined;
    try HmacSha256.mac(key, data, &out);

    const expected = [_]u8{
        0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e,
        0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
        0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83,
        0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43,
    };
    try std.testing.expectEqualSlices(u8, &expected, &out);
}

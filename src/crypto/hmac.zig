const std = @import("std");
const c = @import("../c.zig").c;
const errors = @import("../errors.zig");
const hash = @import("hash.zig");
const opaque_alloc = @import("../opaque_alloc.zig");

/// Comptime-generic HMAC. Wraps wolfCrypt's Hmac structure.
///
/// Note: BLAKE2b and BLAKE2s are NOT supported. wolfSSL's wc_HmacSetKey
/// has no BLAKE2 case and returns BAD_FUNC_ARG for those hash types.
/// Attempting Hmac(.blake2b) or Hmac(.blake2s) is a compile error.
pub fn Hmac(comptime algo: hash.Algorithm) type {
    comptime {
        if (algo == .blake2b or algo == .blake2s)
            @compileError("HMAC-BLAKE2 is not supported: wolfSSL's wc_HmacSetKey has no BLAKE2 path");
    }
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

pub const HmacSha1 = Hmac(.sha1);
pub const HmacSha224 = Hmac(.sha224);
pub const HmacSha256 = Hmac(.sha256);
pub const HmacSha384 = Hmac(.sha384);
pub const HmacSha512 = Hmac(.sha512);
pub const HmacSha3_256 = Hmac(.sha3_256);
pub const HmacSha3_384 = Hmac(.sha3_384);
pub const HmacSha3_512 = Hmac(.sha3_512);

// RFC 2202 §3 Test Case 2: HMAC-SHA-1
// Key = "Jefe", Data = "what do ya want for nothing?"
// HMAC-SHA-1 = effcdf6ae5eb2fa2d27416d5f184df9c259a7c79
test "HMAC-SHA-1 known answer (RFC 2202 Test Case 2)" {
    const key = "Jefe";
    const data = "what do ya want for nothing?";
    var out: [HmacSha1.mac_length]u8 = undefined;
    try HmacSha1.mac(key, data, &out);
    const expected = [_]u8{
        0xef, 0xfc, 0xdf, 0x6a, 0xe5, 0xeb, 0x2f, 0xa2,
        0xd2, 0x74, 0x16, 0xd5, 0xf1, 0x84, 0xdf, 0x9c,
        0x25, 0x9a, 0x7c, 0x79,
    };
    try std.testing.expectEqualSlices(u8, &expected, &out);
}

test "HMAC-SHA-224 known answer (RFC 4231 Test Case 2)" {
    // Key = "Jefe", Data = "what do ya want for nothing?"
    // RFC 4231 §4.2: HMAC-SHA-224 = a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44
    const key = "Jefe";
    const data = "what do ya want for nothing?";
    var out: [HmacSha224.mac_length]u8 = undefined;
    try HmacSha224.mac(key, data, &out);

    const expected = [_]u8{
        0xa3, 0x0e, 0x01, 0x09, 0x8b, 0xc6, 0xdb, 0xbf,
        0x45, 0x69, 0x0f, 0x3a, 0x7e, 0x9e, 0x6d, 0x0f,
        0x8b, 0xbe, 0xa2, 0xa3, 0x9e, 0x61, 0x48, 0x00,
        0x8f, 0xd0, 0x5e, 0x44,
    };
    try std.testing.expectEqualSlices(u8, &expected, &out);
}

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

// HMAC-SHA3-256 known-answer test.
// Computed independently with Python hmac + hashlib.sha3_256 using the same
// key and data as the RFC 4231 Test Case 2 above (for easy cross-checking).
// Verifies that the WC_SHA3_256 type constant is wired correctly to wc_HmacSetKey.
test "HMAC-SHA3-256 known answer" {
    const key = "Jefe";
    const data = "what do ya want for nothing?";
    var out: [HmacSha3_256.mac_length]u8 = undefined;
    try HmacSha3_256.mac(key, data, &out);

    // Python: hmac.new(b"Jefe", b"what do ya want for nothing?", hashlib.sha3_256).hexdigest()
    // = "c7d4072e788877ae3596bbb0da73b887c9171f93095b294ae857fbe2645e1ba5"
    const expected = [_]u8{
        0xc7, 0xd4, 0x07, 0x2e, 0x78, 0x88, 0x77, 0xae,
        0x35, 0x96, 0xbb, 0xb0, 0xda, 0x73, 0xb8, 0x87,
        0xc9, 0x17, 0x1f, 0x93, 0x09, 0x5b, 0x29, 0x4a,
        0xe8, 0x57, 0xfb, 0xe2, 0x64, 0x5e, 0x1b, 0xa5,
    };
    try std.testing.expectEqualSlices(u8, &expected, &out);
}

// HMAC-SHA3-384 known-answer test.
// Key = "Jefe", Data = "what do ya want for nothing?"
// Sourced from wolfSSL wolfcrypt/test/test.c HMAC-SHA3 test vectors.
test "HMAC-SHA3-384 known answer" {
    const key = "Jefe";
    const data = "what do ya want for nothing?";
    var out: [HmacSha3_384.mac_length]u8 = undefined;
    try HmacSha3_384.mac(key, data, &out);
    const expected = [_]u8{
        0xf1, 0x10, 0x1f, 0x8c, 0xbf, 0x97, 0x66, 0xfd,
        0x67, 0x64, 0xd2, 0xed, 0x61, 0x90, 0x3f, 0x21,
        0xca, 0x9b, 0x18, 0xf5, 0x7c, 0xf3, 0xe1, 0xa2,
        0x3c, 0xa1, 0x35, 0x08, 0xa9, 0x32, 0x43, 0xce,
        0x48, 0xc0, 0x45, 0xdc, 0x00, 0x7f, 0x26, 0xa2,
        0x1b, 0x3f, 0x5e, 0x0e, 0x9d, 0xf4, 0xc2, 0x0a,
    };
    try std.testing.expectEqualSlices(u8, &expected, &out);
}

// HMAC-SHA3-512 known-answer test.
// Key = "Jefe", Data = "what do ya want for nothing?"
// Sourced from wolfSSL wolfcrypt/test/test.c HMAC-SHA3 test vectors.
test "HMAC-SHA3-512 known answer" {
    const key = "Jefe";
    const data = "what do ya want for nothing?";
    var out: [HmacSha3_512.mac_length]u8 = undefined;
    try HmacSha3_512.mac(key, data, &out);
    const expected = [_]u8{
        0x5a, 0x4b, 0xfe, 0xab, 0x61, 0x66, 0x42, 0x7c,
        0x7a, 0x36, 0x47, 0xb7, 0x47, 0x29, 0x2b, 0x83,
        0x84, 0x53, 0x7c, 0xdb, 0x89, 0xaf, 0xb3, 0xbf,
        0x56, 0x65, 0xe4, 0xc5, 0xe7, 0x09, 0x35, 0x0b,
        0x28, 0x7b, 0xae, 0xc9, 0x21, 0xfd, 0x7c, 0xa0,
        0xee, 0x7a, 0x0c, 0x31, 0xd0, 0x22, 0xa9, 0x5e,
        0x1f, 0xc9, 0x2b, 0xa9, 0xd7, 0x7d, 0xf8, 0x83,
        0x96, 0x02, 0x75, 0xbe, 0xb4, 0xe6, 0x20, 0x24,
    };
    try std.testing.expectEqualSlices(u8, &expected, &out);
}

// HMAC-MD5 known-answer: RFC 2104 §5 Test Case 2.
// Key = "Jefe", Data = "what do ya want for nothing?"
// Note: MD5/HMAC-MD5 are cryptographically weak; this verifies the wolfSSL binding.
test "HMAC-MD5 known answer (RFC 2104 TC2)" {
    const HmacMd5 = Hmac(.md5);
    const key = "Jefe";
    const data = "what do ya want for nothing?";
    var out: [HmacMd5.mac_length]u8 = undefined;
    try HmacMd5.mac(key, data, &out);
    const expected = [_]u8{
        0x75, 0x0c, 0x78, 0x3e, 0x6a, 0xb0, 0xb5, 0x03,
        0xea, 0xa8, 0x6e, 0x31, 0x0a, 0x5d, 0xb7, 0x38,
    };
    try std.testing.expectEqualSlices(u8, &expected, &out);
}

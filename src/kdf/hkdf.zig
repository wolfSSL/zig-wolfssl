const std = @import("std");
const c = @import("../c.zig").c;
const errors = @import("../errors.zig");
const hash = @import("../crypto/hash.zig");

/// HKDF (RFC 5869) parameterized by hash algorithm.
pub fn Hkdf(comptime algo: hash.Algorithm) type {
    return struct {
        /// Full HKDF: extract + expand in one call.
        pub fn deriveKey(salt: ?[]const u8, ikm: []const u8, info: ?[]const u8, out: []u8) !void {
            const ret = c.wc_HKDF(
                hash.wcType(algo),
                ikm.ptr,
                @intCast(ikm.len),
                if (salt) |s| s.ptr else null,
                if (salt) |s| @as(c.word32, @intCast(s.len)) else 0,
                if (info) |i| i.ptr else null,
                if (info) |i| @as(c.word32, @intCast(i.len)) else 0,
                out.ptr,
                @intCast(out.len),
            );
            if (ret != 0) return errors.mapCryptoError(ret);
        }

        /// HKDF-Extract only.
        pub fn extract(salt: ?[]const u8, ikm: []const u8, prk: *[hash.digestLen(algo)]u8) !void {
            const ret = c.wc_HKDF_Extract(
                hash.wcType(algo),
                if (salt) |s| s.ptr else null,
                if (salt) |s| @as(c.word32, @intCast(s.len)) else 0,
                ikm.ptr,
                @intCast(ikm.len),
                prk,
            );
            if (ret != 0) return errors.mapCryptoError(ret);
        }

        /// HKDF-Expand only.
        /// RFC 5869 §2.3: `out.len` must be ≤ 255 × HashLen. wolfSSL enforces
        /// this internally (wc_HKDF_Expand_ex:hmac.c:1649) and returns BAD_FUNC_ARG
        /// if violated; that maps to an error here. No pre-check is needed.
        pub fn expand(prk: []const u8, info: ?[]const u8, out: []u8) !void {
            const ret = c.wc_HKDF_Expand(
                hash.wcType(algo),
                prk.ptr,
                @intCast(prk.len),
                if (info) |i| i.ptr else null,
                if (info) |i| @as(c.word32, @intCast(i.len)) else 0,
                out.ptr,
                @intCast(out.len),
            );
            if (ret != 0) return errors.mapCryptoError(ret);
        }
    };
}

pub const HkdfSha1 = Hkdf(.sha1);
pub const HkdfSha224 = Hkdf(.sha224);
pub const HkdfSha256 = Hkdf(.sha256);
pub const HkdfSha384 = Hkdf(.sha384);
pub const HkdfSha512 = Hkdf(.sha512);

// HKDF-SHA-384 with RFC 5869 Test Case 1 inputs (IKM/salt/info), output length 42.
// Expected value computed with: openssl kdf -keylen 42 -kdfopt digest:SHA384
//   -kdfopt hexkey:0b0b...0b -kdfopt hexsalt:000102...0c -kdfopt hexinfo:f0f1...f9 HKDF
test "HKDF-SHA-384 KAT (OpenSSL-derived, RFC 5869 TC1 inputs)" {
    const ikm = [_]u8{0x0b} ** 22;
    const salt = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c };
    const info = [_]u8{ 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9 };

    var okm: [42]u8 = undefined;
    try HkdfSha384.deriveKey(&salt, &ikm, &info, &okm);

    const expected = [_]u8{
        0x9b, 0x50, 0x97, 0xa8, 0x60, 0x38, 0xb8, 0x05,
        0x30, 0x90, 0x76, 0xa4, 0x4b, 0x3a, 0x9f, 0x38,
        0x06, 0x3e, 0x25, 0xb5, 0x16, 0xdc, 0xbf, 0x36,
        0x9f, 0x39, 0x4c, 0xfa, 0xb4, 0x36, 0x85, 0xf7,
        0x48, 0xb6, 0x45, 0x77, 0x63, 0xe4, 0xf0, 0x20,
        0x4f, 0xc5,
    };
    try std.testing.expectEqualSlices(u8, &expected, &okm);
}

// HKDF-SHA-1 with RFC 5869 TC1 inputs (IKM/salt/info), output length 42.
// Expected value computed with: openssl kdf -keylen 42 -kdfopt digest:SHA1
//   -kdfopt hexkey:0b0b...0b -kdfopt hexsalt:000102...0c -kdfopt hexinfo:f0f1...f9 HKDF
test "HKDF-SHA-1 KAT (OpenSSL-derived, RFC 5869 TC1 inputs)" {
    const ikm = [_]u8{0x0b} ** 22;
    const salt = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c };
    const info = [_]u8{ 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9 };

    var okm: [42]u8 = undefined;
    try HkdfSha1.deriveKey(&salt, &ikm, &info, &okm);

    const expected = [_]u8{
        0xd6, 0x00, 0x0f, 0xfb, 0x5b, 0x50, 0xbd, 0x39,
        0x70, 0xb2, 0x60, 0x01, 0x77, 0x98, 0xfb, 0x9c,
        0x8d, 0xf9, 0xce, 0x2e, 0x2c, 0x16, 0xb6, 0xcd,
        0x70, 0x9c, 0xca, 0x07, 0xdc, 0x3c, 0xf9, 0xcf,
        0x26, 0xd6, 0xc6, 0xd7, 0x50, 0xd0, 0xaa, 0xf5,
        0xac, 0x94,
    };
    try std.testing.expectEqualSlices(u8, &expected, &okm);
}

test "HKDF-SHA-256 RFC 5869 Test Case 1" {
    const ikm = [_]u8{0x0b} ** 22;
    const salt = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c };
    const info = [_]u8{ 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9 };

    var okm: [42]u8 = undefined;
    try HkdfSha256.deriveKey(&salt, &ikm, &info, &okm);

    const expected = [_]u8{
        0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
        0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
        0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
        0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
        0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
        0x58, 0x65,
    };
    try std.testing.expectEqualSlices(u8, &expected, &okm);
}

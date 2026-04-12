const std = @import("std");
const c = @import("../c.zig").c;
const errors = @import("../errors.zig");
const opaque_alloc = @import("../opaque_alloc.zig");

pub const Algorithm = enum {
    sha1,
    sha224,
    sha256,
    sha384,
    sha512,
    sha3_256,
    sha3_384,
    sha3_512,
    md5,
    blake2b,
    blake2s,
};

/// Map Algorithm to the wolfCrypt hash-type constant (WC_SHA256, etc.).
/// Used by HMAC, HKDF, PBKDF2, and other modules that need the C enum value.
///
/// BLAKE2: wolfSSL's wc_HmacSetKey, wc_HKDF, and wc_PBKDF2 have no BLAKE2 path.
/// The constants are returned here for completeness (e.g. future use, or callers
/// that only need the type tag), but Hmac(.blake2b/.blake2s) is a compile error.
pub fn wcType(comptime algo: Algorithm) c_int {
    return switch (algo) {
        .sha1 => c.WC_SHA,
        .sha224 => c.WC_SHA224,
        .sha256 => c.WC_SHA256,
        .sha384 => c.WC_SHA384,
        .sha512 => c.WC_SHA512,
        .sha3_256 => c.WC_SHA3_256,
        .sha3_384 => c.WC_SHA3_384,
        .sha3_512 => c.WC_SHA3_512,
        .md5 => c.WC_MD5,
        .blake2b => c.WC_HASH_TYPE_BLAKE2B,
        .blake2s => c.WC_HASH_TYPE_BLAKE2S,
    };
}

/// Returns the digest length in bytes for the given algorithm.
pub fn digestLen(comptime algo: Algorithm) usize {
    return switch (algo) {
        .sha1 => c.WC_SHA_DIGEST_SIZE,
        .sha224 => c.WC_SHA224_DIGEST_SIZE,
        .sha256 => c.WC_SHA256_DIGEST_SIZE,
        .sha384 => c.WC_SHA384_DIGEST_SIZE,
        .sha512 => c.WC_SHA512_DIGEST_SIZE,
        .sha3_256 => c.WC_SHA3_256_DIGEST_SIZE,
        .sha3_384 => c.WC_SHA3_384_DIGEST_SIZE,
        .sha3_512 => c.WC_SHA3_512_DIGEST_SIZE,
        .md5 => c.WC_MD5_DIGEST_SIZE,
        .blake2b => c.WC_BLAKE2B_DIGEST_SIZE, // 64 bytes (512-bit)
        .blake2s => c.WC_BLAKE2S_DIGEST_SIZE, // 32 bytes (256-bit)
    };
}

// C state type for each algorithm
fn CState(comptime algo: Algorithm) type {
    return switch (algo) {
        .sha1 => c.wc_Sha,
        // wc_Sha224 is a typedef for wc_Sha256 in wolfSSL
        .sha224 => c.wc_Sha224,
        .sha256 => c.wc_Sha256,
        .sha384 => c.wc_Sha384,
        .sha512 => c.wc_Sha512,
        .sha3_256, .sha3_384, .sha3_512 => c.wc_Sha3,
        .md5 => c.wc_Md5,
        .blake2b => c.Blake2b,
        .blake2s => c.Blake2s,
    };
}

fn allocState(comptime algo: Algorithm) !*CState(algo) {
    return switch (algo) {
        .sha1 => opaque_alloc.allocSha(),
        // wc_Sha224 is `typedef struct wc_Sha256 wc_Sha224` in wolfssl/wolfcrypt/sha256.h:311.
        // The ptrcast is safe: sizeof(wc_Sha224) == sizeof(wc_Sha256) by definition.
        // Platform-specific ports (TI, Renesas) redefine it, but on standard builds this holds.
        .sha224 => @ptrCast(try opaque_alloc.allocSha256()),
        .sha256 => opaque_alloc.allocSha256(),
        .sha384 => opaque_alloc.allocSha384(),
        .sha512 => opaque_alloc.allocSha512(),
        .sha3_256, .sha3_384, .sha3_512 => opaque_alloc.allocSha3(),
        .md5 => opaque_alloc.allocMd5(),
        .blake2b => opaque_alloc.allocBlake2b(),
        .blake2s => opaque_alloc.allocBlake2s(),
    };
}

fn freeState(comptime algo: Algorithm, ptr: *CState(algo)) void {
    switch (algo) {
        .sha1 => opaque_alloc.freeSha(ptr),
        // ptrcast is safe: wc_Sha224 is typedef wc_Sha256 (sha256.h:311). See allocState.
        .sha224 => opaque_alloc.freeSha256(@ptrCast(ptr)),
        .sha256 => opaque_alloc.freeSha256(ptr),
        .sha384 => opaque_alloc.freeSha384(ptr),
        .sha512 => opaque_alloc.freeSha512(ptr),
        .sha3_256, .sha3_384, .sha3_512 => opaque_alloc.freeSha3(ptr),
        .md5 => opaque_alloc.freeMd5(ptr),
        .blake2b => opaque_alloc.freeBlake2b(ptr),
        .blake2s => opaque_alloc.freeBlake2s(ptr),
    }
}

fn cInit(comptime algo: Algorithm, state: *CState(algo)) c_int {
    return switch (algo) {
        .sha1 => c.wc_InitSha(state),
        .sha224 => c.wc_InitSha224(state),
        .sha256 => c.wc_InitSha256(state),
        .sha384 => c.wc_InitSha384(state),
        .sha512 => c.wc_InitSha512(state),
        .sha3_256 => c.wc_InitSha3_256(state, null, c.INVALID_DEVID),
        .sha3_384 => c.wc_InitSha3_384(state, null, c.INVALID_DEVID),
        .sha3_512 => c.wc_InitSha3_512(state, null, c.INVALID_DEVID),
        .md5 => c.wc_InitMd5(state),
        // BLAKE2 init takes the digest size as a parameter
        .blake2b => c.wc_InitBlake2b(state, @intCast(digestLen(.blake2b))),
        .blake2s => c.wc_InitBlake2s(state, @intCast(digestLen(.blake2s))),
    };
}

fn cUpdate(comptime algo: Algorithm, state: *CState(algo), data: [*]const u8, len: c.word32) c_int {
    return switch (algo) {
        .sha1 => c.wc_ShaUpdate(state, data, len),
        .sha224 => c.wc_Sha224Update(state, data, len),
        .sha256 => c.wc_Sha256Update(state, data, len),
        .sha384 => c.wc_Sha384Update(state, data, len),
        .sha512 => c.wc_Sha512Update(state, data, len),
        .sha3_256 => c.wc_Sha3_256_Update(state, data, len),
        .sha3_384 => c.wc_Sha3_384_Update(state, data, len),
        .sha3_512 => c.wc_Sha3_512_Update(state, data, len),
        .md5 => c.wc_Md5Update(state, data, len),
        .blake2b => c.wc_Blake2bUpdate(state, data, len),
        .blake2s => c.wc_Blake2sUpdate(state, data, len),
    };
}

fn cFinal(comptime algo: Algorithm, state: *CState(algo), out: *[digestLen(algo)]u8) c_int {
    return switch (algo) {
        .sha1 => c.wc_ShaFinal(state, out),
        .sha224 => c.wc_Sha224Final(state, out),
        .sha256 => c.wc_Sha256Final(state, out),
        .sha384 => c.wc_Sha384Final(state, out),
        .sha512 => c.wc_Sha512Final(state, out),
        .sha3_256 => c.wc_Sha3_256_Final(state, out),
        .sha3_384 => c.wc_Sha3_384_Final(state, out),
        .sha3_512 => c.wc_Sha3_512_Final(state, out),
        .md5 => c.wc_Md5Final(state, out),
        // BLAKE2 final takes an extra requestSz (we request the full digest size)
        .blake2b => c.wc_Blake2bFinal(state, out, @intCast(digestLen(.blake2b))),
        .blake2s => c.wc_Blake2sFinal(state, out, @intCast(digestLen(.blake2s))),
    };
}

fn cFree(comptime algo: Algorithm, state: *CState(algo)) void {
    switch (algo) {
        .sha1 => c.wc_ShaFree(state),
        .sha224 => c.wc_Sha224Free(state),
        .sha256 => c.wc_Sha256Free(state),
        .sha384 => c.wc_Sha384Free(state),
        .sha512 => c.wc_Sha512Free(state),
        .sha3_256 => c.wc_Sha3_256_Free(state),
        .sha3_384 => c.wc_Sha3_384_Free(state),
        .sha3_512 => c.wc_Sha3_512_Free(state),
        .md5 => c.wc_Md5Free(state),
        // wolfSSL provides no wc_Blake2b/sFree; state memory is managed by opaque_alloc.
        .blake2b, .blake2s => {},
    }
}

/// One-shot C hash: uses wolfCrypt's one-shot functions (wc_Sha256Hash etc.) where available.
/// BLAKE2 has no wc_Blake2*Hash one-shot function, so it allocates state and runs
/// init/update/final inline. This is the same work wolfCrypt's one-shot helpers do
/// internally, just written out explicitly. The asymmetry is unavoidable.
fn cHash(comptime algo: Algorithm, data: [*]const u8, len: c.word32, out: *[digestLen(algo)]u8) c_int {
    return switch (algo) {
        .sha1 => c.wc_ShaHash(data, len, out),
        .sha224 => c.wc_Sha224Hash(data, len, out),
        .sha256 => c.wc_Sha256Hash(data, len, out),
        .sha384 => c.wc_Sha384Hash(data, len, out),
        .sha512 => c.wc_Sha512Hash(data, len, out),
        .sha3_256 => c.wc_Sha3_256Hash(data, len, out),
        .sha3_384 => c.wc_Sha3_384Hash(data, len, out),
        .sha3_512 => c.wc_Sha3_512Hash(data, len, out),
        .md5 => c.wc_Md5Hash(data, len, out),
        // BLAKE2b/s: no one-shot C function. Use c.MEMORY_E (-125) for OOM so
        // mapCryptoError maps it to CryptoError.OutOfMemory rather than Unexpected.
        .blake2b => blk: {
            const st = allocState(.blake2b) catch break :blk @as(c_int, c.MEMORY_E);
            defer freeState(.blake2b, st);
            var r = cInit(.blake2b, st);
            if (r != 0) break :blk r;
            r = cUpdate(.blake2b, st, data, len);
            if (r != 0) break :blk r;
            break :blk cFinal(.blake2b, st, out);
        },
        .blake2s => blk: {
            const st = allocState(.blake2s) catch break :blk @as(c_int, c.MEMORY_E);
            defer freeState(.blake2s, st);
            var r = cInit(.blake2s, st);
            if (r != 0) break :blk r;
            r = cUpdate(.blake2s, st, data, len);
            if (r != 0) break :blk r;
            break :blk cFinal(.blake2s, st, out);
        },
    };
}

/// Comptime-generic hash function. Each instantiation wraps the corresponding wolfCrypt hash.
pub fn Hash(comptime algo: Algorithm) type {
    return struct {
        state: *CState(algo),

        pub const digest_length = digestLen(algo);

        const Self = @This();

        pub fn init() !Self {
            const state = try allocState(algo);
            errdefer freeState(algo, state);
            const ret = cInit(algo, state);
            if (ret != 0) return errors.mapCryptoError(ret);
            return .{ .state = state };
        }

        pub fn deinit(self: *Self) void {
            cFree(algo, self.state);
            freeState(algo, self.state);
        }

        pub fn update(self: *Self, data: []const u8) !void {
            const ret = cUpdate(algo, self.state, data.ptr, @intCast(data.len));
            if (ret != 0) return errors.mapCryptoError(ret);
        }

        pub fn final(self: *Self, out: *[digest_length]u8) !void {
            const ret = cFinal(algo, self.state, out);
            if (ret != 0) return errors.mapCryptoError(ret);
        }

        /// One-shot convenience: hash data in a single call.
        /// Uses wolfCrypt's one-shot function directly, avoiding malloc.
        pub fn hash(data: []const u8, out: *[digest_length]u8) !void {
            const ret = cHash(algo, data.ptr, @intCast(data.len), out);
            if (ret != 0) return errors.mapCryptoError(ret);
        }
    };
}

// Convenient aliases
pub const Sha1 = Hash(.sha1);
pub const Sha224 = Hash(.sha224);
pub const Sha256 = Hash(.sha256);
pub const Sha384 = Hash(.sha384);
pub const Sha512 = Hash(.sha512);
pub const Sha3_256 = Hash(.sha3_256);
pub const Sha3_384 = Hash(.sha3_384);
pub const Sha3_512 = Hash(.sha3_512);
pub const Blake2b = Hash(.blake2b);
pub const Blake2s = Hash(.blake2s);

// SHA-1("abc") from FIPS 180-4 §B.1
test "SHA-1 known answer" {
    var out: [Sha1.digest_length]u8 = undefined;
    try Sha1.hash("abc", &out);
    const expected = [_]u8{
        0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a,
        0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c,
        0x9c, 0xd0, 0xd8, 0x9d,
    };
    try std.testing.expectEqualSlices(u8, &expected, &out);
}

test "SHA-256 known answer" {
    // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    var out: [Sha256.digest_length]u8 = undefined;
    try Sha256.hash("", &out);
    const expected = [_]u8{
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
    };
    try std.testing.expectEqualSlices(u8, &expected, &out);
}

test "SHA-256 incremental" {
    var h = try Sha256.init();
    defer h.deinit();
    try h.update("hello ");
    try h.update("world");
    var out1: [Sha256.digest_length]u8 = undefined;
    try h.final(&out1);

    var out2: [Sha256.digest_length]u8 = undefined;
    try Sha256.hash("hello world", &out2);

    try std.testing.expectEqualSlices(u8, &out1, &out2);
}

test "SHA-224 known answer" {
    // SHA-224("abc") from FIPS 180-4
    var out: [Sha224.digest_length]u8 = undefined;
    try Sha224.hash("abc", &out);
    const expected = [_]u8{
        0x23, 0x09, 0x7d, 0x22, 0x34, 0x05, 0xd8, 0x22,
        0x86, 0x42, 0xa4, 0x77, 0xbd, 0xa2, 0x55, 0xb3,
        0x2a, 0xad, 0xbc, 0xe4, 0xbd, 0xa0, 0xb3, 0xf7,
        0xe3, 0x6c, 0x9d, 0xa7,
    };
    try std.testing.expectEqualSlices(u8, &expected, &out);
}

test "SHA-512 known answer" {
    // SHA-512("") known hash
    var out: [Sha512.digest_length]u8 = undefined;
    try Sha512.hash("", &out);
    const expected = [_]u8{
        0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd,
        0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80, 0x07,
        0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc,
        0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce,
        0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0,
        0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f,
        0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81,
        0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e,
    };
    try std.testing.expectEqualSlices(u8, &expected, &out);
}

// FIPS 202 SHA3-256 known-answer: SHA3-256("") from NIST FIPS 202 §A.1
test "SHA3-256 known answer (FIPS 202 empty string)" {
    var out: [Sha3_256.digest_length]u8 = undefined;
    try Sha3_256.hash("", &out);
    const expected = [_]u8{
        0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66,
        0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61, 0xd6, 0x62,
        0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa,
        0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8, 0x43, 0x4a,
    };
    try std.testing.expectEqualSlices(u8, &expected, &out);
}

// FIPS 202 SHA3-384 known-answer: SHA3-384("") from NIST FIPS 202 §A.2
test "SHA3-384 known answer (FIPS 202 empty string)" {
    var out: [Sha3_384.digest_length]u8 = undefined;
    try Sha3_384.hash("", &out);
    const expected = [_]u8{
        0x0c, 0x63, 0xa7, 0x5b, 0x84, 0x5e, 0x4f, 0x7d,
        0x01, 0x10, 0x7d, 0x85, 0x2e, 0x4c, 0x24, 0x85,
        0xc5, 0x1a, 0x50, 0xaa, 0xaa, 0x94, 0xfc, 0x61,
        0x99, 0x5e, 0x71, 0xbb, 0xee, 0x98, 0x3a, 0x2a,
        0xc3, 0x71, 0x38, 0x31, 0x26, 0x4a, 0xdb, 0x47,
        0xfb, 0x6b, 0xd1, 0xe0, 0x58, 0xd5, 0xf0, 0x04,
    };
    try std.testing.expectEqualSlices(u8, &expected, &out);
}

// FIPS 202 SHA3-512 known-answer: SHA3-512("") from NIST FIPS 202 §A.3
test "SHA3-512 known answer (FIPS 202 empty string)" {
    var out: [Sha3_512.digest_length]u8 = undefined;
    try Sha3_512.hash("", &out);
    const expected = [_]u8{
        0xa6, 0x9f, 0x73, 0xcc, 0xa2, 0x3a, 0x9a, 0xc5,
        0xc8, 0xb5, 0x67, 0xdc, 0x18, 0x5a, 0x75, 0x6e,
        0x97, 0xc9, 0x82, 0x16, 0x4f, 0xe2, 0x58, 0x59,
        0xe0, 0xd1, 0xdc, 0xc1, 0x47, 0x5c, 0x80, 0xa6,
        0x15, 0xb2, 0x12, 0x3a, 0xf1, 0xf5, 0xf9, 0x4c,
        0x11, 0xe3, 0xe9, 0x40, 0x2c, 0x3a, 0xc5, 0x58,
        0xf5, 0x00, 0x19, 0x9d, 0x95, 0xb6, 0xd3, 0xe3,
        0x01, 0x75, 0x85, 0x86, 0x28, 0x1d, 0xcd, 0x26,
    };
    try std.testing.expectEqualSlices(u8, &expected, &out);
}

// MD5("abc") from RFC 1321 §A.5.
// Note: MD5 is cryptographically broken; this test verifies the wolfSSL binding works,
// not that MD5 is safe to use.
test "MD5 known answer (RFC 1321)" {
    const Md5 = Hash(.md5);
    var out: [Md5.digest_length]u8 = undefined;
    try Md5.hash("abc", &out);
    const expected = [_]u8{
        0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0,
        0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0x7f, 0x72,
    };
    try std.testing.expectEqualSlices(u8, &expected, &out);
}

// BLAKE2b known-answer vectors from wolfSSL test suite (wolfcrypt/test/test.c).
// Input for test i = first i bytes of {0x00, 0x01, 0x02, ...}.
// TC0: empty input; TC1: one byte {0x00}.
test "BLAKE2b known answer TC0 (empty)" {
    var out: [Blake2b.digest_length]u8 = undefined;
    try Blake2b.hash("", &out);
    const expected = [_]u8{
        0x78, 0x6A, 0x02, 0xF7, 0x42, 0x01, 0x59, 0x03,
        0xC6, 0xC6, 0xFD, 0x85, 0x25, 0x52, 0xD2, 0x72,
        0x91, 0x2F, 0x47, 0x40, 0xE1, 0x58, 0x47, 0x61,
        0x8A, 0x86, 0xE2, 0x17, 0xF7, 0x1F, 0x54, 0x19,
        0xD2, 0x5E, 0x10, 0x31, 0xAF, 0xEE, 0x58, 0x53,
        0x13, 0x89, 0x64, 0x44, 0x93, 0x4E, 0xB0, 0x4B,
        0x90, 0x3A, 0x68, 0x5B, 0x14, 0x48, 0xB7, 0x55,
        0xD5, 0x6F, 0x70, 0x1A, 0xFE, 0x9B, 0xE2, 0xCE,
    };
    try std.testing.expectEqualSlices(u8, &expected, &out);
}

test "BLAKE2b known answer TC1 (one byte 0x00)" {
    var out: [Blake2b.digest_length]u8 = undefined;
    try Blake2b.hash(&[_]u8{0x00}, &out);
    const expected = [_]u8{
        0x2F, 0xA3, 0xF6, 0x86, 0xDF, 0x87, 0x69, 0x95,
        0x16, 0x7E, 0x7C, 0x2E, 0x5D, 0x74, 0xC4, 0xC7,
        0xB6, 0xE4, 0x8F, 0x80, 0x68, 0xFE, 0x0E, 0x44,
        0x20, 0x83, 0x44, 0xD4, 0x80, 0xF7, 0x90, 0x4C,
        0x36, 0x96, 0x3E, 0x44, 0x11, 0x5F, 0xE3, 0xEB,
        0x2A, 0x3A, 0xC8, 0x69, 0x4C, 0x28, 0xBC, 0xB4,
        0xF5, 0xA0, 0xF3, 0x27, 0x6F, 0x2E, 0x79, 0x48,
        0x7D, 0x82, 0x19, 0x05, 0x7A, 0x50, 0x6E, 0x4B,
    };
    try std.testing.expectEqualSlices(u8, &expected, &out);
}

test "BLAKE2b incremental matches one-shot" {
    var out1: [Blake2b.digest_length]u8 = undefined;
    var out2: [Blake2b.digest_length]u8 = undefined;

    var h = try Blake2b.init();
    defer h.deinit();
    try h.update(&[_]u8{0x00});
    try h.update(&[_]u8{0x01});
    try h.final(&out1);

    try Blake2b.hash(&[_]u8{ 0x00, 0x01 }, &out2);
    try std.testing.expectEqualSlices(u8, &out1, &out2);
}

// BLAKE2s known-answer vectors from wolfSSL test suite (wolfcrypt/test/test.c).
test "BLAKE2s known answer TC0 (empty)" {
    var out: [Blake2s.digest_length]u8 = undefined;
    try Blake2s.hash("", &out);
    const expected = [_]u8{
        0x69, 0x21, 0x7a, 0x30, 0x79, 0x90, 0x80, 0x94,
        0xe1, 0x11, 0x21, 0xd0, 0x42, 0x35, 0x4a, 0x7c,
        0x1f, 0x55, 0xb6, 0x48, 0x2c, 0xa1, 0xa5, 0x1e,
        0x1b, 0x25, 0x0d, 0xfd, 0x1e, 0xd0, 0xee, 0xf9,
    };
    try std.testing.expectEqualSlices(u8, &expected, &out);
}

test "BLAKE2s known answer TC1 (one byte 0x00)" {
    var out: [Blake2s.digest_length]u8 = undefined;
    try Blake2s.hash(&[_]u8{0x00}, &out);
    const expected = [_]u8{
        0xe3, 0x4d, 0x74, 0xdb, 0xaf, 0x4f, 0xf4, 0xc6,
        0xab, 0xd8, 0x71, 0xcc, 0x22, 0x04, 0x51, 0xd2,
        0xea, 0x26, 0x48, 0x84, 0x6c, 0x77, 0x57, 0xfb,
        0xaa, 0xc8, 0x2f, 0xe5, 0x1a, 0xd6, 0x4b, 0xea,
    };
    try std.testing.expectEqualSlices(u8, &expected, &out);
}

test "BLAKE2s incremental matches one-shot" {
    var out1: [Blake2s.digest_length]u8 = undefined;
    var out2: [Blake2s.digest_length]u8 = undefined;

    var h = try Blake2s.init();
    defer h.deinit();
    try h.update(&[_]u8{0x00});
    try h.update(&[_]u8{0x01});
    try h.final(&out1);

    try Blake2s.hash(&[_]u8{ 0x00, 0x01 }, &out2);
    try std.testing.expectEqualSlices(u8, &out1, &out2);
}

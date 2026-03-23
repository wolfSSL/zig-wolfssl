const std = @import("std");
const c = @import("../c.zig").c;
const errors = @import("../errors.zig");
const opaque_alloc = @import("../opaque_alloc.zig");

pub const Algorithm = enum {
    sha256,
    sha384,
    sha512,
    sha3_256,
    sha3_384,
    sha3_512,
    md5,
};

/// Map Algorithm to the wolfCrypt hash-type constant (WC_SHA256, etc.).
/// Used by HMAC, HKDF, PBKDF2, and other modules that need the C enum value.
pub fn wcType(comptime algo: Algorithm) c_int {
    return switch (algo) {
        .sha256 => c.WC_SHA256,
        .sha384 => c.WC_SHA384,
        .sha512 => c.WC_SHA512,
        .sha3_256 => c.WC_SHA3_256,
        .sha3_384 => c.WC_SHA3_384,
        .sha3_512 => c.WC_SHA3_512,
        .md5 => c.WC_MD5,
    };
}

/// Returns the digest length in bytes for the given algorithm.
pub fn digestLen(comptime algo: Algorithm) usize {
    return switch (algo) {
        .sha256 => c.WC_SHA256_DIGEST_SIZE,
        .sha384 => c.WC_SHA384_DIGEST_SIZE,
        .sha512 => c.WC_SHA512_DIGEST_SIZE,
        .sha3_256 => c.WC_SHA3_256_DIGEST_SIZE,
        .sha3_384 => c.WC_SHA3_384_DIGEST_SIZE,
        .sha3_512 => c.WC_SHA3_512_DIGEST_SIZE,
        .md5 => c.WC_MD5_DIGEST_SIZE,
    };
}

// C state type for each algorithm
fn CState(comptime algo: Algorithm) type {
    return switch (algo) {
        .sha256 => c.wc_Sha256,
        .sha384 => c.wc_Sha384,
        .sha512 => c.wc_Sha512,
        .sha3_256, .sha3_384, .sha3_512 => c.wc_Sha3,
        .md5 => c.wc_Md5,
    };
}

fn allocState(comptime algo: Algorithm) !*CState(algo) {
    return switch (algo) {
        .sha256 => opaque_alloc.allocSha256(),
        .sha384 => opaque_alloc.allocSha384(),
        .sha512 => opaque_alloc.allocSha512(),
        .sha3_256, .sha3_384, .sha3_512 => opaque_alloc.allocSha3(),
        .md5 => opaque_alloc.allocMd5(),
    };
}

fn freeState(comptime algo: Algorithm, ptr: *CState(algo)) void {
    switch (algo) {
        .sha256 => opaque_alloc.freeSha256(ptr),
        .sha384 => opaque_alloc.freeSha384(ptr),
        .sha512 => opaque_alloc.freeSha512(ptr),
        .sha3_256, .sha3_384, .sha3_512 => opaque_alloc.freeSha3(ptr),
        .md5 => opaque_alloc.freeMd5(ptr),
    }
}

fn cInit(comptime algo: Algorithm, state: *CState(algo)) c_int {
    return switch (algo) {
        .sha256 => c.wc_InitSha256(state),
        .sha384 => c.wc_InitSha384(state),
        .sha512 => c.wc_InitSha512(state),
        .sha3_256 => c.wc_InitSha3_256(state, null, c.INVALID_DEVID),
        .sha3_384 => c.wc_InitSha3_384(state, null, c.INVALID_DEVID),
        .sha3_512 => c.wc_InitSha3_512(state, null, c.INVALID_DEVID),
        .md5 => c.wc_InitMd5(state),
    };
}

fn cUpdate(comptime algo: Algorithm, state: *CState(algo), data: [*]const u8, len: c.word32) c_int {
    return switch (algo) {
        .sha256 => c.wc_Sha256Update(state, data, len),
        .sha384 => c.wc_Sha384Update(state, data, len),
        .sha512 => c.wc_Sha512Update(state, data, len),
        .sha3_256 => c.wc_Sha3_256_Update(state, data, len),
        .sha3_384 => c.wc_Sha3_384_Update(state, data, len),
        .sha3_512 => c.wc_Sha3_512_Update(state, data, len),
        .md5 => c.wc_Md5Update(state, data, len),
    };
}

fn cFinal(comptime algo: Algorithm, state: *CState(algo), out: *[digestLen(algo)]u8) c_int {
    return switch (algo) {
        .sha256 => c.wc_Sha256Final(state, out),
        .sha384 => c.wc_Sha384Final(state, out),
        .sha512 => c.wc_Sha512Final(state, out),
        .sha3_256 => c.wc_Sha3_256_Final(state, out),
        .sha3_384 => c.wc_Sha3_384_Final(state, out),
        .sha3_512 => c.wc_Sha3_512_Final(state, out),
        .md5 => c.wc_Md5Final(state, out),
    };
}

fn cFree(comptime algo: Algorithm, state: *CState(algo)) void {
    switch (algo) {
        .sha256 => c.wc_Sha256Free(state),
        .sha384 => c.wc_Sha384Free(state),
        .sha512 => c.wc_Sha512Free(state),
        .sha3_256 => c.wc_Sha3_256_Free(state),
        .sha3_384 => c.wc_Sha3_384_Free(state),
        .sha3_512 => c.wc_Sha3_512_Free(state),
        .md5 => c.wc_Md5Free(state),
    }
}

/// One-shot C hash: avoids malloc by letting wolfCrypt manage its own state internally.
fn cHash(comptime algo: Algorithm, data: [*]const u8, len: c.word32, out: *[digestLen(algo)]u8) c_int {
    return switch (algo) {
        .sha256 => c.wc_Sha256Hash(data, len, out),
        .sha384 => c.wc_Sha384Hash(data, len, out),
        .sha512 => c.wc_Sha512Hash(data, len, out),
        .sha3_256 => c.wc_Sha3_256Hash(data, len, out),
        .sha3_384 => c.wc_Sha3_384Hash(data, len, out),
        .sha3_512 => c.wc_Sha3_512Hash(data, len, out),
        .md5 => c.wc_Md5Hash(data, len, out),
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
pub const Sha256 = Hash(.sha256);
pub const Sha384 = Hash(.sha384);
pub const Sha512 = Hash(.sha512);
pub const Sha3_256 = Hash(.sha3_256);
pub const Sha3_384 = Hash(.sha3_384);
pub const Sha3_512 = Hash(.sha3_512);

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

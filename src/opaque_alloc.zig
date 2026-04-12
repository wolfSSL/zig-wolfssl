//! Helpers for allocating opaque wolfCrypt types that Zig's translate-c
//! cannot size. A companion C file (sizeof_helpers.c) exports the real
//! sizeof() values, and we call them here to allocate exact-sized memory.
//!
//! Note: these allocations use libc malloc/free directly, bypassing any
//! Zig allocator (including SecureAllocator). wolfCrypt's own free
//! functions (e.g. wc_HmacFree) handle sensitive data cleanup internally.
//!
//! We use opaque_alloc for wolfCrypt types where wolfSSL does not provide
//! wc_*_new / wc_*_delete allocation functions (e.g. Hmac, DhKey, hash states,
//! ed448_key). Types that DO have new/delete (e.g. RsaKey, ecc_key, ed25519_key,
//! Aes, curve25519_key) use those directly instead.

const std = @import("std");
const c = @import("c.zig").c;

// Extern declarations for the C sizeof helper functions.
extern fn wolfssl_zig_sizeof_Hmac() usize;
extern fn wolfssl_zig_sizeof_DhKey() usize;
extern fn wolfssl_zig_sizeof_wc_Sha() usize;
extern fn wolfssl_zig_sizeof_wc_Sha256() usize;
extern fn wolfssl_zig_sizeof_wc_Sha384() usize;
extern fn wolfssl_zig_sizeof_wc_Sha512() usize;
extern fn wolfssl_zig_sizeof_wc_Sha3() usize;
extern fn wolfssl_zig_sizeof_wc_Md5() usize;
extern fn wolfssl_zig_sizeof_Blake2b() usize;
extern fn wolfssl_zig_sizeof_Blake2s() usize;
extern fn wolfssl_zig_sizeof_ed448_key() usize;
extern fn wolfssl_zig_sizeof_curve448_key() usize;

/// Allocate an opaque C type using libc malloc with the exact size from C.
/// Returns a properly-typed pointer.
fn allocOpaque(comptime T: type, size: usize) !*T {
    const ptr = std.c.malloc(size) orelse return error.OutOfMemory;
    return @ptrCast(@alignCast(ptr));
}

/// Free an opaque C type allocated with allocOpaque.
fn freeOpaque(ptr: *anyopaque) void {
    std.c.free(ptr);
}

pub fn allocHmac() !*c.Hmac {
    return allocOpaque(c.Hmac, wolfssl_zig_sizeof_Hmac());
}

pub fn freeHmac(ptr: *c.Hmac) void {
    freeOpaque(ptr);
}

pub fn allocDhKey() !*c.DhKey {
    return allocOpaque(c.DhKey, wolfssl_zig_sizeof_DhKey());
}

pub fn freeDhKey(ptr: *c.DhKey) void {
    freeOpaque(ptr);
}

pub fn allocSha() !*c.wc_Sha {
    return allocOpaque(c.wc_Sha, wolfssl_zig_sizeof_wc_Sha());
}

pub fn freeSha(ptr: *c.wc_Sha) void {
    freeOpaque(ptr);
}

pub fn allocSha256() !*c.wc_Sha256 {
    return allocOpaque(c.wc_Sha256, wolfssl_zig_sizeof_wc_Sha256());
}

pub fn freeSha256(ptr: *c.wc_Sha256) void {
    freeOpaque(ptr);
}

pub fn allocSha384() !*c.wc_Sha384 {
    return allocOpaque(c.wc_Sha384, wolfssl_zig_sizeof_wc_Sha384());
}

pub fn freeSha384(ptr: *c.wc_Sha384) void {
    freeOpaque(ptr);
}

pub fn allocSha512() !*c.wc_Sha512 {
    return allocOpaque(c.wc_Sha512, wolfssl_zig_sizeof_wc_Sha512());
}

pub fn freeSha512(ptr: *c.wc_Sha512) void {
    freeOpaque(ptr);
}

pub fn allocSha3() !*c.wc_Sha3 {
    return allocOpaque(c.wc_Sha3, wolfssl_zig_sizeof_wc_Sha3());
}

pub fn freeSha3(ptr: *c.wc_Sha3) void {
    freeOpaque(ptr);
}

pub fn allocMd5() !*c.wc_Md5 {
    return allocOpaque(c.wc_Md5, wolfssl_zig_sizeof_wc_Md5());
}

pub fn freeMd5(ptr: *c.wc_Md5) void {
    freeOpaque(ptr);
}

pub fn allocBlake2b() !*c.Blake2b {
    return allocOpaque(c.Blake2b, wolfssl_zig_sizeof_Blake2b());
}

pub fn freeBlake2b(ptr: *c.Blake2b) void {
    freeOpaque(ptr);
}

pub fn allocBlake2s() !*c.Blake2s {
    return allocOpaque(c.Blake2s, wolfssl_zig_sizeof_Blake2s());
}

pub fn freeBlake2s(ptr: *c.Blake2s) void {
    freeOpaque(ptr);
}

pub fn allocEd448() !*c.ed448_key {
    return allocOpaque(c.ed448_key, wolfssl_zig_sizeof_ed448_key());
}

pub fn freeEd448(ptr: *c.ed448_key) void {
    freeOpaque(ptr);
}

pub fn allocCurve448() !*c.curve448_key {
    return allocOpaque(c.curve448_key, wolfssl_zig_sizeof_curve448_key());
}

pub fn freeCurve448(ptr: *c.curve448_key) void {
    freeOpaque(ptr);
}

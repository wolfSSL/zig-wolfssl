const std = @import("std");
const c = @import("../c.zig").c;
const errors = @import("../errors.zig");
const random = @import("../random.zig");
const opaque_alloc = @import("../opaque_alloc.zig");

/// Diffie-Hellman key exchange.
/// Embedded 512-byte key buffers are sized for FFDHE2048 (256-byte keys).
/// FFDHE3072 requires 384-byte keys and FFDHE4096 requires 512-byte keys,
/// so this struct only safely supports up to FFDHE4096. For larger groups,
/// increase the buffer sizes.
///
/// WARNING: This struct embeds private key material. Do not copy it after
/// calling `generateKeyPair()` — copies will not be securely zeroed on
/// `deinit()`. Always pass by pointer, not by value.
pub const DhKeyPair = struct {
    key: *c.DhKey,
    priv_buf: [512]u8 = undefined,
    pub_buf: [512]u8 = undefined,
    priv_len: usize = 0,
    pub_len: usize = 0,

    /// Initialize DH with FFDHE2048 named group parameters.
    pub fn initFfdhe2048() !DhKeyPair {
        const key = try opaque_alloc.allocDhKey();
        errdefer opaque_alloc.freeDhKey(key);

        var ret = c.wc_InitDhKey(key);
        if (ret != 0) return errors.mapCryptoError(ret);
        errdefer _ = c.wc_FreeDhKey(key);

        const params = c.wc_Dh_ffdhe2048_Get();
        ret = c.wc_DhSetKey_ex(
            key,
            params.*.p,
            params.*.p_len,
            params.*.g,
            params.*.g_len,
            null,
            0,
        );
        if (ret != 0) return errors.mapCryptoError(ret);
        return .{ .key = key };
    }

    pub fn deinit(self: *DhKeyPair) void {
        std.crypto.secureZero(u8, @as([]volatile u8, @volatileCast(&self.priv_buf)));
        _ = c.wc_FreeDhKey(self.key);
        opaque_alloc.freeDhKey(self.key);
    }

    /// Generate the DH key pair (public and private components).
    pub fn generateKeyPair(self: *DhKeyPair, rng: *random.SecureRng) !void {
        var priv_len: c.word32 = @intCast(self.priv_buf.len);
        var pub_len: c.word32 = @intCast(self.pub_buf.len);
        const ret = c.wc_DhGenerateKeyPair(
            self.key,
            rng.rng,
            &self.priv_buf,
            &priv_len,
            &self.pub_buf,
            &pub_len,
        );
        if (ret != 0) return errors.mapCryptoError(ret);
        self.priv_len = priv_len;
        self.pub_len = pub_len;
    }

    /// Get the public key bytes.
    pub fn publicKeyBytes(self: *const DhKeyPair) []const u8 {
        return self.pub_buf[0..self.pub_len];
    }

    /// Compute the shared secret with a peer's public key.
    pub fn sharedSecret(self: *DhKeyPair, peer_pub: []const u8, out: []u8) ![]u8 {
        var out_len: c.word32 = @intCast(out.len);
        const ret = c.wc_DhAgree(
            self.key,
            out.ptr,
            &out_len,
            self.priv_buf[0..self.priv_len].ptr,
            @intCast(self.priv_len),
            peer_pub.ptr,
            @intCast(peer_pub.len),
        );
        if (ret != 0) return errors.mapCryptoError(ret);
        return out[0..out_len];
    }
};

test "DH key agreement with FFDHE2048" {
    var rng = try random.SecureRng.init();
    defer rng.deinit();

    var alice = try DhKeyPair.initFfdhe2048();
    defer alice.deinit();
    try alice.generateKeyPair(&rng);

    var bob = try DhKeyPair.initFfdhe2048();
    defer bob.deinit();
    try bob.generateKeyPair(&rng);

    var secret_a: [256]u8 = undefined;
    const sa = try alice.sharedSecret(bob.publicKeyBytes(), &secret_a);

    var secret_b: [256]u8 = undefined;
    const sb = try bob.sharedSecret(alice.publicKeyBytes(), &secret_b);

    try std.testing.expectEqualSlices(u8, sa, sb);
}

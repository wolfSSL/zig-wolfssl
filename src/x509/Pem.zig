const std = @import("std");
const c = @import("../c.zig").c;

/// PEM encoding/decoding utilities.
pub const Pem = struct {
    /// Decode a PEM-encoded certificate block into DER. Returns a slice of `out`.
    /// Note: only supports certificate PEM (BEGIN CERTIFICATE). For private key
    /// PEM decoding, use the appropriate key import function (e.g. RsaKeyPair.fromDer
    /// after manual PEM stripping).
    pub fn decode(pem: []const u8, out: []u8) ![]u8 {
        const ret = c.wc_CertPemToDer(pem.ptr, @intCast(pem.len), out.ptr, @intCast(out.len), c.CERT_TYPE);
        if (ret < 0) return error.DecodeFailed;
        return out[0..@intCast(ret)];
    }
};

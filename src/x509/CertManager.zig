const c = @import("../c.zig").c;
const errors = @import("../errors.zig");
const nullTerminate = @import("../null_terminate.zig").nullTerminate;

/// Certificate manager for CA trust store, CRL, and OCSP operations.
pub const CertManager = struct {
    cm: *c.WOLFSSL_CERT_MANAGER,

    pub fn init() !CertManager {
        const cm = c.wolfSSL_CertManagerNew() orelse return error.OutOfMemory;
        return .{ .cm = cm };
    }

    pub fn deinit(self: *CertManager) void {
        c.wolfSSL_CertManagerFree(self.cm);
    }

    /// Load a CA certificate from a file.
    pub fn loadCaCertFile(self: *CertManager, path: []const u8) !void {
        var path_buf: [4096]u8 = undefined;
        const z_path = nullTerminate(path, &path_buf) orelse return error.BufferOverflow;
        const ret = c.wolfSSL_CertManagerLoadCA(self.cm, z_path, null);
        if (ret != c.WOLFSSL_SUCCESS) return error.LoadFailed;
    }

    /// Load a CA certificate from a buffer.
    pub fn loadCaCert(self: *CertManager, cert: []const u8, format: Format) !void {
        const ret = c.wolfSSL_CertManagerLoadCABuffer(
            self.cm,
            cert.ptr,
            @intCast(cert.len),
            switch (format) {
                .pem => c.WOLFSSL_FILETYPE_PEM,
                .der => c.WOLFSSL_FILETYPE_ASN1,
            },
        );
        if (ret != c.WOLFSSL_SUCCESS) return error.LoadFailed;
    }

    /// Verify a certificate buffer against loaded CAs.
    pub fn verifyCert(self: *CertManager, cert: []const u8, format: Format) !void {
        const ret = c.wolfSSL_CertManagerVerifyBuffer(
            self.cm,
            cert.ptr,
            @intCast(cert.len),
            switch (format) {
                .pem => c.WOLFSSL_FILETYPE_PEM,
                .der => c.WOLFSSL_FILETYPE_ASN1,
            },
        );
        if (ret != c.WOLFSSL_SUCCESS) return error.VerifyFailed;
    }

    pub const Format = enum { pem, der };
};

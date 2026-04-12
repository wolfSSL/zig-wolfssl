const std = @import("std");
const c = @import("../c.zig").c;
const errors = @import("../errors.zig");
const Name = @import("Name.zig").Name;
const nullTerminate = @import("../null_terminate.zig").nullTerminate;

/// X.509 certificate wrapper.
pub const Certificate = struct {
    x509: *c.WOLFSSL_X509,
    owned: bool,

    /// Parse a certificate from PEM-encoded data.
    pub fn fromPem(pem: []const u8) !Certificate {
        const bio = c.wolfSSL_BIO_new_mem_buf(pem.ptr, @intCast(pem.len)) orelse return error.OutOfMemory;
        defer _ = c.wolfSSL_BIO_free(bio);

        const x509 = c.wolfSSL_PEM_read_bio_X509(bio, null, null, null) orelse return error.ParseFailed;
        return .{ .x509 = x509, .owned = true };
    }

    /// Parse a certificate from DER-encoded data.
    pub fn fromDer(der: []const u8) !Certificate {
        // Use wolfSSL_X509_d2i which takes a simple [*c]const u8 pointer,
        // unlike wolfSSL_d2i_X509 which takes [*c][*c]const u8 (OpenSSL compat).
        const x509 = c.wolfSSL_X509_d2i(null, der.ptr, @intCast(der.len)) orelse return error.ParseFailed;
        return .{ .x509 = x509, .owned = true };
    }

    /// Load a certificate from a file (PEM or DER).
    pub fn fromFile(path: []const u8) !Certificate {
        var path_buf: [4096]u8 = undefined;
        const z_path = nullTerminate(path, &path_buf) orelse return error.BufferOverflow;

        const x509 = c.wolfSSL_X509_load_certificate_file(z_path, c.WOLFSSL_FILETYPE_PEM) orelse
            c.wolfSSL_X509_load_certificate_file(z_path, c.WOLFSSL_FILETYPE_ASN1) orelse
            return error.ParseFailed;
        return .{ .x509 = x509, .owned = true };
    }

    /// Wrap a borrowed X509 pointer (does not free on deinit).
    /// For use with wolfssl.ffi: pass a WOLFSSL_X509* obtained from the raw C API.
    pub fn fromBorrowed(x509: *c.WOLFSSL_X509) Certificate {
        return .{ .x509 = x509, .owned = false };
    }

    pub fn deinit(self: *Certificate) void {
        if (self.owned) {
            c.wolfSSL_X509_free(self.x509);
        }
    }

    /// Get the subject distinguished name.
    pub fn subject(self: *const Certificate) ?Name {
        const name = c.wolfSSL_X509_get_subject_name(self.x509) orelse return null;
        return Name{ .name = name };
    }

    /// Get the issuer distinguished name.
    pub fn issuer(self: *const Certificate) ?Name {
        const name = c.wolfSSL_X509_get_issuer_name(self.x509) orelse return null;
        return Name{ .name = name };
    }

    /// Get the not-before time as a string.
    /// Writes into the caller-provided buffer and returns a slice, or null if unavailable.
    pub fn notBefore(self: *const Certificate, buf: []u8) ?[]const u8 {
        const asn_time = c.wolfSSL_X509_get_notBefore(self.x509) orelse return null;
        if (buf.len == 0) return null;
        const s = c.wolfSSL_ASN1_TIME_to_string(asn_time, buf.ptr, @intCast(buf.len)) orelse return null;
        return std.mem.span(s);
    }

    /// Get the not-after time as a string.
    /// Writes into the caller-provided buffer and returns a slice, or null if unavailable.
    pub fn notAfter(self: *const Certificate, buf: []u8) ?[]const u8 {
        const asn_time = c.wolfSSL_X509_get_notAfter(self.x509) orelse return null;
        if (buf.len == 0) return null;
        const s = c.wolfSSL_ASN1_TIME_to_string(asn_time, buf.ptr, @intCast(buf.len)) orelse return null;
        return std.mem.span(s);
    }

    /// Get the certificate version: 1, 2, or 3 (X.509 versions).
    /// wolfSSL returns 0-based index (0=v1, 1=v2, 2=v3); this returns the human-readable number.
    /// Returns null if the version field is unavailable or outside the expected range.
    pub fn certVersion(self: *const Certificate) ?u8 {
        const v = c.wolfSSL_X509_get_version(self.x509);
        if (v < 0) return null;
        return std.math.cast(u8, v + 1) orelse null;
    }

    /// Get the serial number as a byte slice written into `buf`.
    /// Returns null if the serial number is unavailable or `buf` is too small.
    pub fn serialNumber(self: *const Certificate, buf: []u8) ?[]u8 {
        var sz: c_int = @intCast(buf.len);
        // wolfSSL_X509_get_serial_number returns WOLFSSL_SUCCESS (1) on success.
        const ret = c.wolfSSL_X509_get_serial_number(self.x509, buf.ptr, &sz);
        if (ret != c.WOLFSSL_SUCCESS) return null;
        return buf[0..@intCast(sz)];
    }
};


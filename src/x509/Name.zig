const std = @import("std");
const c = @import("../c.zig").c;

/// X.509 distinguished name wrapper.
pub const Name = struct {
    name: *c.WOLFSSL_X509_NAME,

    /// Get the one-line string representation, written into `buf`.
    ///
    /// Returns a slice of `buf`, or null if unavailable or `buf` is empty.
    /// The output is truncated to fit `buf` if the name is longer.
    pub fn oneLine(self: Name, buf: []u8) ?[]const u8 {
        if (buf.len == 0) return null;
        const s = c.wolfSSL_X509_NAME_oneline(self.name, buf.ptr, @intCast(buf.len)) orelse return null;
        return std.mem.span(s);
    }

    /// Get the common name (CN) entry.
    pub fn commonName(self: Name, buf: []u8) ?[]const u8 {
        const ret = c.wolfSSL_X509_NAME_get_text_by_NID(
            self.name,
            c.NID_commonName,
            buf.ptr,
            @intCast(buf.len),
        );
        if (ret <= 0) return null;
        return buf[0..@intCast(ret)];
    }

    /// Get the organization (O) entry.
    pub fn organization(self: Name, buf: []u8) ?[]const u8 {
        const ret = c.wolfSSL_X509_NAME_get_text_by_NID(
            self.name,
            c.NID_organizationName,
            buf.ptr,
            @intCast(buf.len),
        );
        if (ret <= 0) return null;
        return buf[0..@intCast(ret)];
    }

    /// Get the country (C) entry.
    pub fn country(self: Name, buf: []u8) ?[]const u8 {
        const ret = c.wolfSSL_X509_NAME_get_text_by_NID(
            self.name,
            c.NID_countryName,
            buf.ptr,
            @intCast(buf.len),
        );
        if (ret <= 0) return null;
        return buf[0..@intCast(ret)];
    }

    /// Get the state or province (ST) entry.
    pub fn stateOrProvince(self: Name, buf: []u8) ?[]const u8 {
        const ret = c.wolfSSL_X509_NAME_get_text_by_NID(
            self.name,
            c.NID_stateOrProvinceName,
            buf.ptr,
            @intCast(buf.len),
        );
        if (ret <= 0) return null;
        return buf[0..@intCast(ret)];
    }

    /// Get the locality (L) entry.
    pub fn locality(self: Name, buf: []u8) ?[]const u8 {
        const ret = c.wolfSSL_X509_NAME_get_text_by_NID(
            self.name,
            c.NID_localityName,
            buf.ptr,
            @intCast(buf.len),
        );
        if (ret <= 0) return null;
        return buf[0..@intCast(ret)];
    }

    /// Get the organizational unit (OU) entry.
    pub fn organizationalUnit(self: Name, buf: []u8) ?[]const u8 {
        const ret = c.wolfSSL_X509_NAME_get_text_by_NID(
            self.name,
            c.NID_organizationalUnitName,
            buf.ptr,
            @intCast(buf.len),
        );
        if (ret <= 0) return null;
        return buf[0..@intCast(ret)];
    }

    /// Get the email address entry.
    pub fn emailAddress(self: Name, buf: []u8) ?[]const u8 {
        const ret = c.wolfSSL_X509_NAME_get_text_by_NID(
            self.name,
            c.NID_emailAddress,
            buf.ptr,
            @intCast(buf.len),
        );
        if (ret <= 0) return null;
        return buf[0..@intCast(ret)];
    }
};

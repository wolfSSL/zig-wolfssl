const c = @import("../c.zig").c;

/// X.509 distinguished name wrapper.
pub const Name = struct {
    name: *c.WOLFSSL_X509_NAME,

    /// Get the one-line string representation. Returns a pointer to a
    /// static wolfSSL internal buffer — do not free.
    pub fn oneLine(self: Name) ?[*:0]const u8 {
        return c.wolfSSL_X509_NAME_oneline(self.name, null, 0);
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
};

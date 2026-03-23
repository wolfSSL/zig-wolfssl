const std = @import("std");
const c = @import("../c.zig").c;
const errors = @import("../errors.zig");
const Context = @import("Context.zig").Context;
const Config = @import("Config.zig").Config;
const nullTerminate = @import("../null_terminate.zig").nullTerminate;

/// A TLS connection wrapping a WOLFSSL object.
pub const Connection = struct {
    ssl: *c.WOLFSSL,

    pub const ConnectionError = error{
        OutOfMemory,
        AttachFailed,
        SetSniFailed,
        SetAlpnFailed,
        SetHostNameFailed,
        BufferOverflow,
    };

    pub fn init(ctx: *Context) ConnectionError!Connection {
        const ssl = c.wolfSSL_new(ctx.ctx) orelse return error.OutOfMemory;
        errdefer c.wolfSSL_free(ssl);

        // Apply per-connection SNI hostname from config
        if (ctx.config.sni_hostname) |hostname| {
            var buf: [256]u8 = undefined;
            const z = nullTerminate(hostname, &buf) orelse return error.BufferOverflow;
            // wolfSSL_UseSNI reads but does not modify the data; const cast required by C API signature.
            const ret = c.wolfSSL_UseSNI(ssl, c.WOLFSSL_SNI_HOST_NAME, @constCast(@ptrCast(z)), @intCast(hostname.len));
            if (ret != c.WOLFSSL_SUCCESS) return error.SetSniFailed;
        }

        // Apply per-connection ALPN protocols from config
        if (ctx.config.alpn_protocols) |protocols| {
            // Build comma-separated ALPN list as wolfSSL expects
            var alpn_buf: [4096]u8 = undefined;
            var pos: usize = 0;
            for (protocols, 0..) |proto, i| {
                if (i > 0) {
                    if (pos >= alpn_buf.len) return error.BufferOverflow;
                    alpn_buf[pos] = ',';
                    pos += 1;
                }
                if (pos + proto.len > alpn_buf.len) return error.BufferOverflow;
                @memcpy(alpn_buf[pos .. pos + proto.len], proto);
                pos += proto.len;
            }
            if (pos > 0) {
                const ret = c.wolfSSL_UseALPN(ssl, &alpn_buf, @intCast(pos), c.WOLFSSL_ALPN_FAILED_ON_MISMATCH);
                if (ret != c.WOLFSSL_SUCCESS) return error.SetAlpnFailed;
            }
        }

        return .{ .ssl = ssl };
    }

    pub fn deinit(self: *Connection) void {
        c.wolfSSL_free(self.ssl);
    }

    /// Attach the TLS connection to an existing socket file descriptor.
    pub fn attach(self: *Connection, fd: std.posix.fd_t) ConnectionError!void {
        if (c.wolfSSL_set_fd(self.ssl, fd) != c.WOLFSSL_SUCCESS)
            return error.AttachFailed;
    }

    /// Set the SNI hostname for this connection.
    pub fn setHostName(self: *Connection, hostname: []const u8) ConnectionError!void {
        var buf: [256]u8 = undefined;
        const z = nullTerminate(hostname, &buf) orelse return error.BufferOverflow;
        // wolfSSL_UseSNI reads but does not modify the data; const cast required by C API signature.
        const ret = c.wolfSSL_UseSNI(self.ssl, c.WOLFSSL_SNI_HOST_NAME, @constCast(@ptrCast(z)), @intCast(hostname.len));
        if (ret != c.WOLFSSL_SUCCESS) return error.SetHostNameFailed;
    }

    /// Perform the TLS handshake (client connect or server accept).
    /// On non-blocking sockets, may return `WantRead` or `WantWrite` —
    /// the caller should wait for socket readiness and retry.
    /// All other errors are fatal and the connection should be torn down.
    pub fn handshake(self: *Connection) !void {
        const ret = c.wolfSSL_negotiate(self.ssl);
        if (ret != c.WOLFSSL_SUCCESS) {
            return errors.mapTlsError(c.wolfSSL_get_error(self.ssl, ret));
        }
    }

    /// Read decrypted data. Returns 0 on both TCP EOF and clean TLS
    /// shutdown (close_notify). Use `close()` to distinguish intentional
    /// shutdown from unexpected EOF when the protocol requires it.
    // Note: read/write map wolfSSL errors to a small error set to satisfy
    // the std.io.Reader/Writer interface contracts. This lossy mapping is intentional.
    pub fn read(self: *Connection, buf: []u8) ReadError!usize {
        const ret = c.wolfSSL_read(self.ssl, buf.ptr, @intCast(buf.len));
        if (ret > 0) return @intCast(ret);
        if (ret == 0) return 0; // EOF / peer closed
        const err = c.wolfSSL_get_error(self.ssl, ret);
        return switch (err) {
            c.WOLFSSL_ERROR_WANT_READ_E => ReadError.WouldBlock,
            c.WOLFSSL_ERROR_ZERO_RETURN_E => 0, // clean shutdown
            else => ReadError.ConnectionReset,
        };
    }

    /// Write data (encrypted on the wire).
    // Note: read/write map wolfSSL errors to a small error set to satisfy
    // the std.io.Reader/Writer interface contracts. This lossy mapping is intentional.
    pub fn write(self: *Connection, data: []const u8) WriteError!usize {
        const ret = c.wolfSSL_write(self.ssl, data.ptr, @intCast(data.len));
        if (ret > 0) return @intCast(ret);
        const err = c.wolfSSL_get_error(self.ssl, ret);
        return switch (err) {
            c.WOLFSSL_ERROR_WANT_WRITE_E => WriteError.WouldBlock,
            else => WriteError.BrokenPipe,
        };
    }

    /// Graceful TLS shutdown.
    pub fn close(self: *Connection) void {
        _ = c.wolfSSL_shutdown(self.ssl);
    }

    /// Get the negotiated cipher suite name.
    pub fn cipherSuite(self: *const Connection) ?[*:0]const u8 {
        return c.wolfSSL_get_cipher_name(self.ssl);
    }

    /// Get the TLS version string.
    pub fn version(self: *const Connection) ?[*:0]const u8 {
        return c.wolfSSL_get_version(self.ssl);
    }

    pub const ReadError = error{ WouldBlock, ConnectionReset };
    pub const WriteError = error{ WouldBlock, BrokenPipe };
};

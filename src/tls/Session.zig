const c = @import("../c.zig").c;
const Connection = @import("Connection.zig").Connection;

/// TLS session for resumption.
pub const Session = struct {
    session: *c.WOLFSSL_SESSION,

    /// Save the current session from an active connection.
    pub fn save(conn: *Connection) !Session {
        const sess = c.wolfSSL_get1_session(conn.ssl) orelse return error.NoSession;
        return .{ .session = sess };
    }

    /// Restore a saved session onto a new connection (for resumption).
    pub fn restore(self: *const Session, conn: *Connection) !void {
        if (c.wolfSSL_set_session(conn.ssl, self.session) != c.WOLFSSL_SUCCESS)
            return error.RestoreFailed;
    }

    pub fn deinit(self: *Session) void {
        c.wolfSSL_SESSION_free(self.session);
    }
};

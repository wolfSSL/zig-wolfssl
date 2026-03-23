const std = @import("std");
const c = @import("../c.zig").c;
const errors = @import("../errors.zig");
const Config = @import("Config.zig").Config;
const Connection = @import("Connection.zig").Connection;
const nullTerminate = @import("../null_terminate.zig").nullTerminate;

/// TLS context wrapping WOLFSSL_CTX. Reusable for multiple connections.
pub const Context = struct {
    ctx: *c.WOLFSSL_CTX,
    config: Config,

    pub const ContextError = error{
        OutOfMemory,
        InvalidMethod,
        LoadCaCertFailed,
        LoadCertChainFailed,
        LoadPrivateKeyFailed,
        SetCipherListFailed,
        SetVerifyLocationsFailed,
        SetAlpnFailed,
        SetSniFailed,
        SetMinVersionFailed,
        BufferOverflow,
    };

    pub fn init(config: Config) ContextError!Context {
        // When min != max, use the flexible SSLv23 method that negotiates
        // the best version. Otherwise pick the exact version-specific method.
        const method = selectMethod(config) orelse return error.InvalidMethod;
        const ctx = c.wolfSSL_CTX_new(method) orelse return error.OutOfMemory;
        errdefer c.wolfSSL_CTX_free(ctx);

        // Enforce minimum TLS version
        if (config.min_version != config.max_version) {
            const min_ver: c_int = versionToWolfSSL(config.min_version);
            if (c.wolfSSL_CTX_SetMinVersion(ctx, min_ver) != c.WOLFSSL_SUCCESS)
                return error.SetMinVersionFailed;
        }

        // Verification mode
        const verify_flag: c_int = switch (config.verify_mode) {
            .none => c.WOLFSSL_VERIFY_NONE,
            .verify_peer => c.WOLFSSL_VERIFY_PEER,
            .verify_fail_if_no_peer_cert => c.WOLFSSL_VERIFY_PEER | c.WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT,
        };
        c.wolfSSL_CTX_set_verify(ctx, verify_flag, null);

        // Load CA certs
        switch (config.ca_certs) {
            .system => {
                // Best-effort system CA loading — return value intentionally ignored.
                // Some platforms don't support system CA loading; the user must
                // load CAs explicitly via .file/.pem/.dir on those platforms.
                _ = c.wolfSSL_CTX_load_system_CA_certs(ctx);
            },
            .file => |path| {
                var path_buf: [4096]u8 = undefined;
                const z_path = nullTerminate(path, &path_buf) orelse return error.BufferOverflow;
                if (c.wolfSSL_CTX_load_verify_locations(ctx, z_path, null) != c.WOLFSSL_SUCCESS)
                    return error.SetVerifyLocationsFailed;
            },
            .dir => |path| {
                var path_buf: [4096]u8 = undefined;
                const z_path = nullTerminate(path, &path_buf) orelse return error.BufferOverflow;
                if (c.wolfSSL_CTX_load_verify_locations(ctx, null, z_path) != c.WOLFSSL_SUCCESS)
                    return error.SetVerifyLocationsFailed;
            },
            .pem => |pem| {
                if (c.wolfSSL_CTX_load_verify_buffer(ctx, pem.ptr, @intCast(pem.len), c.WOLFSSL_FILETYPE_PEM) != c.WOLFSSL_SUCCESS)
                    return error.LoadCaCertFailed;
            },
            .none => {},
        }

        // Load certificate chain
        if (config.cert_chain) |cert| {
            switch (cert) {
                .file => |path| {
                    var buf: [4096]u8 = undefined;
                    const z = nullTerminate(path, &buf) orelse return error.BufferOverflow;
                    if (c.wolfSSL_CTX_use_certificate_chain_file(ctx, z) != c.WOLFSSL_SUCCESS)
                        return error.LoadCertChainFailed;
                },
                .pem => |pem| {
                    if (c.wolfSSL_CTX_use_certificate_buffer(ctx, pem.ptr, @intCast(pem.len), c.WOLFSSL_FILETYPE_PEM) != c.WOLFSSL_SUCCESS)
                        return error.LoadCertChainFailed;
                },
                .der => |der| {
                    if (c.wolfSSL_CTX_use_certificate_buffer(ctx, der.ptr, @intCast(der.len), c.WOLFSSL_FILETYPE_ASN1) != c.WOLFSSL_SUCCESS)
                        return error.LoadCertChainFailed;
                },
            }
        }

        // Load private key
        if (config.private_key) |key| {
            switch (key) {
                .file => |path| {
                    var buf: [4096]u8 = undefined;
                    const z = nullTerminate(path, &buf) orelse return error.BufferOverflow;
                    if (c.wolfSSL_CTX_use_PrivateKey_file(ctx, z, c.WOLFSSL_FILETYPE_PEM) != c.WOLFSSL_SUCCESS)
                        return error.LoadPrivateKeyFailed;
                },
                .pem => |pem| {
                    if (c.wolfSSL_CTX_use_PrivateKey_buffer(ctx, pem.ptr, @intCast(pem.len), c.WOLFSSL_FILETYPE_PEM) != c.WOLFSSL_SUCCESS)
                        return error.LoadPrivateKeyFailed;
                },
                .der => |der| {
                    if (c.wolfSSL_CTX_use_PrivateKey_buffer(ctx, der.ptr, @intCast(der.len), c.WOLFSSL_FILETYPE_ASN1) != c.WOLFSSL_SUCCESS)
                        return error.LoadPrivateKeyFailed;
                },
            }
        }

        // Cipher suites
        if (config.cipher_suites) |suites| {
            var buf: [4096]u8 = undefined;
            const z = nullTerminate(suites, &buf) orelse return error.BufferOverflow;
            if (c.wolfSSL_CTX_set_cipher_list(ctx, z) != c.WOLFSSL_SUCCESS)
                return error.SetCipherListFailed;
        }

        // Session cache
        if (!config.session_cache) {
            _ = c.wolfSSL_CTX_set_session_cache_mode(ctx, c.WOLFSSL_SESS_CACHE_OFF);
        }

        return .{ .ctx = ctx, .config = config };
    }

    pub fn deinit(self: *Context) void {
        c.wolfSSL_CTX_free(self.ctx);
    }

    /// Create a new TLS connection from this context.
    /// Applies per-connection config (SNI hostname, ALPN protocols) automatically.
    pub fn connection(self: *Context) Connection.ConnectionError!Connection {
        return Connection.init(self);
    }

    fn versionToWolfSSL(ver: Config.Version) c_int {
        return switch (ver) {
            .tls_1_2 => c.WOLFSSL_TLSV1_2,
            .tls_1_3 => c.WOLFSSL_TLSV1_3,
            .dtls_1_2 => c.WOLFSSL_DTLSV1_2,
            .dtls_1_3 => c.WOLFSSL_DTLSV1_3,
        };
    }

    fn selectMethod(config: Config) ?*c.WOLFSSL_METHOD {
        if (config.min_version != config.max_version) {
            return selectFlexibleMethod(config);
        }
        return selectExactMethod(config);
    }

    /// Flexible method: negotiates best version, constrained by SetMinVersion.
    fn selectFlexibleMethod(config: Config) ?*c.WOLFSSL_METHOD {
        const is_dtls = config.min_version == .dtls_1_2 or config.min_version == .dtls_1_3;
        return switch (config.role) {
            .client => if (is_dtls)
                if (@hasDecl(c, "wolfDTLSv1_2_client_method")) c.wolfDTLSv1_2_client_method() else null
            else
                c.wolfSSLv23_client_method(),
            .server => if (is_dtls)
                if (@hasDecl(c, "wolfDTLSv1_2_server_method")) c.wolfDTLSv1_2_server_method() else null
            else
                c.wolfSSLv23_server_method(),
        };
    }

    /// Exact method: pins to a specific TLS/DTLS version.
    fn selectExactMethod(config: Config) ?*c.WOLFSSL_METHOD {
        return switch (config.role) {
            .client => switch (config.max_version) {
                .tls_1_3 => c.wolfTLSv1_3_client_method(),
                .tls_1_2 => c.wolfTLSv1_2_client_method(),
                .dtls_1_2 => if (@hasDecl(c, "wolfDTLSv1_2_client_method"))
                    c.wolfDTLSv1_2_client_method()
                else
                    null,
                .dtls_1_3 => if (@hasDecl(c, "wolfDTLSv1_3_client_method"))
                    c.wolfDTLSv1_3_client_method()
                else
                    null,
            },
            .server => switch (config.max_version) {
                .tls_1_3 => c.wolfTLSv1_3_server_method(),
                .tls_1_2 => c.wolfTLSv1_2_server_method(),
                .dtls_1_2 => if (@hasDecl(c, "wolfDTLSv1_2_server_method"))
                    c.wolfDTLSv1_2_server_method()
                else
                    null,
                .dtls_1_3 => if (@hasDecl(c, "wolfDTLSv1_3_server_method"))
                    c.wolfDTLSv1_3_server_method()
                else
                    null,
            },
        };
    }

};

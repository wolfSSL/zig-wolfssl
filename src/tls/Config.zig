const std = @import("std");

/// TLS configuration. Used to initialize a Context.
pub const Config = struct {
    /// Minimum TLS version to accept.
    min_version: Version = .tls_1_2,
    /// Maximum TLS version to use.
    max_version: Version = .tls_1_3,
    /// Cipher suite string (colon-separated OpenSSL format), or null for defaults.
    cipher_suites: ?[]const u8 = null,
    /// How to load CA certificates for peer verification.
    ca_certs: CaCerts = .system,
    /// Client/server certificate chain.
    cert_chain: ?CertSource = null,
    /// Private key corresponding to the certificate.
    private_key: ?KeySource = null,
    /// Peer certificate verification mode.
    verify_mode: VerifyMode = .verify_peer,
    /// ALPN protocol list (e.g., &.{"h2", "http/1.1"}).
    alpn_protocols: ?[]const []const u8 = null,
    /// SNI hostname (clients should set this).
    sni_hostname: ?[]const u8 = null,
    /// Enable session caching.
    session_cache: bool = true,
    /// Role: client or server.
    role: Role = .client,

    pub const Version = enum { tls_1_2, tls_1_3, dtls_1_2, dtls_1_3 };
    pub const CaCerts = union(enum) {
        /// Attempt to load platform-provided CA certificates. This is best-effort:
        /// on platforms that don't support system CA loading, the call silently
        /// succeeds with no CAs loaded. If `.verify_mode` is `.verify_peer`,
        /// handshakes will then fail with a certificate verification error.
        /// Use `.file` or `.pem` for reliable cross-platform CA loading.
        system,
        file: []const u8,
        pem: []const u8,
        dir: []const u8,
        none,
    };
    pub const CertSource = union(enum) { file: []const u8, pem: []const u8, der: []const u8 };
    pub const KeySource = union(enum) { file: []const u8, pem: []const u8, der: []const u8 };
    pub const VerifyMode = enum { none, verify_peer, verify_fail_if_no_peer_cert };
    pub const Role = enum { client, server };
};

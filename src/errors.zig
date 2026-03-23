const std = @import("std");
const log = std.log.scoped(.wolfssl);
const c = @import("c.zig").c;

/// Errors from wolfSSL TLS operations.
pub const TlsError = error{
    WantRead,
    WantWrite,
    WantX509Lookup,
    Syscall,
    ZeroReturn,
    WantConnect,
    WantAccept,
    InputCase,
    Prefix,
    OutOfMemory,
    VerifyFinished,
    VerifyMac,
    Parse,
    UnknownHandshakeType,
    Socket,
    SocketNoData,
    IncompleteData,
    UnknownRecordType,
    Decrypt,
    FatalAlert,
    Encrypt,
    FileRead,
    NoPeerKey,
    NoPrivateKey,
    RsaPrivate,
    NoDhParams,
    BuildMessage,
    BadHello,
    DomainNameMismatch,
    NotReady,
    IpAddrMismatch,
    VersionMismatch,
    BufferError,
    VerifyCert,
    VerifySign,
    ClientId,
    ServerHint,
    PskKey,
    LengthError,
    PeerKeyError,
    PeerClosed,
    SideError,
    NoPeerCert,
    EccCurveType,
    EccCurve,
    EccPeerKey,
    EccMakeKey,
    EccExport,
    EccShared,
    NotCa,
    BadCertManager,
    Unexpected,
};

/// Errors from wolfCrypt cryptographic operations.
pub const CryptoError = error{
    OutOfMemory,
    MpInit,
    MpRead,
    MpExptmod,
    MpTo,
    MpSub,
    MpAdd,
    MpMul,
    MpMulmod,
    MpMod,
    MpInvmod,
    MpCmp,
    MpZero,
    RsaWrongType,
    RsaBuffer,
    BufferTooSmall,
    AlgoId,
    PublicKey,
    DateValidity,
    Subject,
    Issuer,
    CaTrue,
    Extensions,
    AsnParse,
    AsnVersion,
    AsnGetInt,
    AsnRsaKey,
    AsnObjectId,
    AsnTagNull,
    AsnExpect0,
    AsnBitStr,
    AsnUnknownOid,
    AsnDateSize,
    AsnBeforeDate,
    AsnAfterDate,
    AsnSigOid,
    AsnTime,
    OpenRandom,
    ReadRandom,
    RandomBlock,
    BadMutex,
    Timeout,
    Pending,
    KeyExhausted,
    AesEaxAuth,
    Unexpected,
};

/// Map a wolfSSL TLS error code (from wolfSSL_get_error) to a Zig error.
pub fn mapTlsError(ret: c_int) TlsError {
    return switch (ret) {
        c.WOLFSSL_ERROR_WANT_READ_E => TlsError.WantRead,
        c.WANT_READ => TlsError.WantRead, // legacy alias (-323), distinct from WOLFSSL_ERROR_WANT_READ_E (-2)
        c.WOLFSSL_ERROR_WANT_WRITE_E => TlsError.WantWrite,
        c.WOLFSSL_ERROR_WANT_X509_LOOKUP_E => TlsError.WantX509Lookup,
        c.WOLFSSL_ERROR_SYSCALL_E => TlsError.Syscall,
        c.WOLFSSL_ERROR_ZERO_RETURN_E => TlsError.ZeroReturn,
        c.WOLFSSL_ERROR_WANT_CONNECT_E => TlsError.WantConnect,
        c.WOLFSSL_ERROR_WANT_ACCEPT_E => TlsError.WantAccept,
        c.INPUT_CASE_ERROR => TlsError.InputCase,
        c.PREFIX_ERROR => TlsError.Prefix,
        c.MEMORY_ERROR => TlsError.OutOfMemory,
        c.VERIFY_FINISHED_ERROR => TlsError.VerifyFinished,
        c.VERIFY_MAC_ERROR => TlsError.VerifyMac,
        c.PARSE_ERROR => TlsError.Parse,
        c.UNKNOWN_HANDSHAKE_TYPE => TlsError.UnknownHandshakeType,
        c.SOCKET_ERROR_E => TlsError.Socket,
        c.SOCKET_NODATA => TlsError.SocketNoData,
        c.INCOMPLETE_DATA => TlsError.IncompleteData,
        c.UNKNOWN_RECORD_TYPE => TlsError.UnknownRecordType,
        c.DECRYPT_ERROR => TlsError.Decrypt,
        c.FATAL_ERROR => TlsError.FatalAlert,
        c.ENCRYPT_ERROR => TlsError.Encrypt,
        c.FREAD_ERROR => TlsError.FileRead,
        c.NO_PEER_KEY => TlsError.NoPeerKey,
        c.NO_PRIVATE_KEY => TlsError.NoPrivateKey,
        c.RSA_PRIVATE_ERROR => TlsError.RsaPrivate,
        c.NO_DH_PARAMS => TlsError.NoDhParams,
        c.BUILD_MSG_ERROR => TlsError.BuildMessage,
        c.BAD_HELLO => TlsError.BadHello,
        c.DOMAIN_NAME_MISMATCH => TlsError.DomainNameMismatch,
        c.NOT_READY_ERROR => TlsError.NotReady,
        c.IPADDR_MISMATCH => TlsError.IpAddrMismatch,
        c.VERSION_ERROR => TlsError.VersionMismatch,
        c.BUFFER_ERROR => TlsError.BufferError,
        c.VERIFY_CERT_ERROR => TlsError.VerifyCert,
        c.VERIFY_SIGN_ERROR => TlsError.VerifySign,
        c.CLIENT_ID_ERROR => TlsError.ClientId,
        c.SERVER_HINT_ERROR => TlsError.ServerHint,
        c.PSK_KEY_ERROR => TlsError.PskKey,
        c.LENGTH_ERROR => TlsError.LengthError,
        c.PEER_KEY_ERROR => TlsError.PeerKeyError,
        c.ZERO_RETURN => TlsError.PeerClosed,
        c.SIDE_ERROR => TlsError.SideError,
        c.NO_PEER_CERT => TlsError.NoPeerCert,
        c.ECC_CURVETYPE_ERROR => TlsError.EccCurveType,
        c.ECC_CURVE_ERROR => TlsError.EccCurve,
        c.ECC_PEERKEY_ERROR => TlsError.EccPeerKey,
        c.ECC_MAKEKEY_ERROR => TlsError.EccMakeKey,
        c.ECC_EXPORT_ERROR => TlsError.EccExport,
        c.ECC_SHARED_ERROR => TlsError.EccShared,
        c.NOT_CA_ERROR => TlsError.NotCa,
        c.BAD_CERT_MANAGER_ERROR => TlsError.BadCertManager,
        else => {
            log.warn("unmapped TLS error code: {d}", .{ret});
            return TlsError.Unexpected;
        },
    };
}

// WANT_READ (-323) and WOLFSSL_ERROR_WANT_READ_E (-2) are distinct constants
// in wolfSSL. Both are handled above.

/// Map a wolfCrypt error code to a Zig error.
pub fn mapCryptoError(ret: c_int) CryptoError {
    return switch (ret) {
        c.MEMORY_E => CryptoError.OutOfMemory,
        c.MP_INIT_E => CryptoError.MpInit,
        c.MP_READ_E => CryptoError.MpRead,
        c.MP_EXPTMOD_E => CryptoError.MpExptmod,
        c.MP_TO_E => CryptoError.MpTo,
        c.MP_SUB_E => CryptoError.MpSub,
        c.MP_ADD_E => CryptoError.MpAdd,
        c.MP_MUL_E => CryptoError.MpMul,
        c.MP_MULMOD_E => CryptoError.MpMulmod,
        c.MP_MOD_E => CryptoError.MpMod,
        c.MP_INVMOD_E => CryptoError.MpInvmod,
        c.MP_CMP_E => CryptoError.MpCmp,
        c.MP_ZERO_E => CryptoError.MpZero,
        c.RSA_WRONG_TYPE_E => CryptoError.RsaWrongType,
        c.RSA_BUFFER_E => CryptoError.RsaBuffer,
        c.BUFFER_E => CryptoError.BufferTooSmall,
        c.ALGO_ID_E => CryptoError.AlgoId,
        c.PUBLIC_KEY_E => CryptoError.PublicKey,
        c.DATE_E => CryptoError.DateValidity,
        c.SUBJECT_E => CryptoError.Subject,
        c.ISSUER_E => CryptoError.Issuer,
        c.CA_TRUE_E => CryptoError.CaTrue,
        c.EXTENSIONS_E => CryptoError.Extensions,
        c.ASN_PARSE_E => CryptoError.AsnParse,
        c.ASN_VERSION_E => CryptoError.AsnVersion,
        c.ASN_GETINT_E => CryptoError.AsnGetInt,
        c.ASN_RSA_KEY_E => CryptoError.AsnRsaKey,
        c.ASN_OBJECT_ID_E => CryptoError.AsnObjectId,
        c.ASN_TAG_NULL_E => CryptoError.AsnTagNull,
        c.ASN_EXPECT_0_E => CryptoError.AsnExpect0,
        c.ASN_BITSTR_E => CryptoError.AsnBitStr,
        c.ASN_UNKNOWN_OID_E => CryptoError.AsnUnknownOid,
        c.ASN_DATE_SZ_E => CryptoError.AsnDateSize,
        c.ASN_BEFORE_DATE_E => CryptoError.AsnBeforeDate,
        c.ASN_AFTER_DATE_E => CryptoError.AsnAfterDate,
        c.ASN_SIG_OID_E => CryptoError.AsnSigOid,
        c.ASN_TIME_E => CryptoError.AsnTime,
        c.OPEN_RAN_E => CryptoError.OpenRandom,
        c.READ_RAN_E => CryptoError.ReadRandom,
        c.RAN_BLOCK_E => CryptoError.RandomBlock,
        c.BAD_MUTEX_E => CryptoError.BadMutex,
        c.WC_TIMEOUT_E => CryptoError.Timeout,
        c.WC_PENDING_E => CryptoError.Pending,
        else => {
            log.warn("unmapped crypto error code: {d}", .{ret});
            return CryptoError.Unexpected;
        },
    };
}

/// Check a wolfCrypt return code. Returns void on success (>= 0), or the mapped error.
pub inline fn checkCrypto(ret: c_int) CryptoError!void {
    if (ret < 0) return mapCryptoError(ret);
}

/// Returns true if the wolfCrypt error code indicates a mathematically
/// invalid signature (as opposed to an operational error like OOM).
/// Used by Ed25519/Ed448 verify to distinguish "bad sig" from "crypto engine broken."
pub fn isBadSignatureError(ret: c_int) bool {
    inline for (.{ "SIG_VERIFY_E", "ASN_SIG_CONFIRM_E", "ECC_BAD_ARG_E", "BAD_FUNC_ARG" }) |name| {
        if (@hasDecl(c, name) and ret == @field(c, name)) return true;
    }
    return false;
}

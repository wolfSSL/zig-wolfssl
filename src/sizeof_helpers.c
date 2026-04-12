/* sizeof helpers for wolfCrypt types that are opaque to Zig's translate-c.
 *
 * Zig's @cImport / translate-c cannot determine the layout of complex C structs
 * that use preprocessor-dependent fields, bitfields, or platform-specific
 * extensions. These types become opaque in Zig, making @sizeOf() return 0.
 * This file exports the correct sizeof() values from C so the Zig bindings
 * (via opaque_alloc.zig) can allocate exact-sized memory for these types.
 *
 * Only types WITHOUT wc_*_new/wc_*_delete allocation functions need entries
 * here. Types that have those functions (RsaKey, ecc_key, ed25519_key, Aes,
 * curve25519_key) use them directly instead.
 */
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/dh.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/sha3.h>
#include <wolfssl/wolfcrypt/md5.h>
#include <wolfssl/wolfcrypt/blake2.h>
#include <wolfssl/wolfcrypt/ed448.h>
#include <wolfssl/wolfcrypt/curve448.h>
#include <stddef.h>

size_t wolfssl_zig_sizeof_Hmac(void) { return sizeof(Hmac); }
size_t wolfssl_zig_sizeof_DhKey(void) { return sizeof(DhKey); }
size_t wolfssl_zig_sizeof_wc_Sha(void) { return sizeof(wc_Sha); }
size_t wolfssl_zig_sizeof_wc_Sha256(void) { return sizeof(wc_Sha256); }
size_t wolfssl_zig_sizeof_wc_Sha384(void) { return sizeof(wc_Sha384); }
size_t wolfssl_zig_sizeof_wc_Sha512(void) { return sizeof(wc_Sha512); }
size_t wolfssl_zig_sizeof_wc_Sha3(void) { return sizeof(wc_Sha3); }
size_t wolfssl_zig_sizeof_wc_Md5(void) { return sizeof(wc_Md5); }
size_t wolfssl_zig_sizeof_Blake2b(void) { return sizeof(Blake2b); }
size_t wolfssl_zig_sizeof_Blake2s(void) { return sizeof(Blake2s); }
size_t wolfssl_zig_sizeof_ed448_key(void) { return sizeof(ed448_key); }
size_t wolfssl_zig_sizeof_curve448_key(void) { return sizeof(curve448_key); }

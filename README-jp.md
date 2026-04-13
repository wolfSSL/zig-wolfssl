# zig-wolfssl

このレポジトリでは、wolfSSL および wolfCrypt のZig的な バインディングを提供します。

**ライセンス:** GPL-3.0 またはコマーシャルライセンス（wolfSSL Inc.）

システムにインストールされた wolfSSL ライブラリにリンクし、TLS、暗号化、X.509 証明書、鍵導出、セキュアな乱数生成のネイティブ Zig API を提供します。

## 機能

**TLS** -- クライアント/サーバー接続、コンテキスト管理、セッション再開（TLS 1.2/1.3）

**対称暗号** -- AES-GCM（ワンショットおよびストリーミング）、AES-CBC、AES-CTR、ChaCha20-Poly1305

**ハッシュと MAC** -- SHA-1、SHA-224、SHA-256、SHA-384、SHA-512、SHA3-256、SHA3-384、SHA3-512、BLAKE2b-512、BLAKE2s-256、MD5、HMAC、AES-CMAC

**非対称暗号** -- RSA（PKCS#1 v1.5、PSS、OAEP）、ECC（ECDSA/ECDH P-256/P-384/P-521/SECP256K1）、Ed25519、Ed448、Curve25519、X448、Diffie-Hellman（FFDHE-2048/3072/4096）

**X.509** -- 証明書の解析、チェーン検証、PEM/DER/ファイル読み込み

**KDF** -- HKDF、PBKDF1、PBKDF2、scrypt

**RNG** -- 暗号論的に安全な乱数生成

## 前提条件

wolfSSL がシステムにインストールされている必要があります。ビルドシステムは以下の優先順位で wolfSSL を検索します：`-Dwolfssl-src=` ビルドオプション、`WOLFSSL_SRC` 環境変数、またはフォールバックとして `pkg-config`。

```bash
cd ~/wolfssl
./configure --enable-tls13 --enable-ecc --enable-ed25519 --enable-curve25519 \
            --enable-ed448 --enable-curve448 --enable-secp256k1 \
            --enable-aesgcm --enable-aesgcm-stream --enable-chacha \
            --enable-aescbc --enable-aesctr \
            --enable-sha512 --enable-sha224 --enable-sha3 --enable-blake2 \
            --enable-hkdf --enable-pwdbased --enable-scrypt \
            --enable-cmac --enable-rsapss --enable-keygen \
            --enable-certgen --enable-dh --enable-md5 \
            --enable-pss-salt-len-discover
make
sudo make install
sudo ldconfig
```

インストールを確認：

```bash
pkg-config --modversion wolfssl
```

Zig ラッパーは wolfSSL をソースからコンパイルしません。事前にインストールされたシステムライブラリにリンクします。使用可能なアルゴリズムは wolfSSL ビルド時の `./configure` フラグによって異なります。ラッパーは `@hasDecl` を通じてコンパイル時に利用可能な機能を検出します。

## 最小 Zig バージョン

0.16.0-dev.2877+627f03af9

## ビルド

```bash
zig build
```

## テスト

```bash
zig build test
```

一部のテストは wolfSSL の証明書ファイルを必要とします。ビルドシステムは以下の優先順位で wolfSSL ソースツリー（および `certs/` ディレクトリ）を検索します：

1. `-Dwolfssl-src=<path>` ビルドオプション
2. `WOLFSSL_SRC` 環境変数
3. `pkg-config` ヒューリスティック（未インストールのソースビルド用フォールバック）

```bash
# ビルドオプションを使用する場合
zig build test -Dwolfssl-src=/path/to/wolfssl

# 環境変数を使用する場合
export WOLFSSL_SRC=/path/to/wolfssl
zig build test
```

上記のいずれも解決できない場合でもビルドは成功します — 証明書依存のテストはビルドを中断するのではなく、実行時にファイルが見つからないエラーで失敗します。

## 使用方法

```zig
const wolfssl = @import("wolfssl");

// ライブラリの初期化
try wolfssl.init();
defer wolfssl.deinit();

// SHA-256 ハッシュ
var hasher = try wolfssl.crypto.hash.Hash(.sha256).init();
defer hasher.deinit();
try hasher.update("hello");
var digest: [wolfssl.crypto.hash.Hash(.sha256).digest_length]u8 = undefined;
try hasher.final(&digest);

// システム CA 証明書を使用した TLS 1.3 クライアントコンテキスト
const config = wolfssl.tls.Config{
    .role = .client,
    .min_version = .tls_1_3,
    .max_version = .tls_1_3,
    .ca_certs = .system,
};
var ctx = try wolfssl.tls.Context.init(config);
defer ctx.deinit();
```

## プロジェクト構成

```
src/
  root.zig        -- 公開 API エントリーポイント
  c.zig           -- wolfSSL C ヘッダーの @cImport
  tls/            -- TLS コンテキスト、接続、セッション
  crypto/         -- 対称暗号、ハッシュ、MAC、非対称暗号
  x509/           -- 証明書の解析と検証
  kdf/            -- HKDF、PBKDF1、PBKDF2、scrypt
  random.zig      -- セキュアな乱数生成
build.zig         -- ビルドシステム（ライブラリ検索、テスト設定）
build.zig.zon     -- パッケージマニフェスト（v0.2.0）
```

## コマーシャルサポートとライセンス

wolfSSL Inc. は、zig-wolfssl およびその基盤となる wolfSSL エコシステム（wolfCrypt、wolfHSM、wolfProvider）に対して、コマーシャルサポート、コンサルティング、インテグレーションサービス、および NRE を提供しています。GPL-3.0 のコピーレフト条件が受け入れられない環境向けに、wolfSSL のコマーシャルライセンスも提供しています。

| 用途 | 連絡先 |
|------|--------|
| 一般的な質問、移植、FIPS | facts@wolfssl.com |
| コマーシャルライセンス | licensing@wolfssl.com |
| テクニカルサポート | support@wolfssl.com |
| 電話 | +1 (425) 245-8247 |
| Web | https://www.wolfssl.com/contact/ |

## ライセンス

zig-wolfssl は wolfSSL Inc. の著作物（Copyright (C) 2026）であり、GNU General Public License v3.0（GPL-3.0）のもとでライセンスされています。詳細は
[https://www.gnu.org/licenses/gpl-3.0.html](https://www.gnu.org/licenses/gpl-3.0.html) をご参照ください。

**コマーシャル** -- GPL-3.0 のコピーレフト条件がご利用の環境（プロプライエタリ製品、クローズドソース配布、OEM 組み込み）で受け入れられない場合、wolfSSL Inc. はコピーレフト義務を免除するコマーシャルライセンスを販売しています。
[licensing@wolfssl.com](mailto:licensing@wolfssl.com) または +1 (425) 245-8247 までお問い合わせください。

**wolfSSL / wolfCrypt**（必須依存関係）：同じデュアルライセンスが適用されます -- オープンソース利用には GPL-3.0、プロプライエタリ展開には wolfSSL Inc. からのコマーシャルライセンスが必要です。GPL-3.0 のもとで wolfSSL に対して zig-wolfssl をリンクした製品を配布すると、結合された成果物全体に GPL-3.0 のコピーレフトが適用されます。

**FIPS 140-3**: wolfCrypt は現行の FIPS 140-3 認証（#4718）を保有しています。FIPS 対応の展開には、別途ライセンスされた wolfCrypt FIPS バウンダリビルドが必要です。標準のオープンソース wolfSSL ビルドは検証済みモジュールではありません。

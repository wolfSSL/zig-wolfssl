const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const wolfssl_src = resolveWolfSslSrcDir(b);
    const wolfssl_certs_dir = resolveWolfSslCertsDir(b, wolfssl_src);

    // -- Zig module wrapping wolfSSL (discovered via pkg-config) --
    const wolfssl_mod = b.addModule("wolfssl", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    configureWolfSslModule(b, wolfssl_mod, wolfssl_src);

    // -- Library artifact (for consumers who want a .a / .so) --
    const lib = b.addLibrary(.{
        .linkage = .static,
        .name = "zig-wolfssl",
        .root_module = createWolfSslModule(b, target, optimize, wolfssl_src),
    });
    b.installArtifact(lib);

    // -- Tests --
    const test_mod = createWolfSslModule(b, target, optimize, wolfssl_src);

    const options = b.addOptions();
    options.addOption([]const u8, "wolfssl_certs_dir", wolfssl_certs_dir);
    test_mod.addOptions("build_options", options);

    const tests = b.addTest(.{
        .root_module = test_mod,
    });

    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_tests.step);
}

/// Resolve the wolfSSL source tree root via three mechanisms, in priority order:
/// 1. -Dwolfssl-src=<path>   build option
/// 2. WOLFSSL_SRC            environment variable
/// 3. pkg-config pcfiledir   if the directory (or its parent) contains a "certs"
///                           subdirectory, it is treated as the wolfSSL source root.
///                           This covers uninstalled source builds where wolfssl.pc
///                           lives at $src/ or $src/.libs/.
/// Returns null when none of the above succeed.
fn resolveWolfSslSrcDir(b: *std.Build) ?[]const u8 {
    // 1. Explicit build option.
    if (b.option([]const u8, "wolfssl-src", "Path to wolfSSL source tree root")) |v|
        return v;

    // 2. Environment variable.
    if (b.graph.environ_map.get("WOLFSSL_SRC")) |v|
        return v;

    // 3. pkg-config pcfiledir (useful when wolfSSL was built but not installed).
    var exit_code: u8 = undefined;
    if (b.runAllowFail(&.{ "pkg-config", "--variable=pcfiledir", "wolfssl" }, &exit_code, .ignore) catch null) |stdout| {
        const pcfiledir = std.mem.trimEnd(u8, stdout, " \n\r\t");
        // Check pcfiledir itself, then its parent. Uninstalled builds put wolfssl.pc
        // at $src/ or $src/.libs/ depending on the build configuration.
        var candidates: [2][]const u8 = undefined;
        var n: usize = 0;
        if (pcfiledir.len > 0) {
            candidates[n] = pcfiledir;
            n += 1;
        }
        if (std.fs.path.dirname(pcfiledir)) |parent| {
            candidates[n] = parent;
            n += 1;
        }
        for (candidates[0..n]) |candidate| {
            const certs = b.pathJoin(&.{ candidate, "certs" });
            if (std.Io.Dir.openDirAbsolute(b.graph.io, certs, .{})) |dir| {
                dir.close(b.graph.io);
                return candidate;
            } else |_| {}
        }
    }

    return null;
}

/// Ensure the path ends with a "/", as required by the comptime concatenation in tests.zig.
fn withTrailingSlash(b: *std.Build, path: []const u8) []const u8 {
    if (path.len > 0 and path[path.len - 1] == '/') return path;
    return std.fmt.allocPrint(b.allocator, "{s}/", .{path}) catch path;
}

/// Resolve the wolfSSL test certificates directory via four mechanisms, in priority order:
/// 1. -Dwolfssl-certs-dir=<path>   build option
/// 2. WOLFSSL_CERTS_DIR            environment variable
/// 3. wolfSSL source root + "/certs/" (derived from resolveWolfSslSrcDir)
/// 4. pkg-config prefix + "/share/wolfssl/certs/" (only if that directory exists)
/// Returns "" when none of the above produce an accessible directory.
/// All non-empty return values are guaranteed to end with "/".
fn resolveWolfSslCertsDir(b: *std.Build, wolfssl_src: ?[]const u8) []const u8 {
    // 1. Explicit build option.
    if (b.option([]const u8, "wolfssl-certs-dir", "Path to wolfSSL test certificates directory")) |v|
        return withTrailingSlash(b, v);

    // 2. Environment variable.
    if (b.graph.environ_map.get("WOLFSSL_CERTS_DIR")) |v|
        return withTrailingSlash(b, v);

    // 3. Derive from wolfSSL source root.
    if (wolfssl_src) |src| {
        const candidate = b.pathJoin(&.{ src, "certs" });
        if (std.Io.Dir.openDirAbsolute(b.graph.io, candidate, .{})) |dir| {
            dir.close(b.graph.io);
            return withTrailingSlash(b, candidate);
        } else |_| {}
    }

    // 4. Derive from pkg-config prefix.
    var exit_code: u8 = undefined;
    if (b.runAllowFail(&.{ "pkg-config", "--variable=prefix", "wolfssl" }, &exit_code, .ignore) catch null) |stdout| {
        const prefix = std.mem.trimEnd(u8, stdout, " \n\r\t");
        if (prefix.len > 0) {
            const candidate = b.pathJoin(&.{ prefix, "share", "wolfssl", "certs" });
            if (std.Io.Dir.openDirAbsolute(b.graph.io, candidate, .{})) |dir| {
                dir.close(b.graph.io);
                return withTrailingSlash(b, candidate);
            } else |_| {}
        }
    }

    return "";
}

fn configureWolfSslModule(b: *std.Build, mod: *std.Build.Module, wolfssl_src: ?[]const u8) void {
    _ = wolfssl_src;
    mod.linkSystemLibrary("wolfssl", .{});
    mod.addCSourceFile(.{ .file = b.path("src/sizeof_helpers.c"), .flags = &.{} });
}

fn createWolfSslModule(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, wolfssl_src: ?[]const u8) *std.Build.Module {
    const mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    configureWolfSslModule(b, mod, wolfssl_src);
    return mod;
}

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const wolfssl_certs_dir = b.option([]const u8, "wolfssl-certs-dir", "Path to wolfSSL test certificates directory (e.g. /path/to/wolfssl/certs/)") orelse "";

    // -- Zig module wrapping wolfSSL (discovered via pkg-config) --
    const wolfssl_mod = b.addModule("wolfssl", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    configureWolfSslModule(b, wolfssl_mod);

    // -- Library artifact (for consumers who want a .a / .so) --
    const lib = b.addLibrary(.{
        .linkage = .static,
        .name = "wolfssl-zig",
        .root_module = createWolfSslModule(b, target, optimize),
    });
    b.installArtifact(lib);

    // -- Tests --
    const test_mod = createWolfSslModule(b, target, optimize);

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

fn configureWolfSslModule(b: *std.Build, mod: *std.Build.Module) void {
    mod.linkSystemLibrary("wolfssl", .{});
    mod.addCSourceFile(.{ .file = b.path("src/sizeof_helpers.c"), .flags = &.{} });
}

fn createWolfSslModule(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Module {
    const mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    configureWolfSslModule(b, mod);
    return mod;
}

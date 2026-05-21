const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // The public library module — consumers `@import("tweetnacl_zig")`.
    const mod = b.addModule("tweetnacl_zig", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Static library artifact.
    const lib = b.addLibrary(.{
        .name = "tweetnacl-zig",
        .root_module = mod,
        .linkage = .static,
    });
    b.installArtifact(lib);

    // `zig build test` — testing the root module covers every file it imports.
    const lib_tests = b.addTest(.{ .root_module = mod });
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&b.addRunArtifact(lib_tests).step);

    // Examples: `zig build <name>` builds and runs each one.
    const example_names = [_][]const u8{ "salsa20_demo", "xsalsa20_demo", "secretbox_demo" };
    inline for (example_names) |name| {
        const exe = b.addExecutable(.{
            .name = name,
            .root_module = b.createModule(.{
                .root_source_file = b.path("examples/" ++ name ++ ".zig"),
                .target = target,
                .optimize = optimize,
                .imports = &.{.{ .name = "tweetnacl_zig", .module = mod }},
            }),
        });
        b.installArtifact(exe);
        const run_step = b.step(name, "Build and run the " ++ name ++ " example");
        run_step.dependOn(&b.addRunArtifact(exe).step);
    }
}

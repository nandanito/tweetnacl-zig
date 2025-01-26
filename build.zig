const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Create a module
    const tweetnacl_mod = b.addModule("tweetnacl-zig", .{
        .root_source_file = b.path("src/root.zig"),
    });

    // Create the static library with the module
    const lib = b.addStaticLibrary(.{
        .name = "tweetnacl-zig",
        .root_source_file = tweetnacl_mod.root_source_file,
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(lib);

    // Create the main executable
    const exe = b.addExecutable(.{
        .name = "tweetnacl-zig",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    exe.root_module.addImport("tweetnacl-zig", tweetnacl_mod);
    b.installArtifact(exe);

    // Execute the example for salsa20
    const example_salsa20 = b.addExecutable(.{
        .name = "salsa20_demo",
        .root_source_file = b.path("examples/salsa20_demo.zig"),
        .target = target,
        .optimize = optimize,
    });
    example_salsa20.root_module.addImport("tweetnacl-zig", tweetnacl_mod);
    b.installArtifact(example_salsa20);

    // Add run step for salsa20_demo
    const run_cmd_salsa20 = b.addRunArtifact(example_salsa20);
    const run_step_salsa20 = b.step("salsa20_demo", "Run the salsa20 demo");
    run_step_salsa20.dependOn(&run_cmd_salsa20.step);

    // Execute the example for xsalsa20
    const example_xsalsa20 = b.addExecutable(.{
        .name = "xsalsa20_demo",
        .root_source_file = b.path("examples/xsalsa20_demo.zig"),
        .target = target,
        .optimize = optimize,
    });
    example_xsalsa20.root_module.addImport("tweetnacl-zig", tweetnacl_mod);
    b.installArtifact(example_xsalsa20);

    // Add run step for xsalsa20_demo
    const run_cmd_xsalsa20 = b.addRunArtifact(example_xsalsa20);
    const run_step_xsalsa20 = b.step("xsalsa20_demo", "Run the xsalsa20 demo");
    run_step_xsalsa20.dependOn(&run_cmd_xsalsa20.step);

    // Consolidate test creation into a helper function
    const lib_unit_tests = addTest(b, "src/root.zig", target, optimize);
    const example_salsa20_unit_tests = addTest(b, "examples/salsa20_demo.zig", target, optimize);
    const exe_unit_tests = addTest(b, "src/main.zig", target, optimize);

    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);
    const run_example_salsa20_unit_tests = b.addRunArtifact(example_salsa20_unit_tests);
    const run_exe_unit_tests = b.addRunArtifact(exe_unit_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);
    test_step.dependOn(&run_exe_unit_tests.step);
    test_step.dependOn(&run_example_salsa20_unit_tests.step);
}

// Helper function to create test executables
fn addTest(b: *std.Build, root_source: []const u8, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Step.Compile {
    return b.addTest(.{
        .root_source_file = b.path(root_source),
        .target = target,
        .optimize = optimize,
    });
}

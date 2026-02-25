const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "example-app",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    const host = b.graph.host.result;
    const dep_name = tigercheck_dep_name(host);
    const dep = b.dependency(dep_name, .{});

    const tigercheck_target = b.option(
        []const u8,
        "tigercheck-target",
        "Path for tigercheck to analyze",
    ) orelse "src";

    const tigercheck_bin = dep.path(switch (host.os.tag) {
        .windows => "tigercheck.exe",
        else => "tigercheck",
    });

    const tigercheck_cmd = std.Build.Step.Run.create(b, "run tigercheck");
    tigercheck_cmd.addFileArg(tigercheck_bin);
    tigercheck_cmd.addArgs(&.{
        "--format",
        "text",
        tigercheck_target,
    });

    const tigercheck_step = b.step("tigercheck", "Run tigercheck");
    tigercheck_step.dependOn(&tigercheck_cmd.step);

    const check = b.step("check", "Compile + tigercheck");
    check.dependOn(&exe.step);
    check.dependOn(tigercheck_step);
}

fn tigercheck_dep_name(host: std.Target) []const u8 {
    return switch (host.os.tag) {
        .linux => switch (host.cpu.arch) {
            .x86_64 => "tigercheck_x86_64_linux",
            .aarch64 => "tigercheck_aarch64_linux",
            else => @panic("unsupported linux arch"),
        },
        .macos => switch (host.cpu.arch) {
            .aarch64 => "tigercheck_aarch64_macos",
            else => @panic("unsupported macos arch"),
        },
        else => @panic("unsupported host"),
    };
}

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const style_path = b.option([]const u8, "style-path", "Path for style check") orelse "./src";
    const style_profile = b.option(
        []const u8,
        "style-profile",
        "Style profile: strict_core or tigerbeetle_repo",
    ) orelse "strict_core";
    const default_perf_budget_ms: u64 = switch (optimize) {
        .Debug => 30000,
        .ReleaseSafe, .ReleaseFast, .ReleaseSmall => 200,
    };
    const perf_budget_ms = b.option(
        u64,
        "perf-budget-ms",
        "Perf budget for check-strict/bench (ms)",
    ) orelse default_perf_budget_ms;

    const libtiger_module = b.createModule(.{
        .root_source_file = b.path("src/libtiger/libtiger.zig"),
        .target = target,
        .optimize = optimize,
    });

    const exe = b.addExecutable(.{
        .name = "tigercheck",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/tigercheck/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    exe.root_module.addImport("libtiger", libtiger_module);
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    const run_step = b.step("run", "Run tigercheck");
    run_step.dependOn(&run_cmd.step);

    const check_cmd = b.addRunArtifact(exe);
    check_cmd.addArg("--profile");
    check_cmd.addArg(style_profile);
    check_cmd.addArg(style_path);
    const check_step = b.step("check", "Run style check with profile");
    check_step.dependOn(&check_cmd.step);

    const check_strict_cmd = b.addRunArtifact(exe);
    check_strict_cmd.addArg("--profile");
    check_strict_cmd.addArg("strict_core");
    check_strict_cmd.addArg(style_path);
    const check_strict_step = b.step("check-strict", "Run strict-core style check");
    check_strict_step.dependOn(&check_strict_cmd.step);

    const perf_bench = b.addExecutable(.{
        .name = "perf-bench",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/tools/perf_bench.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const perf_bench_cmd = b.addRunArtifact(perf_bench);
    perf_bench_cmd.addFileArg(exe.getEmittedBin());
    perf_bench_cmd.addArg(b.fmt("{d}", .{perf_budget_ms}));
    perf_bench_cmd.addArg(style_path);

    const bench_step = b.step("bench", "Run performance benchmark budget checks");
    bench_step.dependOn(&perf_bench_cmd.step);
    check_strict_step.dependOn(&perf_bench_cmd.step);

    const lib_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/libtiger/libtiger.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_lib_tests = b.addRunArtifact(lib_tests);

    const exe_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/tigercheck/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    exe_tests.root_module.addImport("libtiger", libtiger_module);
    const run_exe_tests = b.addRunArtifact(exe_tests);

    const test_step = b.step("test", "Run all tests");
    test_step.dependOn(&run_lib_tests.step);
    test_step.dependOn(&run_exe_tests.step);

    const corpus_runner = b.addExecutable(.{
        .name = "corpus-runner",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/tools/corpus_runner.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    const run_corpus = b.addRunArtifact(corpus_runner);
    run_corpus.addFileArg(exe.getEmittedBin());
    run_corpus.addArg("tests/corpus");
    test_step.dependOn(&run_corpus.step);

    const corpus_audit = b.addExecutable(.{
        .name = "corpus-audit",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/tools/corpus_audit.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    corpus_audit.root_module.addImport("libtiger", libtiger_module);

    const run_corpus_audit = b.addRunArtifact(corpus_audit);
    run_corpus_audit.addArg("tests/corpus");
    const corpus_audit_step = b.step("corpus-audit", "Audit corpus naming and rule coverage");
    corpus_audit_step.dependOn(&run_corpus_audit.step);
    test_step.dependOn(&run_corpus_audit.step);

    const precision_harness = b.addExecutable(.{
        .name = "precision-harness",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/tools/precision_harness.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    precision_harness.root_module.addImport("libtiger", libtiger_module);

    const precision_check_cmd = b.addRunArtifact(precision_harness);
    precision_check_cmd.addFileArg(exe.getEmittedBin());
    precision_check_cmd.addArg("tests/corpus");
    precision_check_cmd.addArg("tests/corpus/precision-baseline.json");
    precision_check_cmd.addArg("zig-out/precision-current.json");
    precision_check_cmd.addArg("--check-baseline");

    const precision_check_step = b.step("precision-check", "Run precision regression checks");
    precision_check_step.dependOn(&precision_check_cmd.step);

    const precision_write_cmd = b.addRunArtifact(precision_harness);
    precision_write_cmd.addFileArg(exe.getEmittedBin());
    precision_write_cmd.addArg("tests/corpus");
    precision_write_cmd.addArg("tests/corpus/precision-baseline.json");
    precision_write_cmd.addArg("zig-out/precision-current.json");
    precision_write_cmd.addArg("--write-baseline");

    const precision_write_step = b.step(
        "precision-write-baseline",
        "Generate precision baseline from current corpus",
    );
    precision_write_step.dependOn(&precision_write_cmd.step);
}

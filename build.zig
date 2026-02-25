const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const style_path = b.option([]const u8, "style-path", "Path for style check") orelse "./src";
    const off_rules = b.option(
        []const u8,
        "off-rules",
        "Comma-separated rule IDs forced to off action",
    ) orelse "";
    const default_perf_budget_ms: u64 = switch (optimize) {
        .Debug => 3000,
        .ReleaseSafe, .ReleaseFast, .ReleaseSmall => 200,
    };
    const perf_budget_ms = b.option(
        u64,
        "perf-budget-ms",
        "Perf budget for check-strict/bench (ms)",
    ) orelse default_perf_budget_ms;
    const corpus_min_cases_per_kind = b.option(
        u32,
        "corpus-min-cases-per-kind",
        "Corpus audit minimum pass/fail cases per rule prefix",
    ) orelse 1;
    const corpus_strict_min_cases = b.option(
        bool,
        "corpus-strict-min-cases",
        "Fail corpus-audit when prefix depth is below minimum",
    ) orelse false;

    const checker_build_options = b.addOptions();
    checker_build_options.addOption([]const u8, "off_rules", off_rules);

    const libtigercheck_module = b.createModule(.{
        .root_source_file = b.path("src/libtigercheck/libtigercheck.zig"),
        .target = target,
        .optimize = optimize,
    });
    libtigercheck_module.addOptions("build_options", checker_build_options);

    const exe = b.addExecutable(.{
        .name = "tigercheck",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/tigercheck/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    exe.root_module.addImport("libtigercheck", libtigercheck_module);
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    const run_step = b.step("run", "Run tigercheck");
    run_step.dependOn(&run_cmd.step);

    const check_cmd = b.addRunArtifact(exe);
    check_cmd.addArg(style_path);
    const check_step = b.step("check", "Run style check");
    check_step.dependOn(&check_cmd.step);

    const check_strict_cmd = b.addRunArtifact(exe);
    check_strict_cmd.addArg(style_path);
    const check_strict_step = b.step("check-strict", "Run core style check");
    check_strict_step.dependOn(&check_strict_cmd.step);

    const perf_bench = b.addExecutable(.{
        .name = "perf-bench",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/tools/perf_bench.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
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
            .root_source_file = b.path("src/libtigercheck/libtigercheck.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    lib_tests.root_module.addOptions("build_options", checker_build_options);
    const run_lib_tests = b.addRunArtifact(lib_tests);

    const exe_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/tigercheck/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    exe_tests.root_module.addImport("libtigercheck", libtigercheck_module);
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
    corpus_audit.root_module.addImport("libtigercheck", libtigercheck_module);

    const run_corpus_audit = b.addRunArtifact(corpus_audit);
    run_corpus_audit.addArg("tests/corpus");
    if (corpus_min_cases_per_kind > 1) {
        run_corpus_audit.addArg("--min-cases-per-kind");
        run_corpus_audit.addArg(b.fmt("{d}", .{corpus_min_cases_per_kind}));
    }
    if (corpus_strict_min_cases) {
        run_corpus_audit.addArg("--strict-min-cases");
    }
    const corpus_audit_step = b.step("corpus-audit", "Audit corpus naming and rule coverage");
    corpus_audit_step.dependOn(&run_corpus_audit.step);
    test_step.dependOn(&run_corpus_audit.step);

    const run_corpus_audit_strict = b.addRunArtifact(corpus_audit);
    run_corpus_audit_strict.addArg("tests/corpus");
    run_corpus_audit_strict.addArg("--min-cases-per-kind");
    run_corpus_audit_strict.addArg("2");
    run_corpus_audit_strict.addArg("--strict-min-cases");
    const corpus_audit_strict_step = b.step(
        "corpus-audit-strict",
        "Audit corpus with strict minimum per-prefix depth",
    );
    corpus_audit_strict_step.dependOn(&run_corpus_audit_strict.step);

    const precision_harness = b.addExecutable(.{
        .name = "precision-harness",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/tools/precision_harness.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    precision_harness.root_module.addImport("libtigercheck", libtigercheck_module);

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

    const release_exe = b.addExecutable(.{
        .name = "release",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/tools/release.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    const run_release = b.addRunArtifact(release_exe);
    run_release.addArg("release");
    if (b.args) |args| {
        run_release.addArgs(args);
    }
    const release_step = b.step("release", "Run release automation flow");
    release_step.dependOn(&run_release.step);

    const run_release_validate = b.addRunArtifact(release_exe);
    run_release_validate.addArg("validate");
    if (b.args) |args| {
        run_release_validate.addArgs(args);
    }
    const release_validate_step = b.step(
        "release-validate",
        "Run release validation automation flow",
    );
    release_validate_step.dependOn(&run_release_validate.step);
}

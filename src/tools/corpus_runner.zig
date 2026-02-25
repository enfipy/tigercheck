const std = @import("std");
const assert = std.debug.assert;
const corpus_common = @import("corpus_common.zig");

const RunStats = struct {
    passed: usize = 0,
    failed: usize = 0,
    errs: usize = 0,
};

const ExpectedRulePrefixes = struct {
    primary: ?[]const u8 = null,
    fallback: ?[]const u8 = null,
};

const ExpectationDirectives = struct {
    rule_id: ?[]const u8 = null,
    message_substring: ?[]const u8 = null,
};

const JSONDiagnostic = struct {
    rule_id: []const u8,
    message: []const u8,
};

const JSONRunOutput = struct {
    schema_version: u32,
    diagnostics: []const JSONDiagnostic,
};

const TestObservation = struct {
    expected_prefixes: ExpectedRulePrefixes,
    expected_rule_seen: bool,
    expected_message_seen: bool,
    exited_ok: bool,
    test_passed: bool,
};

pub fn main(init: std.process.Init) !void {
    var args = init.minimal.args.iterate();
    const argv0 = args.next(); // skip argv[0]
    assert(argv0 != null);
    const tiger_check_bin = args.next() orelse fatal("missing tigercheck binary path argument");
    const corpus_dir = args.next() orelse fatal("missing corpus directory argument");
    assert(tiger_check_bin.len > 0);
    assert(corpus_dir.len > 0);

    var stdout_buf: [4096]u8 = undefined;
    const io = init.io;
    var stdout_writer = std.Io.File.stdout().writerStreaming(io, &stdout_buf);
    const stdout = &stdout_writer.interface;

    try stdout.print("corpus-runner: binary={s} corpus={s}\n", .{ tiger_check_bin, corpus_dir });

    const allocator = init.gpa;
    var test_files = std.array_list.Managed([]const u8).init(allocator);
    defer corpus_common.deinit_owned_paths(allocator, &test_files);
    try corpus_common.collect_zig_files(allocator, corpus_dir, &test_files);
    corpus_common.sort_paths(&test_files);

    var stats = RunStats{};

    for (test_files.items) |file_path| {
        try process_test_file(allocator, io, stdout, tiger_check_bin, file_path, &stats);
    }

    try stdout.print("\ncorpus-runner: {d} passed, {d} failed, {d} errors, {d} total\n", .{
        stats.passed,
        stats.failed,
        stats.errs,
        test_files.items.len,
    });
    try stdout.flush();

    if (stats.failed > 0 or stats.errs > 0) {
        std.process.exit(1);
    }
}

fn process_test_file(
    allocator: std.mem.Allocator,
    io: std.Io,
    stdout: *std.Io.Writer,
    tiger_check_bin: []const u8,
    file_path: []const u8,
    stats: *RunStats,
) !void {
    assert(file_path.len > 0);
    assert(tiger_check_bin.len > 0);
    if (file_path.len == 0) return error.InvalidInputPath;
    if (tiger_check_bin.len == 0) return error.InvalidInputPath;

    const basename = std.fs.path.basename(file_path);
    const expect_pass = corpus_common.is_pass_case_basename(basename);
    const expect_fail = corpus_common.is_fail_case_basename(basename);

    if (!test_file_has_expected_prefix(expect_pass, expect_fail)) {
        try stdout.print("  SKIP  {s} (no pass_/fail_ prefix)\n", .{basename});
        return;
    }

    var argv = std.array_list.Managed([]const u8).init(allocator);
    defer argv.deinit();
    try argv.append(tiger_check_bin);
    try argv.append("--format");
    try argv.append("json");
    if (profile_for_test_file(file_path)) |profile_name| {
        try argv.append("--profile");
        try argv.append(profile_name);
    }
    try argv.append(file_path);

    const result = std.process.run(allocator, io, .{
        .argv = argv.items,
    }) catch |err| {
        try stdout.print("  ERROR {s}: failed to spawn tigercheck: {}\n", .{ basename, err });
        stats.errs += 1;
        return;
    };
    defer {
        allocator.free(result.stdout);
        allocator.free(result.stderr);
    }

    const parsed_output = std.json.parseFromSlice(
        JSONRunOutput,
        allocator,
        result.stdout,
        .{ .allocate = .alloc_always, .ignore_unknown_fields = true },
    ) catch |err| {
        try stdout.print(
            "  ERROR {s}: invalid tigercheck JSON output: {}\n",
            .{ basename, err },
        );
        stats.errs += 1;
        return;
    };
    defer parsed_output.deinit();

    const directives = try parse_expectation_directives(allocator, file_path);
    defer {
        if (directives.rule_id) |rule_id| allocator.free(rule_id);
        if (directives.message_substring) |msg| allocator.free(msg);
    }

    const observation = observe_test_result(
        basename,
        expect_pass,
        parsed_output.value.diagnostics,
        result.term,
        directives,
    );

    if (observation.test_passed) {
        try stdout.print("  PASS  {s}\n", .{basename});
        stats.passed += 1;
        return;
    }

    try report_test_failure(
        stdout,
        basename,
        expect_pass,
        expect_fail,
        result,
        directives,
        observation,
    );
    stats.failed += 1;
}

fn test_file_has_expected_prefix(expect_pass: bool, expect_fail: bool) bool {
    if (expect_pass) return true;
    return expect_fail;
}

fn profile_for_test_file(file_path: []const u8) ?[]const u8 {
    assert(file_path.len > 0);
    if (file_path.len == 0) return null;
    if (corpus_common.is_tigerbeetle_corpus_file(file_path)) {
        return "tigerbeetle_repo";
    }
    return null;
}

fn observe_test_result(
    basename: []const u8,
    expect_pass: bool,
    diagnostics: []const JSONDiagnostic,
    term: std.process.Child.Term,
    directives: ExpectationDirectives,
) TestObservation {
    assert(basename.len > 0);
    if (basename.len == 0) {
        return .{
            .expected_prefixes = .{},
            .expected_rule_seen = false,
            .expected_message_seen = false,
            .exited_ok = false,
            .test_passed = false,
        };
    }
    const expected_prefixes = expected_rule_prefixes_for_fail_case(basename);
    const expected_rule_seen = expected_output_matches_expectation(
        diagnostics,
        expected_prefixes,
        directives.rule_id,
    );
    const expected_message_seen = expected_output_matches_message(
        diagnostics,
        directives.message_substring,
    );
    const exited_ok = switch (term) {
        .exited => |code| code == 0,
        .signal, .stopped, .unknown => false,
    };
    var test_passed = false;
    if (expect_pass) {
        test_passed = exited_ok;
    } else {
        test_passed = !exited_ok and expected_rule_seen and expected_message_seen;
    }

    return .{
        .expected_prefixes = expected_prefixes,
        .expected_rule_seen = expected_rule_seen,
        .expected_message_seen = expected_message_seen,
        .exited_ok = exited_ok,
        .test_passed = test_passed,
    };
}

fn report_test_failure(
    stdout: *std.Io.Writer,
    basename: []const u8,
    expect_pass: bool,
    expect_fail: bool,
    result: std.process.RunResult,
    directives: ExpectationDirectives,
    observation: TestObservation,
) !void {
    assert(basename.len > 0);
    assert(!observation.test_passed);
    assert(!expect_pass or !expect_fail);
    if (basename.len == 0) return;
    if (expect_pass and expect_fail) return;
    const exit_code: u32 = switch (result.term) {
        .exited => |code| code,
        .signal => |sig| @intFromEnum(sig),
        .stopped => |v| v,
        .unknown => |v| v,
    };
    const expected_outcome = expected_outcome_label(expect_pass);

    try stdout.print("  FAIL  {s} (expected {s}, got exit={d})\n", .{
        basename,
        expected_outcome,
        exit_code,
    });
    try print_failure_expectations(stdout, expect_fail, directives, observation);
    try print_process_output(stdout, result);
}

fn expected_outcome_label(expect_pass: bool) []const u8 {
    if (expect_pass) return "pass (exit 0)";
    return "fail (exit != 0)";
}

fn print_failure_expectations(
    stdout: *std.Io.Writer,
    expect_fail: bool,
    directives: ExpectationDirectives,
    observation: TestObservation,
) !void {
    if (expect_fail and !observation.expected_rule_seen) {
        try print_expected_rule_expectation(
            stdout,
            observation.expected_prefixes,
            directives.rule_id,
        );
    }
    if (expect_fail and !observation.expected_message_seen) {
        if (directives.message_substring) |msg| {
            try stdout.print(
                "        expected message substring: \"{s}\" (not found in diagnostics)\n",
                .{msg},
            );
        }
    }
}

fn print_process_output(stdout: *std.Io.Writer, result: std.process.RunResult) !void {
    if (result.stdout.len > 0) {
        try stdout.print("        stdout: {s}\n", .{std.mem.trimEnd(u8, result.stdout, "\n")});
    }
    if (result.stderr.len > 0) {
        try stdout.print("        stderr: {s}\n", .{std.mem.trimEnd(u8, result.stderr, "\n")});
    }
}

fn expected_rule_prefixes_for_fail_case(basename: []const u8) ExpectedRulePrefixes {
    assert(basename.len > 0);
    assert(basename.len <= 255);
    if (basename.len == 0) return .{};
    var out = ExpectedRulePrefixes{};
    if (!corpus_common.is_fail_case_basename(basename)) return out;
    if (!corpus_common.is_zig_case_file(basename)) return out;
    const stem_start = corpus_common.case_fail_prefix().len;
    const stem_end = basename.len - corpus_common.zig_file_extension().len;
    const stem = basename[stem_start..stem_end];
    const sep = std.mem.indexOfScalar(u8, stem, '_') orelse return out;
    if (sep == 0) return out;
    const prefix = stem[0..sep];
    out.primary = prefix;
    out.fallback = corpus_common.fallback_rule_prefix(prefix);
    return out;
}

fn parse_expectation_directives(
    allocator: std.mem.Allocator,
    file_path: []const u8,
) !ExpectationDirectives {
    assert(file_path.len > 0);
    if (file_path.len == 0) return error.InvalidInputPath;
    const source = try std.Io.Dir.cwd().readFileAllocOptions(
        std.Options.debug_io,
        file_path,
        allocator,
        std.Io.Limit.limited(128 * 1024),
        .of(u8),
        0,
    );
    defer allocator.free(source);

    var out = ExpectationDirectives{};
    var line_start: usize = 0;
    for (source, 0..) |byte, index| {
        if (byte != '\n') continue;
        try parse_expectation_directive_line(allocator, source[line_start..index], &out);
        line_start = index + 1;
    }
    if (line_start < source.len) {
        try parse_expectation_directive_line(allocator, source[line_start..], &out);
    }
    return out;
}

fn parse_expectation_directive_line(
    allocator: std.mem.Allocator,
    line: []const u8,
    out: *ExpectationDirectives,
) !void {
    assert(line.len <= std.math.maxInt(u32));
    assert(out.rule_id == null or out.rule_id.?.len > 0);
    if (line.len == 0) return;
    const trimmed = std.mem.trim(u8, line, " \t\r");
    if (std.mem.startsWith(u8, trimmed, "// expect-rule:")) {
        const value = std.mem.trim(u8, trimmed[15..], " \t\r");
        if (value.len > 0) {
            out.rule_id = try allocator.dupe(u8, value);
        }
        return;
    }

    if (std.mem.startsWith(u8, trimmed, "// expect-msg:")) {
        const value = std.mem.trim(u8, trimmed[14..], " \t\r");
        if (value.len > 0) {
            out.message_substring = try allocator.dupe(u8, value);
        }
    }
}

fn expected_output_matches_expectation(
    diagnostics: []const JSONDiagnostic,
    expected_prefixes: ExpectedRulePrefixes,
    direct_rule_id: ?[]const u8,
) bool {
    assert(direct_rule_id == null or direct_rule_id.?.len > 0);
    assert(expected_prefixes.primary != null or expected_prefixes.fallback == null);
    if (diagnostics.len == 0 and direct_rule_id != null) {
        return false;
    }
    if (direct_rule_id) |rule_id| {
        if (rule_id.len == 0) return false;
        return diagnostics_mention_rule_id(diagnostics, rule_id);
    }
    return expected_output_matches_rule_prefixes(diagnostics, expected_prefixes);
}

fn expected_output_matches_message(
    diagnostics: []const JSONDiagnostic,
    message_substring: ?[]const u8,
) bool {
    assert(message_substring == null or message_substring.?.len > 0);
    assert(diagnostics.len <= 4096);
    if (diagnostics.len == 0 and message_substring != null) {
        return false;
    }
    const expected = message_substring orelse return true;
    assert(expected.len > 0);
    if (expected.len == 0) return false;
    for (diagnostics) |diag| {
        if (std.mem.indexOf(u8, diag.message, expected) != null) {
            return true;
        }
    }
    return false;
}

fn expected_output_matches_rule_prefixes(
    diagnostics: []const JSONDiagnostic,
    expected: ExpectedRulePrefixes,
) bool {
    assert(diagnostics.len <= 4096);
    assert(expected.primary != null or expected.fallback == null);
    assert(expected.primary == null or expected.primary.?.len > 0);
    assert(expected.fallback == null or expected.fallback.?.len > 0);
    if (diagnostics.len > 4096) {
        return false;
    }
    if (expected.fallback != null and expected.primary == null) {
        return false;
    }
    if (diagnostics.len == 0) {
        return expected.primary == null;
    }
    const primary = expected.primary orelse return true;
    if (primary.len == 0) return false;
    if (!diagnostics_mention_rule_prefix(diagnostics, primary)) {
        if (expected.fallback) |fallback| {
            if (fallback.len == 0) return false;
            return diagnostics_mention_rule_prefix(diagnostics, fallback);
        }
        return false;
    }
    return true;
}

fn diagnostics_mention_rule_id(diagnostics: []const JSONDiagnostic, rule_id: []const u8) bool {
    assert(rule_id.len > 0);
    if (rule_id.len == 0) return false;
    for (diagnostics) |diag| {
        if (std.mem.eql(u8, diag.rule_id, rule_id)) {
            return true;
        }
    }
    return false;
}

fn print_expected_rule_expectation(
    stdout: *std.Io.Writer,
    expected: ExpectedRulePrefixes,
    direct_rule_id: ?[]const u8,
) !void {
    assert(direct_rule_id != null or expected.primary != null or expected.fallback == null);
    if (direct_rule_id == null) {
        if (expected.primary == null and expected.fallback != null) {
            return;
        }
    }
    if (direct_rule_id) |rule_id| {
        assert(rule_id.len > 0);
        if (rule_id.len == 0) return;
        try stdout.print(
            "        expected rule id: [{s}] (not found in diagnostics)\n",
            .{rule_id},
        );
        return;
    }

    const primary = expected.primary orelse return;
    if (expected.fallback) |fallback| {
        try stdout.print(
            "        expected rule prefix: [{s}_ or [{s}_ (not found in diagnostics)\n",
            .{ primary, fallback },
        );
        return;
    }
    try stdout.print(
        "        expected rule prefix: [{s}_ (not found in diagnostics)\n",
        .{primary},
    );
}

fn diagnostics_mention_rule_prefix(diagnostics: []const JSONDiagnostic, prefix: []const u8) bool {
    assert(prefix.len > 0);
    if (prefix.len == 0) return false;
    for (diagnostics) |diag| {
        const sep = std.mem.indexOfScalar(u8, diag.rule_id, '_') orelse continue;
        if (std.mem.eql(u8, diag.rule_id[0..sep], prefix)) {
            return true;
        }
    }
    return false;
}

fn fatal(msg: []const u8) noreturn {
    assert(msg.len > 0);
    if (msg.len == 0) {
        std.debug.print("corpus-runner: fatal\n", .{});
        std.process.exit(2);
        unreachable;
    }
    std.debug.print("corpus-runner: {s}\n", .{msg});
    std.process.exit(2);
}

const std = @import("std");
const assert = std.debug.assert;
const libtigercheck = @import("libtigercheck");
const rules = libtigercheck.rules;
const corpus_common = @import("corpus_common.zig");

const rule_count: usize = @typeInfo(rules.Id).@"enum".fields.len;
const all_rule_ids: [rule_count]rules.Id = blk: {
    var out: [rule_count]rules.Id = undefined;
    for (@typeInfo(rules.Id).@"enum".fields, 0..) |field, i| {
        out[i] = @field(rules.Id, field.name);
    }
    break :blk out;
};
const RuleBitSet = std.StaticBitSet(rule_count);

const Mode = enum {
    check_baseline,
    write_baseline,
    report_only,
};

const CliOptions = struct {
    tiger_check_bin: []const u8,
    corpus_dir: []const u8,
    baseline_path: []const u8,
    output_path: []const u8,
    mode: Mode,
};

const CaseExpectation = struct {
    expect_fail: bool,
    expected_rule: rules.Id,
};

const CaseObservation = struct {
    exited_ok: bool,
    seen_rules: RuleBitSet,
};

const RunStats = struct {
    evaluated_cases: u32 = 0,
    skipped_cases: u32 = 0,
    contract_failures: u32 = 0,
};

const RuleAccumulator = struct {
    rule_id: rules.Id,
    positives: u32 = 0,
    negatives: u32 = 0,
    tp: u32 = 0,
    fp: u32 = 0,
    fn_count: u32 = 0,
    tn: u32 = 0,
    fp_cases: std.array_list.Managed([]const u8),
    fn_cases: std.array_list.Managed([]const u8),

    fn init(allocator: std.mem.Allocator, rule_id: rules.Id) RuleAccumulator {
        return .{
            .rule_id = rule_id,
            .fp_cases = std.array_list.Managed([]const u8).init(allocator),
            .fn_cases = std.array_list.Managed([]const u8).init(allocator),
        };
    }

    fn deinit(self: *RuleAccumulator) void {
        self.fp_cases.deinit();
        self.fn_cases.deinit();
    }
};

const RuleReport = struct {
    rule_id: []const u8,
    prefix: []const u8,
    positives: u32,
    negatives: u32,
    tp: u32,
    fp: u32,
    fn_count: u32,
    tn: u32,
    precision: f64,
    recall: f64,
    fp_cases: []const []const u8,
    fn_cases: []const []const u8,
};

const TotalsReport = struct {
    evaluated_cases: u32,
    skipped_cases: u32,
    positives: u32,
    negatives: u32,
    tp: u32,
    fp: u32,
    fn_count: u32,
    tn: u32,
    contract_failures: u32,
};

const Report = struct {
    schema_version: u32,
    corpus_dir: []const u8,
    rules: []const RuleReport,
    totals: TotalsReport,
};

const OwnedReport = struct {
    rules: std.array_list.Managed(RuleReport),
    value: Report,

    fn deinit(self: *OwnedReport) void {
        self.rules.deinit();
    }
};

const BaselineDelta = struct {
    rule_id: []const u8,
    fp_delta: i32,
    fn_delta: i32,
};

pub fn main(init: std.process.Init) !void {
    const cli = parse_cli_options(init) catch {
        print_usage();
        std.process.exit(1);
    };
    assert(cli.tiger_check_bin.len > 0);
    assert(cli.corpus_dir.len > 0);

    const allocator = init.gpa;
    var test_files = std.array_list.Managed([]const u8).init(allocator);
    defer corpus_common.deinit_owned_paths(allocator, &test_files);
    try corpus_common.collect_zig_files(allocator, cli.corpus_dir, &test_files);
    corpus_common.sort_paths(&test_files);

    const accumulators = try init_accumulators(allocator);
    defer deinit_accumulators(allocator, accumulators);

    const io = init.io;
    var stats = RunStats{};
    try run_corpus_cases(
        allocator,
        io,
        cli.tiger_check_bin,
        &test_files,
        accumulators,
        &stats,
    );

    var report = try build_report(allocator, cli.corpus_dir, accumulators, stats);
    defer report.deinit();
    try write_report_json(allocator, io, cli.output_path, &report.value);

    var stdout_buf: [4096]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writerStreaming(io, &stdout_buf);
    const stdout = &stdout_writer.interface;

    try finalize_mode(allocator, io, stdout, cli, stats, &report.value);
}

fn run_corpus_cases(
    allocator: std.mem.Allocator,
    io: std.Io,
    tiger_check_bin: []const u8,
    test_files: *const std.array_list.Managed([]const u8),
    accumulators: []RuleAccumulator,
    stats: *RunStats,
) !void {
    assert(tiger_check_bin.len > 0);
    assert(test_files.items.len <= 4096);
    if (tiger_check_bin.len == 0) {
        return error.InvalidInputPath;
    }

    for (test_files.items) |file_path| {
        const expectation = try parse_case_expectation(allocator, file_path);
        if (expectation == null) {
            stats.skipped_cases += 1;
            continue;
        }

        const observation = try run_tiger_check_case(
            allocator,
            io,
            tiger_check_bin,
            file_path,
        );
        try apply_case_observation(
            accumulators,
            file_path,
            expectation.?,
            observation,
            stats,
        );
    }
}

fn finalize_mode(
    allocator: std.mem.Allocator,
    io: std.Io,
    stdout: *std.Io.Writer,
    cli: CliOptions,
    stats: RunStats,
    report: *const Report,
) !void {
    assert(report.schema_version > 0);
    assert(stats.evaluated_cases >= stats.contract_failures);
    assert(cli.output_path.len > 0);
    try stdout.print(
        "precision-harness: evaluated={d} skipped={d} report={s}\n",
        .{ stats.evaluated_cases, stats.skipped_cases, cli.output_path },
    );

    switch (cli.mode) {
        .report_only => {
            try stdout.writeAll("precision-harness: report-only mode\n");
            try stdout.flush();
            return;
        },
        .write_baseline => {
            try write_report_json(allocator, io, cli.baseline_path, report);
            try stdout.print(
                "precision-harness: baseline updated at {s}\n",
                .{cli.baseline_path},
            );
            try stdout.flush();
            return;
        },
        .check_baseline => {
            try finalize_check_baseline(allocator, stdout, cli.baseline_path, stats, report);
            return;
        },
    }
}

fn finalize_check_baseline(
    allocator: std.mem.Allocator,
    stdout: *std.Io.Writer,
    baseline_path: []const u8,
    stats: RunStats,
    report: *const Report,
) !void {
    assert(baseline_path.len > 0);
    assert(stats.evaluated_cases >= stats.contract_failures);
    if (baseline_path.len == 0) {
        return error.InvalidBaselinePath;
    }

    const baseline = try read_report_json(allocator, baseline_path);
    defer baseline.deinit();

    const regressions = try check_against_baseline(stdout, &baseline.value, report);
    if (regressions) {
        try stdout.flush();
        std.process.exit(1);
    }
    if (stats.contract_failures > 0) {
        try stdout.flush();
        std.process.exit(1);
    }
    try stdout.writeAll("precision-harness: baseline check passed\n");
    try stdout.flush();
}

fn parse_cli_options(init: std.process.Init) !CliOptions {
    var args = init.minimal.args.iterate();
    const argv0 = args.next();
    assert(argv0 != null);
    if (argv0 == null) {
        return error.InvalidArguments;
    }

    var out = CliOptions{
        .tiger_check_bin = try parse_required_arg(&args),
        .corpus_dir = try parse_required_arg(&args),
        .baseline_path = try parse_required_arg(&args),
        .output_path = try parse_required_arg(&args),
        .mode = .check_baseline,
    };

    out.mode = try parse_mode_arg(&args);
    if (args.next() != null) {
        return error.InvalidArguments;
    }
    try validate_cli_options(out);
    return out;
}

fn parse_mode_arg(args: anytype) !Mode {
    const mode_arg = args.next() orelse "--check-baseline";
    return parse_mode(mode_arg) orelse error.InvalidArguments;
}

fn validate_cli_options(out: CliOptions) !void {
    assert(out.tiger_check_bin.len > 0);
    assert(out.corpus_dir.len > 0);
    assert(out.baseline_path.len > 0);
    assert(out.output_path.len > 0);
    if (out.tiger_check_bin.len == 0) {
        return error.InvalidArguments;
    }
    if (out.corpus_dir.len == 0) {
        return error.InvalidArguments;
    }
    if (out.baseline_path.len == 0) {
        return error.InvalidArguments;
    }
    if (out.output_path.len == 0) {
        return error.InvalidArguments;
    }
}

fn parse_required_arg(args: anytype) ![]const u8 {
    const arg = args.next() orelse return error.InvalidArguments;
    if (arg.len == 0) {
        return error.InvalidArguments;
    }
    return arg;
}

fn parse_mode(arg: []const u8) ?Mode {
    assert(arg.len > 0);
    if (arg.len == 0) {
        return null;
    }
    if (std.mem.eql(u8, arg, "--check-baseline")) {
        return .check_baseline;
    }
    if (std.mem.eql(u8, arg, "--write-baseline")) {
        return .write_baseline;
    }
    if (std.mem.eql(u8, arg, "--report-only")) {
        return .report_only;
    }
    return null;
}

fn print_usage() void {
    std.debug.print(
        "usage: precision-harness <tigercheck-bin> <corpus-dir> " ++
            "<baseline-json> <output-json> [--check-baseline|--write-baseline|--report-only]\n",
        .{},
    );
}

fn init_accumulators(allocator: std.mem.Allocator) ![]RuleAccumulator {
    var out = try allocator.alloc(RuleAccumulator, rule_count);
    for (all_rule_ids, 0..) |rule_id, i| {
        out[i] = RuleAccumulator.init(allocator, rule_id);
    }
    return out;
}

fn deinit_accumulators(allocator: std.mem.Allocator, accumulators: []RuleAccumulator) void {
    assert(accumulators.len == rule_count);
    if (accumulators.len == 0) {
        return;
    }
    for (accumulators) |*acc| acc.deinit();
    allocator.free(accumulators);
}

fn parse_case_expectation(
    allocator: std.mem.Allocator,
    file_path: []const u8,
) !?CaseExpectation {
    assert(file_path.len > 0);
    if (file_path.len == 0) {
        return null;
    }

    const basename = std.fs.path.basename(file_path);
    const expect_pass = corpus_common.is_pass_case_basename(basename);
    const expect_fail = corpus_common.is_fail_case_basename(basename);
    if (!expect_pass) {
        if (!expect_fail) {
            return null;
        }
    }
    if (!corpus_common.is_zig_case_file(basename)) {
        return error.InvalidCorpusFileName;
    }

    const expected_rule = try resolve_expected_rule_for_case(allocator, file_path, basename);

    return .{
        .expect_fail = expect_fail,
        .expected_rule = expected_rule,
    };
}

fn resolve_expected_rule_for_case(
    allocator: std.mem.Allocator,
    file_path: []const u8,
    basename: []const u8,
) !rules.Id {
    assert(file_path.len > 0);
    assert(basename.len > 0);
    if (file_path.len == 0) {
        return error.InvalidCorpusFileName;
    }
    if (basename.len == 0) {
        return error.InvalidCorpusFileName;
    }

    const directive_rule = try parse_expect_rule_directive(allocator, file_path);
    if (directive_rule) |rule_id| {
        return rule_id;
    }
    return parse_rule_from_case_basename(basename);
}

fn parse_rule_from_case_basename(basename: []const u8) !rules.Id {
    assert(basename.len > 0);
    const min_len = corpus_common.case_fail_prefix().len +
        corpus_common.zig_file_extension().len + 1;
    if (basename.len <= min_len) {
        return error.InvalidCorpusFileName;
    }

    const stem_start = corpus_common.case_fail_prefix().len;
    const stem_end = basename.len - corpus_common.zig_file_extension().len;
    const stem = basename[stem_start..stem_end];
    const sep = std.mem.indexOfScalar(u8, stem, '_') orelse {
        return error.InvalidCorpusFileName;
    };
    if (sep == 0) {
        return error.InvalidCorpusFileName;
    }
    return resolve_rule_by_prefix(stem[0..sep]);
}

fn parse_expect_rule_directive(
    allocator: std.mem.Allocator,
    file_path: []const u8,
) !?rules.Id {
    assert(file_path.len > 0);
    if (file_path.len == 0) {
        return null;
    }

    const source = try std.Io.Dir.cwd().readFileAllocOptions(
        std.Options.debug_io,
        file_path,
        allocator,
        std.Io.Limit.limited(128 * 1024),
        .of(u8),
        0,
    );
    defer allocator.free(source);

    var out: ?rules.Id = null;
    var line_start: usize = 0;
    for (source, 0..) |byte, i| {
        if (byte != '\n') {
            continue;
        }
        try parse_expect_rule_directive_line(source[line_start..i], &out);
        line_start = i + 1;
    }
    if (line_start < source.len) {
        try parse_expect_rule_directive_line(source[line_start..], &out);
    }
    return out;
}

fn parse_expect_rule_directive_line(line: []const u8, out: *?rules.Id) !void {
    assert(line.len <= 4096);
    assert(std.mem.indexOfScalar(u8, line, 0) == null);
    if (line.len == 0) {
        return;
    }
    const trimmed = std.mem.trim(u8, line, " \t\r");
    assert(trimmed.len <= line.len);
    if (!std.mem.startsWith(u8, trimmed, "// expect-rule:")) {
        return;
    }

    const value = std.mem.trim(u8, trimmed[15..], " \t\r");
    if (value.len == 0) {
        return error.EmptyExpectRuleDirective;
    }
    const parsed = parse_rule_id(value) orelse return error.InvalidExpectRuleDirective;
    try ensure_expect_rule_not_conflicting(out, parsed);
    out.* = parsed;
}

fn ensure_expect_rule_not_conflicting(out: *?rules.Id, parsed: rules.Id) !void {
    if (out.* == null) {
        return;
    }
    if (out.*.? != parsed) {
        return error.ConflictingExpectRuleDirective;
    }
}

fn resolve_rule_by_prefix(prefix: []const u8) !rules.Id {
    assert(prefix.len > 0);
    assert(prefix.len <= 8);
    if (prefix.len == 0) {
        return error.EmptyRulePrefix;
    }

    var matched: ?rules.Id = null;
    for (all_rule_ids) |rule_id| {
        if (!rule_id_matches_prefix(rule_id, prefix)) {
            continue;
        }
        if (matched == null) {
            matched = rule_id;
            continue;
        }
        if (matched.? != rule_id) {
            return error.AmbiguousRulePrefix;
        }
    }
    return matched orelse error.UnknownRulePrefix;
}

fn rule_id_matches_prefix(rule_id: rules.Id, prefix: []const u8) bool {
    assert(prefix.len > 0);
    if (prefix.len == 0) {
        return false;
    }
    const id = rules.id_string(rule_id);
    const sep = std.mem.indexOfScalar(u8, id, '_') orelse {
        return false;
    };
    return std.mem.eql(u8, id[0..sep], prefix);
}

fn parse_rule_id(value: []const u8) ?rules.Id {
    assert(value.len <= 128);
    if (value.len == 0) {
        return null;
    }
    for (all_rule_ids) |rule_id| {
        if (std.mem.eql(u8, value, rules.id_string(rule_id))) {
            return rule_id;
        }
    }
    return null;
}

fn run_tiger_check_case(
    allocator: std.mem.Allocator,
    io: std.Io,
    tiger_check_bin: []const u8,
    file_path: []const u8,
) !CaseObservation {
    assert(tiger_check_bin.len > 0);
    assert(file_path.len > 0);
    if (tiger_check_bin.len == 0) {
        return error.InvalidInputPath;
    }
    if (file_path.len == 0) {
        return error.InvalidInputPath;
    }

    var argv = std.array_list.Managed([]const u8).init(allocator);
    defer argv.deinit();
    try argv.append(tiger_check_bin);
    if (profile_for_test_file(file_path)) |profile_name| {
        try argv.append("--profile");
        try argv.append(profile_name);
    }
    try argv.append(file_path);

    const result = try std.process.run(allocator, io, .{ .argv = argv.items });
    defer {
        allocator.free(result.stdout);
        allocator.free(result.stderr);
    }

    var seen_rules = RuleBitSet.initEmpty();
    collect_rule_ids(result.stdout, &seen_rules);
    collect_rule_ids(result.stderr, &seen_rules);

    const exited_ok = switch (result.term) {
        .exited => |code| code == 0,
        .signal, .stopped, .unknown => false,
    };

    return .{
        .exited_ok = exited_ok,
        .seen_rules = seen_rules,
    };
}

fn collect_rule_ids(output: []const u8, seen_rules: *RuleBitSet) void {
    assert(output.len <= 4 * 1024 * 1024);
    assert(std.mem.indexOfScalar(u8, output, 0) == null);
    if (output.len == 0) {
        return;
    }

    for (all_rule_ids) |rule_id| {
        if (output_mentions_rule_id(output, rule_id)) {
            seen_rules.set(@intFromEnum(rule_id));
        }
    }
}

fn output_mentions_rule_id(output: []const u8, rule_id: rules.Id) bool {
    assert(output.len <= 4 * 1024 * 1024);
    if (output.len == 0) {
        return false;
    }

    var needle_buf: [64]u8 = undefined;
    const needle = std.fmt.bufPrint(&needle_buf, "[{s}]", .{rules.id_string(rule_id)}) catch {
        return false;
    };
    return std.mem.indexOf(u8, output, needle) != null;
}

fn apply_case_observation(
    accumulators: []RuleAccumulator,
    file_path: []const u8,
    expectation: CaseExpectation,
    observation: CaseObservation,
    stats: *RunStats,
) !void {
    assert(file_path.len > 0);
    assert(stats.evaluated_cases >= stats.contract_failures);
    if (file_path.len == 0) {
        return error.InvalidInputPath;
    }
    const idx = @intFromEnum(expectation.expected_rule);
    assert(idx < accumulators.len);
    if (idx >= accumulators.len) {
        return error.InvalidRuleIndex;
    }

    const acc = &accumulators[idx];
    const expected_seen = observation.seen_rules.isSet(idx);

    if (expectation.expect_fail) {
        acc.positives += 1;
        if (expected_seen) {
            acc.tp += 1;
        } else {
            acc.fn_count += 1;
            try acc.fn_cases.append(file_path);
        }
    } else {
        acc.negatives += 1;
        if (expected_seen) {
            acc.fp += 1;
            try acc.fp_cases.append(file_path);
        } else {
            acc.tn += 1;
        }
    }

    stats.evaluated_cases += 1;
    if (expectation.expect_fail) {
        if (observation.exited_ok) {
            stats.contract_failures += 1;
        }
    }
    if (!expectation.expect_fail) {
        if (!observation.exited_ok) {
            stats.contract_failures += 1;
        }
    }
}

fn build_report(
    allocator: std.mem.Allocator,
    corpus_dir: []const u8,
    accumulators: []const RuleAccumulator,
    stats: RunStats,
) !OwnedReport {
    assert(corpus_dir.len > 0);
    assert(accumulators.len == rule_count);
    assert(stats.evaluated_cases >= stats.contract_failures);
    if (corpus_dir.len == 0) {
        return error.InvalidCorpusPath;
    }
    if (accumulators.len != rule_count) {
        return error.InvalidAccumulatorSet;
    }

    var rules_out = std.array_list.Managed(RuleReport).init(allocator);
    errdefer rules_out.deinit();

    var totals = TotalsReport{
        .evaluated_cases = stats.evaluated_cases,
        .skipped_cases = stats.skipped_cases,
        .positives = 0,
        .negatives = 0,
        .tp = 0,
        .fp = 0,
        .fn_count = 0,
        .tn = 0,
        .contract_failures = stats.contract_failures,
    };

    for (accumulators) |acc| {
        if (!accumulator_has_examples(acc)) {
            continue;
        }

        add_totals_from_accumulator(&totals, acc);
        var rule_report: RuleReport = undefined;
        build_rule_report_from_accumulator(acc, &rule_report);
        try rules_out.append(rule_report);
    }

    return .{
        .rules = rules_out,
        .value = .{
            .schema_version = 1,
            .corpus_dir = corpus_dir,
            .rules = rules_out.items,
            .totals = totals,
        },
    };
}

fn accumulator_has_examples(acc: RuleAccumulator) bool {
    assert(acc.tp <= acc.positives);
    assert(acc.tn <= acc.negatives);
    if (acc.positives > 0) {
        return true;
    }
    return acc.negatives > 0;
}

fn add_totals_from_accumulator(totals: *TotalsReport, acc: RuleAccumulator) void {
    assert(totals.evaluated_cases >= totals.contract_failures);
    assert(acc.tp <= acc.positives);
    assert(acc.tn <= acc.negatives);
    totals.positives += acc.positives;
    totals.negatives += acc.negatives;
    totals.tp += acc.tp;
    totals.fp += acc.fp;
    totals.fn_count += acc.fn_count;
    totals.tn += acc.tn;
}

fn build_rule_report_from_accumulator(acc: RuleAccumulator, out: *RuleReport) void {
    assert(acc.tp <= acc.positives);
    assert(acc.tn <= acc.negatives);
    const precision = ratio_or_one(acc.tp, acc.tp + acc.fp);
    const recall = ratio_or_one(acc.tp, acc.tp + acc.fn_count);
    out.* = .{
        .rule_id = rules.id_string(acc.rule_id),
        .prefix = rule_prefix(acc.rule_id),
        .positives = acc.positives,
        .negatives = acc.negatives,
        .tp = acc.tp,
        .fp = acc.fp,
        .fn_count = acc.fn_count,
        .tn = acc.tn,
        .precision = precision,
        .recall = recall,
        .fp_cases = acc.fp_cases.items,
        .fn_cases = acc.fn_cases.items,
    };
}

fn ratio_or_one(numerator: u32, denominator: u32) f64 {
    assert(denominator >= numerator);
    if (denominator == 0) {
        return 1.0;
    }
    return @as(f64, @floatFromInt(numerator)) / @as(f64, @floatFromInt(denominator));
}

fn rule_prefix(rule_id: rules.Id) []const u8 {
    const id = rules.id_string(rule_id);
    if (id.len == 0) {
        return id;
    }
    const sep = std.mem.indexOfScalar(u8, id, '_') orelse {
        return id;
    };
    return id[0..sep];
}

fn write_report_json(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    report: *const Report,
) !void {
    assert(path.len > 0);
    assert(report.schema_version > 0);
    if (path.len == 0) {
        return error.InvalidOutputPath;
    }
    if (report.schema_version == 0) {
        return error.InvalidReport;
    }

    var out: std.Io.Writer.Allocating = .init(allocator);
    defer out.deinit();

    try std.json.Stringify.value(report.*, .{ .whitespace = .indent_2 }, &out.writer);
    try out.writer.writeAll("\n");

    try ensure_parent_dir(io, path);
    try std.Io.Dir.cwd().writeFile(io, .{
        .sub_path = path,
        .data = out.written(),
    });
}

fn ensure_parent_dir(io: std.Io, path: []const u8) !void {
    assert(path.len > 0);
    if (path.len == 0) {
        return;
    }
    if (std.fs.path.dirname(path)) |parent| {
        if (parent.len == 0) {
            return;
        }
        try std.Io.Dir.cwd().createDirPath(io, parent);
    }
}

fn read_report_json(
    allocator: std.mem.Allocator,
    path: []const u8,
) !std.json.Parsed(Report) {
    assert(path.len > 0);
    if (path.len == 0) {
        return error.InvalidBaselinePath;
    }

    const data = try std.Io.Dir.cwd().readFileAllocOptions(
        std.Options.debug_io,
        path,
        allocator,
        std.Io.Limit.limited(8 * 1024 * 1024),
        .of(u8),
        0,
    );
    defer allocator.free(data);

    return std.json.parseFromSlice(Report, allocator, data, .{
        .allocate = .alloc_always,
    });
}

fn check_against_baseline(
    stdout: *std.Io.Writer,
    baseline: *const Report,
    current: *const Report,
) !bool {
    assert(baseline.schema_version > 0);
    assert(current.schema_version > 0);
    if (baseline.schema_version == 0) {
        return true;
    }
    if (current.schema_version == 0) {
        return true;
    }

    var regressions = try report_schema_mismatch(stdout, baseline, current);

    var deltas = std.array_list.Managed(BaselineDelta).init(std.heap.page_allocator);
    defer deltas.deinit();

    if (try collect_rule_deltas(stdout, baseline, current, &deltas)) {
        regressions = true;
    }
    if (try detect_missing_current_rules(stdout, baseline, current)) {
        regressions = true;
    }
    try print_rule_deltas(stdout, deltas.items);
    return regressions;
}

fn report_schema_mismatch(
    stdout: *std.Io.Writer,
    baseline: *const Report,
    current: *const Report,
) !bool {
    assert(baseline.schema_version > 0);
    assert(current.schema_version > 0);
    if (baseline.schema_version == current.schema_version) {
        return false;
    }

    try stdout.print(
        "precision-harness: schema mismatch baseline={d} current={d}\n",
        .{ baseline.schema_version, current.schema_version },
    );
    return true;
}

fn collect_rule_deltas(
    stdout: *std.Io.Writer,
    baseline: *const Report,
    current: *const Report,
    deltas: *std.array_list.Managed(BaselineDelta),
) !bool {
    assert(baseline.rules.len <= rule_count);
    assert(current.rules.len <= rule_count);
    assert(deltas.items.len <= deltas.capacity);
    if (current.rules.len == 0) {
        return false;
    }

    var regressions = false;
    for (current.rules) |cur| {
        const base = find_rule_report(baseline.rules, cur.rule_id) orelse {
            regressions = true;
            try stdout.print(
                "precision-harness: baseline missing rule {s}; refresh baseline\n",
                .{cur.rule_id},
            );
            continue;
        };

        if (cur.positives != base.positives) {
            regressions = true;
            try stdout.print(
                "precision-harness: coverage drift {s} positives {d}->{d} negatives {d}->{d}\n",
                .{ cur.rule_id, base.positives, cur.positives, base.negatives, cur.negatives },
            );
        } else if (cur.negatives != base.negatives) {
            regressions = true;
            try stdout.print(
                "precision-harness: coverage drift {s} positives {d}->{d} negatives {d}->{d}\n",
                .{ cur.rule_id, base.positives, cur.positives, base.negatives, cur.negatives },
            );
        }

        const fp_delta: i32 = @as(i32, @intCast(cur.fp)) - @as(i32, @intCast(base.fp));
        const fn_delta: i32 =
            @as(i32, @intCast(cur.fn_count)) - @as(i32, @intCast(base.fn_count));
        if (fp_delta > 0) {
            regressions = true;
            try deltas.append(.{
                .rule_id = cur.rule_id,
                .fp_delta = fp_delta,
                .fn_delta = fn_delta,
            });
        } else if (fn_delta > 0) {
            regressions = true;
            try deltas.append(.{
                .rule_id = cur.rule_id,
                .fp_delta = fp_delta,
                .fn_delta = fn_delta,
            });
        }
    }
    return regressions;
}

fn detect_missing_current_rules(
    stdout: *std.Io.Writer,
    baseline: *const Report,
    current: *const Report,
) !bool {
    assert(baseline.rules.len <= rule_count);
    assert(current.rules.len <= rule_count);
    if (baseline.rules.len == 0) {
        return false;
    }

    var regressions = false;
    for (baseline.rules) |base| {
        if (find_rule_report(current.rules, base.rule_id) == null) {
            regressions = true;
            try stdout.print(
                "precision-harness: current report missing baseline rule {s}\n",
                .{base.rule_id},
            );
        }
    }
    return regressions;
}

fn print_rule_deltas(stdout: *std.Io.Writer, deltas: []const BaselineDelta) !void {
    assert(deltas.len <= rule_count);
    if (deltas.len == 0) {
        return;
    }

    try stdout.writeAll("precision-harness: rule regressions detected\n");
    for (deltas) |delta| {
        try stdout.print(
            "  - {s}: fp_delta={d}, fn_delta={d}\n",
            .{ delta.rule_id, delta.fp_delta, delta.fn_delta },
        );
    }
}

fn find_rule_report(reports: []const RuleReport, rule_id: []const u8) ?*const RuleReport {
    assert(rule_id.len > 0);
    assert(reports.len <= rule_count);
    if (rule_id.len == 0) {
        return null;
    }

    for (reports) |*entry| {
        if (std.mem.eql(u8, entry.rule_id, rule_id)) {
            return entry;
        }
    }
    return null;
}

fn profile_for_test_file(file_path: []const u8) ?[]const u8 {
    assert(file_path.len > 0);
    if (file_path.len == 0) {
        return null;
    }
    if (corpus_common.is_tigerbeetle_corpus_file(file_path)) {
        return "tigerbeetle_repo";
    }
    return null;
}

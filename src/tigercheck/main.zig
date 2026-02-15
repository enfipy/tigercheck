const std = @import("std");
const assert = std.debug.assert;
const libtigercheck = @import("libtigercheck");
const rules = libtigercheck.rules;

const HistogramCount = u32;
const HistogramEntry = struct {
    id: rules.Id,
    count: HistogramCount,
};

const CliOptions = struct {
    dump_graph: bool,
    explain_policy: bool,
    explain_strict: bool,
    profile: libtigercheck.policy.Profile,
    target_path: []const u8,
};

const SourceLocation = struct {
    line: u32,
    column: u32,
};

const FileFunctionIndex = struct {
    source: []u8,
    functions: std.StringHashMap(SourceLocation),

    fn init(allocator: std.mem.Allocator, file_path: []const u8) !FileFunctionIndex {
        const source = try std.Io.Dir.cwd().readFileAllocOptions(
            std.Options.debug_io,
            file_path,
            allocator,
            std.Io.Limit.limited(16 * 1024 * 1024),
            .of(u8),
            0,
        );
        errdefer allocator.free(source);

        var functions = std.StringHashMap(SourceLocation).init(allocator);
        errdefer functions.deinit();

        const tree = try std.zig.Ast.parse(allocator, source, .zig);
        defer {
            var t = tree;
            t.deinit(allocator);
        }

        const tags = tree.tokens.items(.tag);
        const starts = tree.tokens.items(.start);
        if (tags.len >= 2) {
            for (0..tags.len - 1) |i| {
                if (tags[i] != .keyword_fn or tags[i + 1] != .identifier) continue;
                const name_token: std.zig.Ast.TokenIndex = @intCast(i + 1);
                const function_name = tree.tokenSlice(name_token);
                if (function_name.len == 0 or functions.contains(function_name)) continue;

                const offset: u32 = @intCast(starts[i + 1]);
                const location = offset_to_line_col(source, offset);
                try functions.put(function_name, location);
            }
        }

        return .{
            .source = source,
            .functions = functions,
        };
    }

    fn deinit(self: *FileFunctionIndex, allocator: std.mem.Allocator) void {
        self.functions.deinit();
        allocator.free(self.source);
    }
};

const LocationCache = struct {
    allocator: std.mem.Allocator,
    by_file: std.StringHashMap(FileFunctionIndex),

    fn init(allocator: std.mem.Allocator) LocationCache {
        return .{
            .allocator = allocator,
            .by_file = std.StringHashMap(FileFunctionIndex).init(allocator),
        };
    }

    fn deinit(self: *LocationCache) void {
        var it = self.by_file.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.deinit(self.allocator);
        }
        self.by_file.deinit();
    }

    fn function_location(
        self: *LocationCache,
        file_path: []const u8,
        function_name: []const u8,
    ) ?SourceLocation {
        const index = self.file_index(file_path) catch return null;
        return index.functions.get(function_name);
    }

    fn file_index(self: *LocationCache, file_path: []const u8) !*FileFunctionIndex {
        const gop = try self.by_file.getOrPut(file_path);
        if (!gop.found_existing) {
            gop.value_ptr.* = try FileFunctionIndex.init(self.allocator, file_path);
        }
        return gop.value_ptr;
    }
};

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;

    const cli = parse_cli_options(init) catch {
        print_usage();
        std.process.exit(1);
    };
    assert(cli.target_path.len > 0);

    var call_graph = try libtigercheck.graph.build_from_path(allocator, cli.target_path);
    defer call_graph.deinit();

    var stdout_buf: [4096]u8 = undefined;
    const io = init.io;
    var stdout_writer = std.Io.File.stdout().writerStreaming(io, &stdout_buf);
    const stdout = &stdout_writer.interface;

    if (cli.dump_graph) {
        try call_graph.dump_dot(stdout);
        try stdout.flush();
        return;
    }

    var result = try libtigercheck.analysis.analyze_with_options(allocator, &call_graph, .{
        .profile = cli.profile,
    });
    defer result.deinit();
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);

    var location_cache = LocationCache.init(allocator);
    defer location_cache.deinit();

    for (result.diagnostics.items) |diag| {
        try print_diagnostic(stdout, &location_cache, diag);
    }

    if (result.critical_count > 0 or result.warning_count > 0) {
        try print_issue_histograms(allocator, stdout, result);
    }

    if (cli.explain_policy) {
        try print_policy_explanation(stdout, result);
    }

    if (cli.explain_strict) {
        try print_strict_explanation(allocator, stdout, result);
    }

    if (result.critical_count > 0 or result.warning_count > 0) {
        try stdout.print(
            "\n{d} critical, {d} warning(s)\n",
            .{ result.critical_count, result.warning_count },
        );
        try stdout.flush();
        std.process.exit(1);
    }

    try stdout.writeAll("OK\n");
    try stdout.flush();
}

fn print_usage() void {
    std.debug.print(
        "usage: tigercheck [--dump-graph] [--explain-policy] " ++
            "[--explain-strict] " ++
            "[--profile strict_core|tigerbeetle_repo] <path>\n",
        .{},
    );
}

fn parse_cli_options(init: std.process.Init) !CliOptions {
    var args_arena = std.heap.ArenaAllocator.init(init.gpa);
    defer args_arena.deinit();
    const argv = try init.minimal.args.toSlice(args_arena.allocator());
    const arg_count = argv.len;
    assert(arg_count > 0);

    var option_flags: u8 = 0;
    var profile: libtigercheck.policy.Profile = .strict_core;
    var target_path: ?[]const u8 = null;

    var arg_index: usize = 1;
    while (arg_index < arg_count) : (arg_index += 1) {
        const kind = cli_arg_kind(argv[arg_index]);
        switch (kind) {
            .unknown => return error.InvalidArguments,
            .profile => {
                arg_index += 1;
                if (arg_index >= arg_count) return error.InvalidArguments;
                profile = parse_profile_arg(argv[arg_index]) orelse return error.InvalidArguments;
            },
            .positional => {
                target_path = try parse_positional_arg(target_path, argv[arg_index]);
            },
            .dump_graph, .explain_policy, .explain_strict => {
                option_flags |= cli_flag_bit(kind);
            },
        }
    }

    const resolved_target = target_path orelse return error.InvalidArguments;
    assert(std.mem.indexOfScalar(u8, resolved_target, 0) == null);

    return .{
        .dump_graph = (option_flags & (1 << 0)) != 0,
        .explain_policy = (option_flags & (1 << 1)) != 0,
        .explain_strict = (option_flags & (1 << 2)) != 0,
        .profile = profile,
        .target_path = resolved_target,
    };
}

fn parse_profile_arg(profile_name: []const u8) ?libtigercheck.policy.Profile {
    assert(profile_name.len > 0);
    if (profile_name.len == 0) return null;
    return libtigercheck.policy.parse_profile_name(profile_name);
}

fn parse_positional_arg(target_path: ?[]const u8, arg: []const u8) !?[]const u8 {
    assert(arg.len > 0);
    if (arg.len == 0) return error.InvalidArguments;
    if (target_path == null) return arg;
    return error.InvalidArguments;
}

fn cli_flag_bit(kind: CliArgKind) u8 {
    return switch (kind) {
        .dump_graph => 1 << 0,
        .explain_policy => 1 << 1,
        .explain_strict => 1 << 2,
        .profile, .positional, .unknown => 0,
    };
}

const CliArgKind = enum {
    dump_graph,
    explain_policy,
    explain_strict,
    profile,
    positional,
    unknown,
};

fn cli_arg_kind(arg: []const u8) CliArgKind {
    assert(arg.len > 0);
    assert(std.mem.indexOfScalar(u8, arg, 0) == null);
    if (arg.len == 0) return .positional;
    if (std.mem.eql(u8, arg, "--dump-graph")) return .dump_graph;
    if (std.mem.eql(u8, arg, "--explain-policy")) return .explain_policy;
    if (std.mem.eql(u8, arg, "--explain-strict")) return .explain_strict;
    if (std.mem.eql(u8, arg, "--profile")) return .profile;
    if (std.mem.startsWith(u8, arg, "--")) return .unknown;
    return .positional;
}

fn print_strict_explanation(
    allocator: std.mem.Allocator,
    stdout: *std.Io.Writer,
    result: libtigercheck.analysis.Result,
) !void {
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    assert(result.warning_count + result.critical_count <= 4096);
    if (result.diagnostics.items.len == 0) {
        try stdout.writeAll("\nStrict explanation: no diagnostics\n");
        return;
    }

    var seen = std.AutoHashMap(rules.Id, void).init(allocator);
    defer seen.deinit();

    try stdout.writeAll("\nStrict explanation:\n");
    for (result.diagnostics.items) |diag| {
        const gop = try seen.getOrPut(diag.rule_id);
        if (gop.found_existing) continue;

        const id = rules.id_string(diag.rule_id);
        try stdout.print("- [{s}] why: {s}\n", .{ id, strict_why(diag.rule_id) });
        try stdout.print("  rewrite: {s}\n", .{strict_rewrite(diag.rule_id)});
    }
}

const strict_why_n08 =
    "metaprogramming/indirect control flow is harder to " ++
    "verify";

fn strict_why(rule_id: rules.Id) []const u8 {
    return switch (rule_id) {
        .TS02_EXPLICIT_BOUNDS => "loop grows queue state without a static capacity guard",
        .TS11_PACED_CONTROL => "external-event handling mutates state without a pacing boundary",
        .TS12_PLANE_BOUNDARY => "control-plane and data-plane concerns are mixed in one function",
        .N08_PREPROCESSOR_OR_COMPTIME_BUDGET => strict_why_n08,
        .N07_RETURN_AND_PARAM_CHECKS => "fallible paths or input contracts are not explicitly " ++
            "handled",
        else => rules.summary(rule_id),
    };
}

fn strict_rewrite(rule_id: rules.Id) []const u8 {
    return switch (rule_id) {
        .TS02_EXPLICIT_BOUNDS => "add a guard like `if (queue.len < MAX_QUEUE) " ++
            "queue.append(item);` in the loop",
        .TS11_PACED_CONTROL => "stage event updates and commit via explicit boundary " ++
            "call (e.g. `commit/flush/drain`)",
        .TS12_PLANE_BOUNDARY => "split control/data operations and insert a named " ++
            "boundary handoff function",
        .N08_PREPROCESSOR_OR_COMPTIME_BUDGET => "replace hidden dispatch (`@call`/deep comptime " ++
            "nesting) with direct, explicit branches",
        .N07_RETURN_AND_PARAM_CHECKS => "check return values and enforce preconditions at " ++
            "function entry with guard/assert",
        else => "make the condition explicit, local, and statically " ++
            "bounded; then rerun tigercheck",
    };
}

fn print_policy_explanation(stdout: *std.Io.Writer, result: libtigercheck.analysis.Result) !void {
    assert(result.policy_profile.len > 0 or !result.policy_applied);
    if (!result.policy_applied) {
        try stdout.writeAll("\nPolicy explanation: policy was not applied\n");
        return;
    }

    const class_counts, const action_counts = collect_policy_histograms(result);

    try stdout.print(
        "\nPolicy explanation ({s}): suppressed={d}, downgraded={d}\n",
        .{ result.policy_profile, result.suppressed_count, result.downgraded_count },
    );

    try print_policy_class_histogram(stdout, class_counts);
    try print_policy_action_histogram(stdout, action_counts);
}

fn collect_policy_histograms(
    result: libtigercheck.analysis.Result,
) struct {
    std.enums.EnumArray(libtigercheck.policy.CodeClass, u32),
    std.enums.EnumArray(libtigercheck.policy.Action, u32),
} {
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    var class_counts = std.enums.EnumArray(libtigercheck.policy.CodeClass, u32).initFill(0);
    var action_counts = std.enums.EnumArray(libtigercheck.policy.Action, u32).initFill(0);

    for (result.diagnostics.items) |diag| {
        if (diag.effective_class) |class| {
            class_counts.set(class, class_counts.get(class) + 1);
        }
        if (diag.effective_action) |action| {
            action_counts.set(action, action_counts.get(action) + 1);
        }
    }

    return .{ class_counts, action_counts };
}

fn print_policy_class_histogram(
    stdout: *std.Io.Writer,
    counts: std.enums.EnumArray(libtigercheck.policy.CodeClass, u32),
) !void {
    const classes = [_]libtigercheck.policy.CodeClass{
        .runtime,
        .test_or_fuzz,
        .tooling,
        .bindings,
        .vendored,
    };
    try stdout.writeAll("Effective class histogram:\n");
    for (classes) |class| {
        try stdout.print(
            "{d}  {s}\n",
            .{ counts.get(class), code_class_name(class) },
        );
    }
}

fn print_policy_action_histogram(
    stdout: *std.Io.Writer,
    counts: std.enums.EnumArray(libtigercheck.policy.Action, u32),
) !void {
    const actions = [_]libtigercheck.policy.Action{ .enforce, .warn, .off };
    try stdout.writeAll("Effective action histogram:\n");
    for (actions) |action| {
        try stdout.print(
            "{d}  {s}\n",
            .{ counts.get(action), policy_action_name(action) },
        );
    }
}

fn code_class_name(class: libtigercheck.policy.CodeClass) []const u8 {
    return switch (class) {
        .runtime => "runtime",
        .test_or_fuzz => "test_or_fuzz",
        .tooling => "tooling",
        .bindings => "bindings",
        .vendored => "vendored",
    };
}

fn policy_action_name(action: libtigercheck.policy.Action) []const u8 {
    return switch (action) {
        .enforce => "enforce",
        .warn => "warn",
        .off => "off",
    };
}

fn print_diagnostic(
    stdout: *std.Io.Writer,
    location_cache: *LocationCache,
    diag: libtigercheck.analysis.Diagnostic,
) !void {
    assert(diag.file_path.len > 0);
    assert(diag.message.len > 0);
    const severity_str = switch (diag.severity) {
        .critical => "CRITICAL",
        .warning => "WARNING",
    };

    const id = rules.id_string(diag.rule_id);
    const requirement = rules.summary(diag.rule_id);
    if (diag.line) |line| {
        const column = diag.column orelse 1;
        try stdout.print(
            "[{s}] {s}:{d}:{d} [{s}] {s}; {s}\n",
            .{ severity_str, diag.file_path, line, column, id, requirement, diag.message },
        );
        if (diag.hint) |hint| {
            try stdout.print("        rewrite: {s}\n", .{hint});
        }
        return;
    }

    if (extract_subject(diag.message)) |subject| {
        if (location_cache.function_location(diag.file_path, subject)) |loc| {
            try stdout.print(
                "[{s}] {s}:{d}:{d} [{s}] {s}; {s}\n",
                .{
                    severity_str,
                    diag.file_path,
                    loc.line,
                    loc.column,
                    id,
                    requirement,
                    diag.message,
                },
            );
            if (diag.hint) |hint| {
                try stdout.print("        rewrite: {s}\n", .{hint});
            }
            return;
        }
    }

    try stdout.print(
        "[{s}] {s} [{s}] {s}; {s}\n",
        .{ severity_str, diag.file_path, id, requirement, diag.message },
    );
    if (diag.hint) |hint| {
        try stdout.print("        rewrite: {s}\n", .{hint});
    }
}

fn offset_to_line_col(source: []const u8, offset: u32) SourceLocation {
    assert(source.len <= (16 * 1024 * 1024));
    if (source.len == 0) return .{ .line = 1, .column = 1 };
    const end = @min(@as(usize, offset), source.len);
    var line: u32 = 1;
    var column: u32 = 1;
    for (source[0..end]) |byte| {
        if (byte == '\n') {
            line += 1;
            column = 1;
            continue;
        }
        column += 1;
    }
    return .{ .line = line, .column = column };
}

fn print_issue_histograms(
    allocator: std.mem.Allocator,
    stdout: *std.Io.Writer,
    result: libtigercheck.analysis.Result,
) !void {
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    assert(result.warning_count + result.critical_count <= 4096);
    var warnings = std.AutoHashMap(rules.Id, HistogramCount).init(allocator);
    defer warnings.deinit();

    var criticals = std.AutoHashMap(rules.Id, HistogramCount).init(allocator);
    defer criticals.deinit();

    for (result.diagnostics.items) |diag| {
        switch (diag.severity) {
            .warning => try histogram_increment(&warnings, diag.rule_id),
            .critical => try histogram_increment(&criticals, diag.rule_id),
        }
    }

    if (result.warning_count > 0) {
        try stdout.writeAll("\nWarning histogram:\n");
        try histogram_print(stdout, allocator, warnings);
    }
    if (result.critical_count > 0) {
        try stdout.writeAll("\nCritical histogram:\n");
        try histogram_print(stdout, allocator, criticals);
    }
}

fn histogram_increment(histogram: *std.AutoHashMap(rules.Id, HistogramCount), id: rules.Id) !void {
    const gop = try histogram.getOrPut(id);
    if (!gop.found_existing) {
        gop.value_ptr.* = 0;
    }
    gop.value_ptr.* += 1;
}

fn histogram_print(
    stdout: *std.Io.Writer,
    allocator: std.mem.Allocator,
    histogram: std.AutoHashMap(rules.Id, HistogramCount),
) !void {
    assert(histogram.count() <= @typeInfo(rules.Id).@"enum".fields.len);
    assert(histogram.count() <= 1024);
    var entries = std.array_list.Managed(HistogramEntry).init(allocator);
    defer entries.deinit();

    var it = histogram.iterator();
    while (it.next()) |entry| {
        try entries.append(.{
            .id = entry.key_ptr.*,
            .count = entry.value_ptr.*,
        });
    }

    sort_histogram_entries(entries.items);
    for (entries.items) |entry| {
        try stdout.print(
            "{d}  {s}  {s}\n",
            .{ entry.count, rules.id_string(entry.id), rules.summary(entry.id) },
        );
    }
}

fn sort_histogram_entries(entries: []HistogramEntry) void {
    assert(entries.len <= 1024);
    assert(entries.len == 0 or rules.id_string(entries[0].id).len > 0);
    if (entries.len == 0) return;
    var i: usize = 0;
    while (i < entries.len) : (i += 1) {
        var best = i;
        var j = i + 1;
        while (j < entries.len) : (j += 1) {
            if (entries[j].count > entries[best].count) {
                best = j;
                continue;
            }
            if (entries[j].count == entries[best].count and
                std.mem.order(
                    u8,
                    rules.id_string(entries[j].id),
                    rules.id_string(entries[best].id),
                ) == .lt)
            {
                best = j;
            }
        }

        if (best != i) {
            std.mem.swap(HistogramEntry, &entries[i], &entries[best]);
        }
    }
}

fn extract_subject(message: []const u8) ?[]const u8 {
    assert(message.len > 0);
    assert(message.len <= 4096);
    if (message.len == 0) return null;
    const first = std.mem.indexOfScalar(u8, message, '`') orelse return null;
    if (first + 1 >= message.len) return null;
    const rest = message[first + 1 ..];
    const second_rel = std.mem.indexOfScalar(u8, rest, '`') orelse return null;
    if (second_rel == 0) return null;
    return rest[0..second_rel];
}

test "all rule IDs are documented" {
    const allocator = std.testing.allocator;
    const readme = try std.Io.Dir.cwd().readFileAllocOptions(
        std.Options.debug_io,
        "README.md",
        allocator,
        std.Io.Limit.limited(1024 * 1024),
        .of(u8),
        0,
    );
    defer allocator.free(readme);

    inline for (@typeInfo(rules.Id).@"enum".fields) |field| {
        const needle = "`" ++ field.name ++ "`";
        try std.testing.expect(std.mem.indexOf(u8, readme, needle) != null);
    }
}

test "histogram output snapshot" {
    const allocator = std.testing.allocator;
    var result = libtigercheck.analysis.Result.init(allocator);
    defer result.deinit();

    try result.diagnostics.append(.{
        .severity = .warning,
        .rule_id = .TS02_EXPLICIT_BOUNDS,
        .file_path = "tests/corpus/tigerstyle/fail_TS02_queue_bounds.zig",
        .message = "TS02_EXPLICIT_BOUNDS: queue growth in loop requires " ++
            "explicit queue-capacity bounds",
    });
    result.warning_count += 1;

    try result.diagnostics.append(.{
        .severity = .critical,
        .rule_id = .TS13_BOOLEAN_SPLIT,
        .file_path = "tests/corpus/tigerstyle/fail_TS13_branch_density.zig",
        .message = "TS13_BOOLEAN_SPLIT: split dense branch condition into explicit guard checks",
    });
    result.critical_count += 1;

    var out: std.Io.Writer.Allocating = .init(allocator);
    defer out.deinit();

    try print_issue_histograms(allocator, &out.writer, result);
    const expected =
        "\nWarning histogram:\n" ++
        "1  TS02_EXPLICIT_BOUNDS  all loops and queues require explicit bounds\n" ++
        "\nCritical histogram:\n" ++
        "1  TS13_BOOLEAN_SPLIT  split compound boolean checks into explicit branches\n";
    try std.testing.expectEqualStrings(expected, out.written());
}

test "diagnostic line snapshot" {
    const allocator = std.testing.allocator;
    var out: std.Io.Writer.Allocating = .init(allocator);
    defer out.deinit();

    var cache = LocationCache.init(allocator);
    defer cache.deinit();

    const diag = libtigercheck.analysis.Diagnostic{
        .severity = .warning,
        .rule_id = .TS16_EXPLICIT_OPTIONS,
        .file_path = "tests/corpus/tigerstyle/fail_TS16_explicit_options.zig",
        .message = "TS16_EXPLICIT_OPTIONS: explicit options are required",
    };
    try print_diagnostic(&out.writer, &cache, diag);

    const expected =
        "[WARNING] tests/corpus/tigerstyle/fail_TS16_explicit_options.zig " ++
        "[TS16_EXPLICIT_OPTIONS] avoid default-option reliance; " ++
        "TS16_EXPLICIT_OPTIONS: explicit options are required\n";
    try std.testing.expectEqualStrings(expected, out.written());
}

test "cli arg kind rejects unknown flags" {
    try std.testing.expectEqual(CliArgKind.unknown, cli_arg_kind("--unknownz"));
    try std.testing.expectEqual(CliArgKind.positional, cli_arg_kind("src"));
}

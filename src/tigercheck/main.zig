const std = @import("std");
const assert = std.debug.assert;
const libtigercheck = @import("libtigercheck");
const rules = libtigercheck.rules;

const HistogramCount = u32;
const HistogramEntry = struct {
    id: rules.Id,
    count: HistogramCount,
};

const OutputFormat = enum {
    text,
    json,
};

const GateSet = struct {
    policy: bool = false,
    perf: bool = false,
};

const perf_gate_budget_ms_default: u64 = 6000;

const CliOptions = struct {
    dump_graph: bool,
    explain_policy: bool,
    explain_strict: bool,
    allow_findings: bool,
    output_format: OutputFormat,
    gates: GateSet,
    target_paths: std.array_list.Managed([]const u8),

    fn deinit(self: *CliOptions) void {
        self.target_paths.deinit();
    }
};

const AnalyzeRun = struct {
    result: libtigercheck.analysis.Result,
    perf_elapsed_ms: u64,
    perf_gate_failed: bool,
};

const JSONDiagnostic = struct {
    severity: libtigercheck.analysis.Severity,
    rule_id: []const u8,
    summary: []const u8,
    file_path: []const u8,
    message: []const u8,
    line: ?u32,
    column: ?u32,
    hint: ?[]const u8,
    effective_class: ?libtigercheck.policy.CodeClass,
    effective_action: ?libtigercheck.policy.Action,
};

const JSONRunOutput = struct {
    schema_version: u32,
    policy_profile: []const u8,
    policy_applied: bool,
    warning_count: usize,
    critical_count: usize,
    suppressed_count: usize,
    downgraded_count: usize,
    diagnostics: []const JSONDiagnostic,
};

const OwnedJSONRunOutput = struct {
    diagnostics: std.array_list.Managed(JSONDiagnostic),
    value: JSONRunOutput,

    fn deinit(self: *OwnedJSONRunOutput) void {
        self.diagnostics.deinit();
    }
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
        if (gop.found_existing) {
            return gop.value_ptr;
        }
        gop.value_ptr.* = try FileFunctionIndex.init(self.allocator, file_path);
        return gop.value_ptr;
    }
};

pub fn main(init: std.process.Init) !void {
    var cli = parse_cli_options(init) catch {
        print_usage();
        std.process.exit(1);
    };
    defer cli.deinit();
    assert(cli.target_paths.items.len > 0);

    const io = init.io;
    var stdout_buf: [4096]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writerStreaming(io, &stdout_buf);
    const stdout = &stdout_writer.interface;

    const allocator = init.gpa;
    var call_graph = try libtigercheck.graph.build_from_paths(allocator, &cli.target_paths);
    defer call_graph.deinit();

    if (cli.dump_graph) {
        try call_graph.dump_dot(stdout);
        try stdout.flush();
        return;
    }

    var analyze_run = try run_analysis(allocator, io, &call_graph, cli.gates);
    defer analyze_run.result.deinit();

    var location_cache = LocationCache.init(allocator);
    defer location_cache.deinit();

    if (cli.output_format == .json) {
        try emit_json_output(
            allocator,
            stdout,
            &location_cache,
            analyze_run,
            cli.allow_findings,
        );
        return;
    }

    try emit_text_output(
        allocator,
        stdout,
        &location_cache,
        analyze_run,
        cli.explain_policy,
        cli.explain_strict,
        cli.allow_findings,
    );
}

fn run_analysis(
    allocator: std.mem.Allocator,
    io: std.Io,
    call_graph: *const libtigercheck.graph.CallGraph,
    gates: GateSet,
) !AnalyzeRun {
    const perf_started_at = perf_started_timestamp(io, gates);
    var result = try libtigercheck.analysis.analyze_with_options(allocator, call_graph, .{
        .apply_policy_gate = gates.policy,
    });
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    const perf_elapsed_ms = perf_elapsed_after_analysis(io, gates, perf_started_at);
    const perf_gate_failed = is_perf_gate_failed(gates, perf_elapsed_ms);
    return .{
        .result = result,
        .perf_elapsed_ms = perf_elapsed_ms,
        .perf_gate_failed = perf_gate_failed,
    };
}

fn perf_started_timestamp(io: std.Io, gates: GateSet) std.Io.Timestamp {
    if (gates.perf) {
        return std.Io.Timestamp.now(io, .awake);
    }
    return std.Io.Timestamp.zero;
}

fn perf_elapsed_after_analysis(
    io: std.Io,
    gates: GateSet,
    perf_started_at: std.Io.Timestamp,
) u64 {
    if (!gates.perf) {
        return 0;
    }
    const ended_at = std.Io.Timestamp.now(io, .awake);
    const elapsed = perf_started_at.durationTo(ended_at);
    return duration_ms_non_negative(elapsed);
}

fn is_perf_gate_failed(gates: GateSet, perf_elapsed_ms: u64) bool {
    if (!gates.perf) {
        return false;
    }
    return perf_elapsed_ms > perf_gate_budget_ms_default;
}

fn has_findings(result: libtigercheck.analysis.Result) bool {
    if (result.critical_count > 0) {
        return true;
    }
    if (result.warning_count > 0) {
        return true;
    }
    return false;
}

fn should_exit_nonzero(
    result: libtigercheck.analysis.Result,
    allow_findings: bool,
    perf_gate_failed: bool,
) bool {
    if (perf_gate_failed) {
        return true;
    }
    if (!has_findings(result)) {
        return false;
    }
    if (allow_findings) {
        return false;
    }
    return true;
}

fn emit_json_output(
    allocator: std.mem.Allocator,
    stdout: *std.Io.Writer,
    location_cache: *LocationCache,
    analyze_run: AnalyzeRun,
    allow_findings: bool,
) !void {
    try print_json_run_output(allocator, stdout, location_cache, analyze_run.result);
    try stdout.flush();
    if (analyze_run.perf_gate_failed) {
        std.debug.print(
            "tigercheck: PERF_GATE failed elapsed_ms={d} budget_ms={d}\n",
            .{ analyze_run.perf_elapsed_ms, perf_gate_budget_ms_default },
        );
    }
    if (should_exit_nonzero(analyze_run.result, allow_findings, analyze_run.perf_gate_failed)) {
        std.process.exit(1);
    }
}

fn emit_text_output(
    allocator: std.mem.Allocator,
    stdout: *std.Io.Writer,
    location_cache: *LocationCache,
    analyze_run: AnalyzeRun,
    explain_policy: bool,
    explain_strict: bool,
    allow_findings: bool,
) !void {
    assert(analyze_run.result.diagnostics.items.len ==
        analyze_run.result.warning_count + analyze_run.result.critical_count);
    const run_has_findings = has_findings(analyze_run.result);
    try emit_text_diagnostics(
        allocator,
        stdout,
        location_cache,
        analyze_run.result,
        run_has_findings,
    );
    try emit_text_explanations(
        allocator,
        stdout,
        analyze_run.result,
        explain_policy,
        explain_strict,
    );
    try emit_perf_gate_summary(stdout, analyze_run);
    try emit_findings_summary(stdout, analyze_run.result, run_has_findings);

    if (should_exit_nonzero(analyze_run.result, allow_findings, analyze_run.perf_gate_failed)) {
        try stdout.flush();
        std.process.exit(1);
    }

    if (run_has_findings) {
        try stdout.flush();
        return;
    }

    try stdout.writeAll("OK\n");
    try stdout.flush();
}

fn emit_text_diagnostics(
    allocator: std.mem.Allocator,
    stdout: *std.Io.Writer,
    location_cache: *LocationCache,
    result: libtigercheck.analysis.Result,
    run_has_findings: bool,
) !void {
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    for (result.diagnostics.items) |diag| {
        try print_diagnostic(stdout, location_cache, diag);
    }
    if (run_has_findings) {
        try print_issue_histograms(allocator, stdout, result);
    }
}

fn emit_text_explanations(
    allocator: std.mem.Allocator,
    stdout: *std.Io.Writer,
    result: libtigercheck.analysis.Result,
    explain_policy: bool,
    explain_strict: bool,
) !void {
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    if (explain_policy) {
        try print_policy_explanation(stdout, result);
    }
    if (explain_strict) {
        try print_strict_explanation(allocator, stdout, result);
    }
}

fn emit_perf_gate_summary(stdout: *std.Io.Writer, analyze_run: AnalyzeRun) !void {
    if (!analyze_run.perf_gate_failed) {
        return;
    }
    try stdout.print(
        "\n[CRITICAL] [PERF_GATE] analysis exceeded budget; elapsed_ms={d} budget_ms={d}\n",
        .{ analyze_run.perf_elapsed_ms, perf_gate_budget_ms_default },
    );
}

fn emit_findings_summary(
    stdout: *std.Io.Writer,
    result: libtigercheck.analysis.Result,
    run_has_findings: bool,
) !void {
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    if (!run_has_findings) {
        return;
    }
    try stdout.print(
        "\n{d} critical, {d} warning(s)\n",
        .{ result.critical_count, result.warning_count },
    );
}

fn print_usage() void {
    std.debug.print(
        "usage: tigercheck [--dump-graph] [--explain-policy] " ++
            "[--explain-strict] " ++
            "[--allow-findings] " ++
            "[--format text|json] " ++
            "[--gates policy,perf] " ++
            "<path> [path ...]\n",
        .{},
    );
}

fn parse_cli_options(init: std.process.Init) !CliOptions {
    var args = try init.minimal.args.iterateAllocator(init.gpa);
    defer args.deinit();
    const argv0 = args.next() orelse return error.InvalidArguments;
    assert(argv0.len > 0);

    var state = CliParseState.init(init.gpa);
    errdefer state.deinit();
    try parse_cli_tokens(&args, &state);
    assert(state.target_paths.items.len <= state.target_paths.capacity);
    if (state.target_paths.items.len == 0) {
        return error.InvalidArguments;
    }

    return .{
        .dump_graph = state.dump_graph,
        .explain_policy = state.explain_policy,
        .explain_strict = state.explain_strict,
        .allow_findings = state.allow_findings,
        .output_format = state.output_format,
        .gates = state.gates,
        .target_paths = state.target_paths,
    };
}

fn parse_cli_tokens(args: *std.process.Args.Iterator, state: *CliParseState) !void {
    const max_cli_args: u16 = 64;
    var step: u16 = 0;
    while (step < max_cli_args) : (step += 1) {
        const arg = args.next() orelse return;
        try parse_cli_token(arg, args, state);
    }
    if (args.next() != null) {
        return error.InvalidArguments;
    }
}

const CliParseState = struct {
    dump_graph: bool = false,
    explain_policy: bool = false,
    explain_strict: bool = false,
    allow_findings: bool = false,
    output_format: OutputFormat = .text,
    gates: GateSet = .{},
    target_paths: std.array_list.Managed([]const u8),

    fn init(allocator: std.mem.Allocator) CliParseState {
        return .{
            .target_paths = std.array_list.Managed([]const u8).init(allocator),
        };
    }

    fn deinit(self: *CliParseState) void {
        self.target_paths.deinit();
    }
};

fn parse_cli_token(
    arg: []const u8,
    args: *std.process.Args.Iterator,
    state: *CliParseState,
) !void {
    assert(arg.len > 0);
    assert(state.target_paths.items.len <= state.target_paths.capacity);
    if (arg.len == 0) return error.InvalidArguments;

    switch (cli_arg_kind(arg)) {
        .format => try parse_cli_format_token(args, state),
        .gates => try parse_cli_gates_token(args, state),
        .positional => try parse_positional_arg(&state.target_paths, arg),
        else => |kind| {
            try apply_simple_cli_flag(kind, state);
        },
    }
}

fn parse_cli_format_token(args: *std.process.Args.Iterator, state: *CliParseState) !void {
    const value = args.next() orelse return error.InvalidArguments;
    state.output_format = parse_output_format_arg(value) orelse return error.InvalidArguments;
}

fn parse_cli_gates_token(args: *std.process.Args.Iterator, state: *CliParseState) !void {
    const value = args.next() orelse return error.InvalidArguments;
    const parsed = parse_gates_arg(value) orelse return error.InvalidArguments;
    merge_gate_set(&state.gates, parsed);
}

fn merge_gate_set(into: *GateSet, parsed: GateSet) void {
    if (parsed.policy) {
        into.policy = true;
    }
    if (parsed.perf) {
        into.perf = true;
    }
}

fn apply_simple_cli_flag(kind: CliArgKind, state: *CliParseState) !void {
    assert(
        kind == .dump_graph or
            kind == .explain_policy or
            kind == .explain_strict or
            kind == .allow_findings or
            kind == .gates or
            kind == .unknown,
    );
    assert(state.output_format == .text or state.output_format == .json);

    switch (kind) {
        .dump_graph => state.dump_graph = true,
        .explain_policy => state.explain_policy = true,
        .explain_strict => state.explain_strict = true,
        .allow_findings => state.allow_findings = true,
        .gates => return error.InvalidArguments,
        .unknown => return error.InvalidArguments,
        .format, .positional => return error.InvalidArguments,
    }
}

fn parse_gates_arg(value: []const u8) ?GateSet {
    assert(value.len > 0);
    if (value.len == 0) {
        return null;
    }
    const trimmed = std.mem.trim(u8, value, " \t\r\n");
    if (trimmed.len == 0) {
        return null;
    }
    if (std.mem.indexOfScalar(u8, trimmed, ',') == null) {
        return parse_gate_token(trimmed);
    }
    return parse_two_gates(trimmed);
}

fn parse_two_gates(value: []const u8) ?GateSet {
    assert(value.len > 0);
    assert(std.mem.indexOfScalar(u8, value, ',') != null);
    if (value.len == 0) {
        return null;
    }
    if (std.mem.indexOfScalar(u8, value, ',') == null) {
        return null;
    }
    const max_gate_tokens: u8 = 2;
    var tokens = std.mem.tokenizeScalar(u8, value, ',');
    var parsed_count: u8 = 0;
    var out = GateSet{};
    while (parsed_count < max_gate_tokens) : (parsed_count += 1) {
        const raw_token = tokens.next() orelse break;
        const token = std.mem.trim(u8, raw_token, " \t\r\n");
        const parsed = parse_gate_token(token) orelse return null;
        if (!merge_unique_gate(&out, parsed)) {
            return null;
        }
    }
    if (parsed_count != max_gate_tokens) {
        return null;
    }
    if (tokens.next() != null) {
        return null;
    }
    return out;
}

fn parse_gate_token(token: []const u8) ?GateSet {
    assert(token.len > 0);
    if (token.len == 0) {
        return null;
    }
    if (std.mem.indexOfAny(u8, token, " \t\r\n") != null) {
        return null;
    }
    if (std.mem.eql(u8, token, "policy")) {
        return .{ .policy = true };
    }
    if (std.mem.eql(u8, token, "perf")) {
        return .{ .perf = true };
    }
    return null;
}

fn merge_unique_gate(into: *GateSet, parsed: GateSet) bool {
    assert(!(parsed.policy and parsed.perf));
    if (parsed.policy) {
        return merge_policy_gate(into);
    }
    if (parsed.perf) {
        return merge_perf_gate(into);
    }
    return false;
}

fn merge_policy_gate(into: *GateSet) bool {
    assert(into.policy or !into.policy);
    if (into.policy) {
        return false;
    }
    into.policy = true;
    return true;
}

fn merge_perf_gate(into: *GateSet) bool {
    assert(into.perf or !into.perf);
    if (into.perf) {
        return false;
    }
    into.perf = true;
    return true;
}

fn parse_output_format_arg(value: []const u8) ?OutputFormat {
    assert(value.len > 0);
    if (value.len == 0) return null;
    if (std.mem.eql(u8, value, "text")) return .text;
    if (std.mem.eql(u8, value, "json")) return .json;
    return null;
}

fn parse_positional_arg(
    target_paths: *std.array_list.Managed([]const u8),
    arg: []const u8,
) !void {
    assert(arg.len > 0);
    if (arg.len == 0) return error.InvalidArguments;
    if (std.mem.indexOfScalar(u8, arg, 0) != null) return error.InvalidArguments;
    try target_paths.append(arg);
}

const CliArgKind = enum {
    dump_graph,
    explain_policy,
    explain_strict,
    allow_findings,
    format,
    gates,
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
    if (std.mem.eql(u8, arg, "--allow-findings")) return .allow_findings;
    if (std.mem.eql(u8, arg, "--format")) return .format;
    if (std.mem.eql(u8, arg, "--gates")) return .gates;
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
    if (result.policy_applied == false) {
        try stdout.writeAll("\nPolicy explanation: policy was not applied\n");
        return;
    }
    assert(result.policy_profile.len > 0);

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
    if (resolved_diagnostic_location(location_cache, diag)) |loc| {
        try stdout.print(
            "[{s}] {s}:{d}:{d} [{s}] {s}; {s}\n",
            .{ severity_str, diag.file_path, loc.line, loc.column, id, requirement, diag.message },
        );
        if (diag.hint) |hint| {
            try stdout.print("        rewrite: {s}\n", .{hint});
        }
        return;
    }

    try stdout.print(
        "[{s}] {s} [{s}] {s}; {s}\n",
        .{ severity_str, diag.file_path, id, requirement, diag.message },
    );
    if (diag.hint) |hint| {
        try stdout.print("        rewrite: {s}\n", .{hint});
    }
}

fn resolved_diagnostic_location(
    location_cache: *LocationCache,
    diag: libtigercheck.analysis.Diagnostic,
) ?SourceLocation {
    if (diag.line) |line| {
        return .{ .line = line, .column = diag.column orelse 1 };
    }
    if (extract_subject(diag.message)) |subject| {
        return location_cache.function_location(diag.file_path, subject);
    }
    return null;
}

fn print_json_run_output(
    allocator: std.mem.Allocator,
    stdout: *std.Io.Writer,
    location_cache: *LocationCache,
    result: libtigercheck.analysis.Result,
) !void {
    var owned = try build_json_run_output(allocator, location_cache, result);
    defer owned.deinit();

    var out: std.Io.Writer.Allocating = .init(allocator);
    defer out.deinit();
    try std.json.Stringify.value(owned.value, .{ .whitespace = .indent_2 }, &out.writer);
    try out.writer.writeAll("\n");
    try stdout.writeAll(out.written());
}

fn build_json_run_output(
    allocator: std.mem.Allocator,
    location_cache: *LocationCache,
    result: libtigercheck.analysis.Result,
) !OwnedJSONRunOutput {
    var diagnostics = std.array_list.Managed(JSONDiagnostic).init(allocator);
    errdefer diagnostics.deinit();

    for (result.diagnostics.items) |diag| {
        const loc = resolved_diagnostic_location(location_cache, diag);
        try diagnostics.append(.{
            .severity = diag.severity,
            .rule_id = rules.id_string(diag.rule_id),
            .summary = rules.summary(diag.rule_id),
            .file_path = diag.file_path,
            .message = diag.message,
            .line = if (loc) |v| v.line else null,
            .column = if (loc) |v| v.column else null,
            .hint = diag.hint,
            .effective_class = diag.effective_class,
            .effective_action = diag.effective_action,
        });
    }

    return .{
        .diagnostics = diagnostics,
        .value = .{
            .schema_version = 1,
            .policy_profile = result.policy_profile,
            .policy_applied = result.policy_applied,
            .warning_count = result.warning_count,
            .critical_count = result.critical_count,
            .suppressed_count = result.suppressed_count,
            .downgraded_count = result.downgraded_count,
            .diagnostics = diagnostics.items,
        },
    };
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

fn duration_ms_non_negative(duration: std.Io.Duration) u64 {
    if (duration.nanoseconds <= 0) return 0;
    const elapsed_ms_i96 = @divTrunc(duration.nanoseconds, std.time.ns_per_ms);
    return @intCast(elapsed_ms_i96);
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
    try std.testing.expectEqual(CliArgKind.format, cli_arg_kind("--format"));
    try std.testing.expectEqual(CliArgKind.gates, cli_arg_kind("--gates"));
    try std.testing.expectEqual(CliArgKind.allow_findings, cli_arg_kind("--allow-findings"));
    try std.testing.expectEqual(CliArgKind.positional, cli_arg_kind("src"));
}

test "parse output format arg" {
    try std.testing.expectEqual(OutputFormat.text, parse_output_format_arg("text").?);
    try std.testing.expectEqual(OutputFormat.json, parse_output_format_arg("json").?);
    try std.testing.expect(parse_output_format_arg("yaml") == null);
}

test "parse gates arg" {
    const both = parse_gates_arg("policy,perf").?;
    try std.testing.expect(both.policy);
    try std.testing.expect(both.perf);

    const spaced = parse_gates_arg(" policy , perf ").?;
    try std.testing.expect(spaced.policy);
    try std.testing.expect(spaced.perf);

    const policy_only = parse_gates_arg("policy").?;
    try std.testing.expect(policy_only.policy);
    try std.testing.expect(!policy_only.perf);

    try std.testing.expect(parse_gates_arg("perf,perf") == null);
    try std.testing.expect(parse_gates_arg("unknown") == null);
}

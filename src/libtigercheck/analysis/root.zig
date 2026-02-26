const std = @import("std");
const assert = std.debug.assert;
const graph = @import("../graph.zig");
const taint = @import("../taint.zig");
const metrics = @import("../metrics.zig");
const asserts = @import("../asserts.zig");
const rules = @import("../rules.zig");
const policy = @import("../policy.zig");
const file_cache = @import("file_cache.zig");
const architecture_shape = @import("architecture_shape.zig");
const assert_metric_quality = @import("assert_metric_quality.zig");
const global_state_pointer = @import("global_state_pointer.zig");
const implicit_walk = @import("implicit_walk.zig");
const phase_graph = @import("phase_graph.zig");
const pedantic = @import("pedantic.zig");
const style_quality = @import("style_quality.zig");
const taint_phase = @import("taint_phase.zig");
const diagnostics = @import("diagnostics.zig");
const test_depth_matrix = @import("test_depth_matrix.zig");

const append_diag = diagnostics.append;

comptime {
    _ = test_depth_matrix.analyzer_core_targets.len;
}

pub const Severity = diagnostics.Severity;
pub const Diagnostic = diagnostics.Diagnostic;
pub const Result = diagnostics.Result;

pub const AnalyzeOptions = struct {
    r4_max_function_lines: ?usize = null,
};

pub fn analyze_with_options(
    allocator: std.mem.Allocator,
    call_graph: *const graph.CallGraph,
    options: AnalyzeOptions,
) !Result {
    const active_policy = policy.for_core();
    try policy.validate(active_policy);
    const policy_max_lines = active_policy.default_thresholds.max_function_lines orelse 70;
    const default_max_function_lines: usize =
        options.r4_max_function_lines orelse @as(usize, policy_max_lines);
    const max_function_lines = default_max_function_lines;
    assert(max_function_lines > 0);
    assert(call_graph.files.items.len <= call_graph.files.capacity);
    var result = Result.init(allocator);
    errdefer result.deinit();
    result.policy_profile = active_policy.profile_name;

    var green = std.StringHashMap(void).init(allocator);
    defer green.deinit();
    var red = std.StringHashMap(void).init(allocator);
    defer red.deinit();

    var parsed_files = file_cache.Cache.init(allocator);
    defer parsed_files.deinit();
    try parsed_files.build_for_call_graph(call_graph);

    const phase_sets = phase_graph.PhaseSets{ .green = &green, .red = &red };
    try phase_graph.seed_green_and_red(allocator, call_graph, &parsed_files, phase_sets);

    var runtime_files = std.StringHashMap(void).init(allocator);
    defer runtime_files.deinit();
    try collect_runtime_files(&runtime_files, &red);
    try phase_graph.detect_recursion(allocator, call_graph, &result);

    const quality_options = AnalyzeOptions{ .r4_max_function_lines = max_function_lines };
    try detect_local_quality_violations(
        allocator,
        call_graph,
        &parsed_files,
        quality_options,
        active_policy,
        &runtime_files,
        &green,
        &red,
        &result,
    );

    try diagnostics.apply_precedence_and_dedup(&result);
    try apply_profile_policy(active_policy, &runtime_files, &result);
    try append_pedantic_pipeline_diagnostics(allocator, &result);

    return result;
}

fn append_pedantic_pipeline_diagnostics(
    allocator: std.mem.Allocator,
    result: *Result,
) !void {
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    assert(result.warning_count <= result.diagnostics.items.len);
    if (result.warning_count == 0) return;

    var families: pedantic.WarningFamilies = .{};
    for (result.diagnostics.items) |diag| {
        if (diag.severity != .warning) continue;
        pedantic.note_warning_rule(diag.rule_id, &families);
    }

    const gate_rule = pedantic.gate_rule_for_families(families.saw_nasa, families.saw_tigerstyle);
    if (result.warning_count > std.math.maxInt(u32)) {
        return error.WarningCountOverflow;
    }
    const warning_count: u32 = @intCast(result.warning_count);
    const gate_message = try pedantic.gate_message(allocator, gate_rule, warning_count);
    const warning_file = first_warning_file_path(result) orelse return;
    try append_diag(
        result,
        .critical,
        gate_rule,
        warning_file,
        gate_message,
    );
}

fn first_warning_file_path(result: *const Result) ?[]const u8 {
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    for (result.diagnostics.items) |diag| {
        if (diag.severity == .warning) {
            return diag.file_path;
        }
    }
    return null;
}

fn detect_local_quality_violations(
    allocator: std.mem.Allocator,
    call_graph: *const graph.CallGraph,
    parsed_files: *const file_cache.Cache,
    options: AnalyzeOptions,
    active_policy: policy.Policy,
    runtime_files: *const std.StringHashMap(void),
    green: *const std.StringHashMap(void),
    red: *const std.StringHashMap(void),
    result: *Result,
) !void {
    const max_lines = options.r4_max_function_lines orelse 70;
    assert(max_lines > 0);
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    const default_max_function_lines: u32 = @intCast(max_lines);

    var taint_green_functions = std.StringHashMap(void).init(allocator);
    defer taint_green_functions.deinit();
    try taint.build_green_function_set(allocator, call_graph, &taint_green_functions);

    for (call_graph.files.items) |file_path| {
        try analyze_local_quality_file(
            allocator,
            parsed_files,
            file_path,
            options,
            active_policy,
            runtime_files,
            &taint_green_functions,
            green,
            red,
            default_max_function_lines,
            result,
        );
    }
}

fn analyze_local_quality_file(
    allocator: std.mem.Allocator,
    parsed_files: *const file_cache.Cache,
    file_path: []const u8,
    options: AnalyzeOptions,
    active_policy: policy.Policy,
    runtime_files: *const std.StringHashMap(void),
    taint_green_functions: *const std.StringHashMap(void),
    green: *const std.StringHashMap(void),
    red: *const std.StringHashMap(void),
    default_max_function_lines: u32,
    result: *Result,
) !void {
    assert(file_path.len > 0);
    assert(default_max_function_lines > 0);
    if (file_path.len == 0) return;
    if (default_max_function_lines == 0) return;
    const parsed = parsed_files.get(file_path) orelse return error.MissingParsedFile;

    try analyze_local_quality_with_parsed(
        allocator,
        file_path,
        options,
        active_policy,
        runtime_files,
        taint_green_functions,
        green,
        red,
        default_max_function_lines,
        parsed.source,
        &parsed.tree,
        result,
    );
}

fn analyze_local_quality_with_parsed(
    allocator: std.mem.Allocator,
    file_path: []const u8,
    options: AnalyzeOptions,
    active_policy: policy.Policy,
    runtime_files: *const std.StringHashMap(void),
    taint_green_functions: *const std.StringHashMap(void),
    green: *const std.StringHashMap(void),
    red: *const std.StringHashMap(void),
    default_max_function_lines: u32,
    source: []const u8,
    tree: *const std.zig.Ast,
    result: *Result,
) !void {
    assert(file_path.len > 0);
    assert(source.len > 0);
    assert(default_max_function_lines > 0);
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    if (file_path.len == 0) return;
    if (source.len == 0) return;
    if (default_max_function_lines == 0) return;
    if (result.diagnostics.items.len != result.warning_count + result.critical_count) return;

    try style_quality.append_style_diagnostics_with_parsed(allocator, file_path, tree, result);
    try append_metric_and_assert_diagnostics_with_parsed(
        allocator,
        file_path,
        source,
        tree,
        options,
        active_policy,
        runtime_files,
        default_max_function_lines,
        result,
    );
    try architecture_shape.detect_with_parsed(
        allocator,
        file_path,
        source,
        tree,
        result,
    );
    try global_state_pointer.detect_with_parsed(
        allocator,
        tree,
        source,
        file_path,
        result,
    );
    try taint_phase.append_with_parsed(
        allocator,
        taint_green_functions,
        tree,
        file_path,
        green,
        red,
        result,
    );
}

fn append_metric_and_assert_diagnostics_with_parsed(
    allocator: std.mem.Allocator,
    file_path: []const u8,
    source: []const u8,
    tree: *const std.zig.Ast,
    options: AnalyzeOptions,
    active_policy: policy.Policy,
    runtime_files: *const std.StringHashMap(void),
    default_max_function_lines: u32,
    result: *Result,
) !void {
    assert(file_path.len > 0);
    assert(source.len > 0);
    assert(default_max_function_lines > 0);
    if (file_path.len == 0) return;
    if (source.len == 0) return;
    if (default_max_function_lines == 0) return;

    var file_metrics = try metrics.analyze_file_with_parsed(
        allocator,
        file_path,
        source,
        tree,
    );
    defer file_metrics.deinit();

    var file_asserts = try asserts.analyze_file_with_parsed(
        allocator,
        file_path,
        &file_metrics,
        tree,
    );
    defer file_asserts.deinit();

    const line_length_limit: u32 = policy
        .thresholds_for(active_policy, classify_file_class(active_policy, runtime_files, file_path))
        .max_line_length orelse 100;
    try style_quality.append_line_length_diag(
        allocator,
        file_path,
        &file_metrics,
        line_length_limit,
        result,
    );

    const max_function_lines = configured_max_function_lines(
        options,
        default_max_function_lines,
        policy
            .thresholds_for(
                active_policy,
                classify_file_class(active_policy, runtime_files, file_path),
            )
            .max_function_lines orelse @as(u16, @intCast(default_max_function_lines)),
    );
    try assert_metric_quality.append_metric_quality_diagnostics(
        allocator,
        max_function_lines,
        &file_metrics,
        result,
    );
    try assert_metric_quality.append_assert_quality_diagnostics(
        allocator,
        &file_metrics,
        &file_asserts,
        result,
    );
}

fn configured_max_function_lines(
    options: AnalyzeOptions,
    default_max_function_lines: u32,
    threshold_max_lines: u16,
) u32 {
    assert(default_max_function_lines > 0);
    assert(threshold_max_lines > 0);
    if (default_max_function_lines == 0) return threshold_max_lines;
    if (threshold_max_lines == 0) return default_max_function_lines;
    if (options.r4_max_function_lines == null) {
        return threshold_max_lines;
    }
    return default_max_function_lines;
}

fn detect_implicit_alloc_and_switch_else_with_limit(
    allocator: std.mem.Allocator,
    tree: *const std.zig.Ast,
    source: []const u8,
    node: std.zig.Ast.Node.Index,
    file_path: []const u8,
    result: *Result,
    max_nodes: u32,
) !void {
    assert(source.len > 0);
    assert(file_path.len > 0);
    assert(node == .root or @intFromEnum(node) < tree.nodes.len);
    assert(max_nodes > 0);
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    if (source.len == 0) return;
    if (file_path.len == 0) return;
    if (node == .root or @intFromEnum(node) >= tree.nodes.len) return;
    if (max_nodes == 0) return;
    try implicit_walk.detect_implicit_alloc_and_switch_else_with_limit(
        allocator,
        tree,
        source,
        node,
        file_path,
        result,
        max_nodes,
    );
}

test "implicit walk limit emits deterministic critical diagnostic" {
    const allocator = std.testing.allocator;
    const fixture_path = "tests/fixtures/phase01_walk_limit.zig";
    const source = try std.Io.Dir.cwd().readFileAllocOptions(
        std.Options.debug_io,
        fixture_path,
        allocator,
        std.Io.Limit.limited(64 * 1024),
        .of(u8),
        0,
    );
    defer allocator.free(source);

    var tree = try std.zig.Ast.parse(allocator, source, .zig);
    defer tree.deinit(allocator);

    var body_node: std.zig.Ast.Node.Index = .root;
    for (tree.rootDecls()) |decl| {
        if (tree.nodes.items(.tag)[@intFromEnum(decl)] != .fn_decl) continue;
        var proto_buf: [1]std.zig.Ast.Node.Index = undefined;
        const proto = tree.fullFnProto(&proto_buf, decl) orelse continue;
        const name_token = proto.name_token orelse continue;
        if (!std.mem.eql(u8, tree.tokenSlice(name_token), "main")) continue;
        body_node = tree.nodeData(decl).node_and_node[1];
        break;
    }
    try std.testing.expect(body_node != .root);

    var result = Result.init(allocator);
    defer result.deinit();

    try detect_implicit_alloc_and_switch_else_with_limit(
        allocator,
        &tree,
        source,
        body_node,
        fixture_path,
        &result,
        1,
    );

    try std.testing.expectEqual(@as(usize, 1), result.critical_count);
    try std.testing.expectEqual(@as(usize, 1), result.diagnostics.items.len);
    const diag = result.diagnostics.items[0];
    try std.testing.expectEqual(Severity.critical, diag.severity);
    try std.testing.expectEqual(rules.Id.N02_BOUNDED_LOOPS, diag.rule_id);
    try std.testing.expectEqualStrings(
        fixture_path,
        diag.file_path,
    );
    try std.testing.expectEqualStrings(implicit_walk.implicit_walk_limit_message, diag.message);
}

fn apply_profile_policy(
    active_policy: policy.Policy,
    runtime_files: *const std.StringHashMap(void),
    result: *Result,
) !void {
    assert(active_policy.profile_name.len > 0);
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);

    var filtered = std.array_list.Managed(Diagnostic).init(result.diagnostics.allocator);
    errdefer filtered.deinit();

    var warning_count: usize = 0;
    var critical_count: usize = 0;
    var suppressed_count: usize = 0;
    var downgraded_count: usize = 0;

    for (result.diagnostics.items) |diag| {
        const class = classify_file_class(active_policy, runtime_files, diag.file_path);

        const action = policy.action_for(active_policy, class, diag.rule_id);
        var effective_diag = diag;
        effective_diag.effective_class = class;
        effective_diag.effective_action = action;

        if (action == .off) {
            suppressed_count += 1;
            continue;
        }

        if (action == .warn and effective_diag.severity == .critical) {
            effective_diag.severity = .warning;
            downgraded_count += 1;
        }

        try filtered.append(effective_diag);
        if (effective_diag.severity == .critical) {
            critical_count += 1;
        } else {
            warning_count += 1;
        }
    }

    result.diagnostics.deinit();
    result.diagnostics = filtered;
    result.warning_count = warning_count;
    result.critical_count = critical_count;
    result.suppressed_count = suppressed_count;
    result.downgraded_count = downgraded_count;
    result.policy_applied = true;
}

fn collect_runtime_files(
    runtime_files: *std.StringHashMap(void),
    red: *const std.StringHashMap(void),
) !void {
    try collect_runtime_files_from_phase_set(runtime_files, red);
}

fn classify_file_class(
    active_policy: policy.Policy,
    runtime_files: *const std.StringHashMap(void),
    file_path: []const u8,
) policy.CodeClass {
    assert(file_path.len > 0);
    if (file_path.len == 0) return .runtime;
    if (runtime_files.contains(file_path)) {
        return .runtime;
    }
    return policy.classify_path(active_policy, file_path);
}

fn collect_runtime_files_from_phase_set(
    runtime_files: *std.StringHashMap(void),
    phase_set: *const std.StringHashMap(void),
) !void {
    var iter = phase_set.keyIterator();
    while (iter.next()) |node| {
        const file_path = file_from_canonical(node.*);
        if (file_path.len == 0) {
            continue;
        }
        try runtime_files.put(file_path, {});
    }
}

fn file_from_canonical(canonical: []const u8) []const u8 {
    assert(canonical.len > 0);
    if (canonical.len == 0) return "";
    const sep = std.mem.indexOf(u8, canonical, "::") orelse return canonical;
    return canonical[0..sep];
}

const std = @import("std");
const assert = std.debug.assert;
const graph = @import("../graph.zig");
const taint = @import("../taint.zig");
const style = @import("../style.zig");
const metrics = @import("../metrics.zig");
const asserts = @import("../asserts.zig");
const rules = @import("../rules.zig");
const policy = @import("../policy.zig");
const ast_walk = @import("../ast_walk.zig");
const call_expr = @import("call_expr.zig");
const roles = @import("roles.zig");
const pedantic = @import("pedantic.zig");
const event_pacing = @import("event_pacing.zig");
const control_data_boundary = @import("control_data_boundary.zig");
const queue_growth_bounds = @import("queue_growth_bounds.zig");

const ast_walk_nodes_max: usize = 4000;
const large_arg_array_threshold: u64 = 64;
const large_arg_value_threshold_bytes: u64 = 64;
const pointer_size_bytes: u64 = 8;
const slice_size_bytes: u64 = 16;
const declaration_locality_gap_statements: usize = 5;
const phase_queue_bound_limit: usize = 32768;
const tb03_copy_api_message =
    "raw copy API is banned (`@memcpy`, `std.mem.copyForwards`, `std.mem.copyBackwards`); " ++
    "use explicit copy helper (`stdx.copy_disjoint`, `stdx.copy_left`, or `stdx.copy_right`)";

const collect_call_path = call_expr.collect_call_path;

const PhaseSets = struct {
    green: *std.StringHashMap(void),
    red: *std.StringHashMap(void),
};

const LargeArgSymbolIndex = struct {
    const_expr_nodes: std.StringHashMap(std.zig.Ast.Node.Index),
    type_decl_nodes: std.StringHashMap(std.zig.Ast.Node.Index),

    fn init(allocator: std.mem.Allocator) LargeArgSymbolIndex {
        return .{
            .const_expr_nodes = std.StringHashMap(std.zig.Ast.Node.Index).init(allocator),
            .type_decl_nodes = std.StringHashMap(std.zig.Ast.Node.Index).init(allocator),
        };
    }

    fn deinit(self: *LargeArgSymbolIndex) void {
        self.const_expr_nodes.deinit();
        self.type_decl_nodes.deinit();
    }
};

const ConstVisitState = struct {
    names: [32][]const u8 = undefined,
    len: u8 = 0,
};

const TypeVisitState = struct {
    names: [32][]const u8 = undefined,
    len: u8 = 0,
};

pub const Severity = enum {
    warning,
    critical,
};

pub const Diagnostic = struct {
    severity: Severity,
    rule_id: rules.Id,
    file_path: []const u8,
    message: []const u8,
    line: ?u32 = null,
    column: ?u32 = null,
    hint: ?[]const u8 = null,
    effective_class: ?policy.CodeClass = null,
    effective_action: ?policy.Action = null,
};

pub const Result = struct {
    diagnostics: std.array_list.Managed(Diagnostic),
    critical_count: usize,
    warning_count: usize,
    policy_profile: []const u8,
    suppressed_count: usize,
    downgraded_count: usize,
    policy_applied: bool,

    pub fn init(allocator: std.mem.Allocator) Result {
        return .{
            .diagnostics = std.array_list.Managed(Diagnostic).init(allocator),
            .critical_count = 0,
            .warning_count = 0,
            .policy_profile = "",
            .suppressed_count = 0,
            .downgraded_count = 0,
            .policy_applied = false,
        };
    }

    pub fn deinit(self: *Result) void {
        self.diagnostics.deinit();
    }
};

pub const AnalyzeOptions = struct {
    profile: policy.Profile = .strict_core,
    r4_max_function_lines: ?usize = null,
};

pub fn analyze(allocator: std.mem.Allocator, call_graph: *const graph.CallGraph) !Result {
    return analyze_with_options(allocator, call_graph, .{});
}

pub fn analyze_with_options(
    allocator: std.mem.Allocator,
    call_graph: *const graph.CallGraph,
    options: AnalyzeOptions,
) !Result {
    const active_policy = policy.for_profile(options.profile);
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

    const phase_sets = PhaseSets{ .green = &green, .red = &red };
    try seed_green_and_red(allocator, call_graph, phase_sets);

    var runtime_files = std.StringHashMap(void).init(allocator);
    defer runtime_files.deinit();
    try collect_runtime_files(&runtime_files, &red);

    try detect_recursion(allocator, call_graph, &result);
    const quality_options = AnalyzeOptions{
        .profile = options.profile,
        .r4_max_function_lines = max_function_lines,
    };
    try detect_local_quality_violations(
        allocator,
        call_graph,
        quality_options,
        active_policy,
        &runtime_files,
        &green,
        &red,
        &result,
    );
    try apply_diagnostic_precedence_and_dedup(&result);
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

fn apply_diagnostic_precedence_and_dedup(result: *Result) !void {
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    sort_diagnostics_by_precedence(result);

    var filtered = std.array_list.Managed(Diagnostic).init(result.diagnostics.allocator);
    errdefer filtered.deinit();

    var warning_count: usize = 0;
    var critical_count: usize = 0;

    for (result.diagnostics.items) |diag| {
        if (has_exact_diagnostic_already_reported(filtered.items, diag)) {
            continue;
        }
        try filtered.append(diag);
        if (diag.severity == .critical) {
            critical_count += 1;
        } else {
            warning_count += 1;
        }
    }

    result.diagnostics.deinit();
    result.diagnostics = filtered;
    result.warning_count = warning_count;
    result.critical_count = critical_count;
}

fn sort_diagnostics_by_precedence(result: *Result) void {
    std.mem.sort(Diagnostic, result.diagnostics.items, {}, struct {
        fn lt(_: void, lhs: Diagnostic, rhs: Diagnostic) bool {
            if (lhs.severity != rhs.severity) {
                return lhs.severity == .critical;
            }
            const lhs_rule = @intFromEnum(lhs.rule_id);
            const rhs_rule = @intFromEnum(rhs.rule_id);
            if (lhs_rule != rhs_rule) {
                return lhs_rule < rhs_rule;
            }
            const file_order = std.mem.order(u8, lhs.file_path, rhs.file_path);
            if (file_order != .eq) {
                return file_order == .lt;
            }
            const lhs_line = lhs.line orelse 0;
            const rhs_line = rhs.line orelse 0;
            if (lhs_line != rhs_line) {
                return lhs_line < rhs_line;
            }
            const lhs_column = lhs.column orelse 0;
            const rhs_column = rhs.column orelse 0;
            if (lhs_column != rhs_column) {
                return lhs_column < rhs_column;
            }
            return std.mem.order(u8, lhs.message, rhs.message) == .lt;
        }
    }.lt);
}

fn has_exact_diagnostic_already_reported(
    existing: []const Diagnostic,
    candidate: Diagnostic,
) bool {
    assert(existing.len <= 4096);
    assert(candidate.file_path.len > 0);
    if (existing.len == 0) return false;
    if (candidate.file_path.len == 0) return false;
    for (existing) |diag| {
        if (diag_exact_match(diag, candidate)) {
            return true;
        }
    }
    return false;
}

fn diag_exact_match(lhs: Diagnostic, rhs: Diagnostic) bool {
    assert(lhs.file_path.len > 0);
    assert(rhs.file_path.len > 0);
    if (lhs.file_path.len == 0 or rhs.file_path.len == 0) return false;
    if (lhs.severity != rhs.severity) return false;
    if (lhs.rule_id != rhs.rule_id) return false;
    if (!std.mem.eql(u8, lhs.file_path, rhs.file_path)) return false;
    if (lhs.line != rhs.line) return false;
    if (lhs.column != rhs.column) return false;
    return std.mem.eql(u8, lhs.message, rhs.message);
}

fn append_diag(
    result: *Result,
    severity: Severity,
    rule_id: rules.Id,
    file_path: []const u8,
    message: []const u8,
) !void {
    assert(file_path.len > 0);
    assert(message.len > 0);
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    if (file_path.len == 0) return;
    if (message.len == 0) return;
    for (result.diagnostics.items) |existing| {
        if (diag_is_exact_match(existing, severity, rule_id, file_path, message, null, null)) {
            return;
        }
    }

    try result.diagnostics.append(.{
        .severity = severity,
        .rule_id = rule_id,
        .file_path = file_path,
        .message = message,
        .hint = default_hint_for_rule(rule_id),
    });
    if (severity == .critical) {
        result.critical_count += 1;
    } else {
        result.warning_count += 1;
    }
}

fn append_diag_pair(
    result: *Result,
    severity: Severity,
    first_rule_id: rules.Id,
    second_rule_id: rules.Id,
    file_path: []const u8,
    message: []const u8,
) !void {
    assert(file_path.len > 0);
    assert(message.len > 0);
    if (file_path.len == 0) return;
    if (message.len == 0) return;
    if (first_rule_id == second_rule_id) return;
    try append_diag(result, severity, first_rule_id, file_path, message);
    try append_diag(result, severity, second_rule_id, file_path, message);
}

fn diag_is_exact_match(
    existing: Diagnostic,
    severity: Severity,
    rule_id: rules.Id,
    file_path: []const u8,
    message: []const u8,
    line: ?u32,
    column: ?u32,
) bool {
    assert(file_path.len > 0);
    assert(message.len > 0);
    if (file_path.len == 0) return false;
    if (message.len == 0) return false;
    if (existing.severity != severity) return false;
    if (existing.rule_id != rule_id) return false;
    if (!std.mem.eql(u8, existing.file_path, file_path)) return false;
    if (existing.line != line) return false;
    if (existing.column != column) return false;
    return std.mem.eql(u8, existing.message, message);
}

fn default_hint_for_rule(rule_id: rules.Id) ?[]const u8 {
    return switch (rule_id) {
        .N02_BOUNDED_LOOPS,
        .TS02_EXPLICIT_BOUNDS,
        .N03_STATIC_MEMORY,
        .TS07_MEMORY_PHASE,
        .TS12_PLANE_BOUNDARY,
        => rules.rewrite_hint(rule_id),
        else => null,
    };
}

fn seed_green_and_red(
    allocator: std.mem.Allocator,
    call_graph: *const graph.CallGraph,
    phase_sets: PhaseSets,
) !void {
    assert(
        call_graph.edges.count() <= call_graph.nodes.count() * call_graph.nodes.count() or
            call_graph.nodes.count() == 0,
    );
    assert(call_graph.nodes.count() > 0 or call_graph.edges.count() == 0);
    var edges_by_caller = std.StringHashMap(std.array_list.Managed([]const u8)).init(allocator);
    defer deinit_edge_map(&edges_by_caller);
    try collect_edges_by_caller(allocator, call_graph, &edges_by_caller);

    var queue = std.array_list.Managed([]const u8).init(allocator);
    defer queue.deinit();
    try seed_phase_roots(call_graph, phase_sets, &queue);
    try propagate_phase(&queue, &edges_by_caller, phase_sets.green);
    try seed_red_from_runtime_loops(allocator, call_graph, phase_sets.red);
    try refill_queue_from_set(&queue, phase_sets.red);
    try propagate_phase(&queue, &edges_by_caller, phase_sets.red);
}

fn deinit_edge_map(edges_by_caller: *std.StringHashMap(std.array_list.Managed([]const u8))) void {
    var it = edges_by_caller.iterator();
    while (it.next()) |entry| {
        entry.value_ptr.deinit();
    }
    edges_by_caller.deinit();
}

fn collect_edges_by_caller(
    allocator: std.mem.Allocator,
    call_graph: *const graph.CallGraph,
    edges_by_caller: *std.StringHashMap(std.array_list.Managed([]const u8)),
) !void {
    assert(edges_by_caller.count() <= call_graph.edges.count());
    assert(call_graph.edges.count() > 0 or edges_by_caller.count() == 0);
    var edge_iter = call_graph.edges.keyIterator();
    while (edge_iter.next()) |edge| {
        const sep = std.mem.indexOf(u8, edge.*, "->") orelse continue;
        const caller = edge.*[0..sep];
        const callee = edge.*[sep + 2 ..];

        const gop = try edges_by_caller.getOrPut(caller);
        if (!gop.found_existing) {
            gop.value_ptr.* = std.array_list.Managed([]const u8).init(allocator);
        }
        try gop.value_ptr.append(callee);
    }
}

fn seed_phase_roots(
    call_graph: *const graph.CallGraph,
    phase_sets: PhaseSets,
    queue: *std.array_list.Managed([]const u8),
) !void {
    assert(queue.items.len <= phase_queue_bound_limit);
    assert(phase_sets.green.count() <= call_graph.nodes.count());
    if (queue.items.len > phase_queue_bound_limit) return error.PhaseQueueBoundExceeded;
    var node_iter = call_graph.nodes.keyIterator();
    while (node_iter.next()) |node| {
        if (std.mem.endsWith(u8, node.*, "::main")) {
            try phase_sets.green.put(node.*, {});
            if (queue.items.len >= phase_queue_bound_limit) {
                return error.PhaseQueueBoundExceeded;
            }
            try queue.append(node.*);
        }
        if (is_red_phase_root(node.*)) {
            try phase_sets.red.put(node.*, {});
        }
    }
}

fn is_red_phase_root(node_name: []const u8) bool {
    assert(node_name.len > 0);
    if (node_name.len == 0) return false;
    if (std.mem.endsWith(u8, node_name, "::run")) return true;
    if (std.mem.endsWith(u8, node_name, "::start")) return true;
    return std.mem.endsWith(u8, node_name, "::listen");
}

fn seed_red_from_runtime_loops(
    allocator: std.mem.Allocator,
    call_graph: *const graph.CallGraph,
    red: *std.StringHashMap(void),
) !void {
    assert(call_graph.files.items.len <= call_graph.files.capacity);
    assert(red.count() <= call_graph.nodes.count());
    for (call_graph.files.items) |file_path| {
        assert(file_path.len > 0);
        const src = try std.Io.Dir.cwd().readFileAllocOptions(
            std.Options.debug_io,
            file_path,
            allocator,
            std.Io.Limit.limited(16 * 1024 * 1024),
            .of(u8),
            0,
        );
        defer allocator.free(src);

        var tree = try std.zig.Ast.parse(allocator, src, .zig);
        defer tree.deinit(allocator);

        var function_names = std.StringHashMap(void).init(allocator);
        defer function_names.deinit();
        try collect_runtime_loop_function_names(&tree, &function_names);

        var fn_it = function_names.keyIterator();
        while (fn_it.next()) |function_name| {
            if (find_canonical_call_node(call_graph, file_path, function_name.*)) |canonical| {
                try red.put(canonical, {});
            }
        }
    }
}

const RuntimeLoopWhileVisitCtx = struct {
    found: bool,
};

fn collect_runtime_loop_function_names(
    tree: *const std.zig.Ast,
    function_names: *std.StringHashMap(void),
) !void {
    assert(tree.nodes.items(.tag).len == tree.nodes.len);
    assert(function_names.count() <= tree.nodes.len);
    var index: usize = 0;
    while (index < tree.nodes.len) : (index += 1) {
        const node: std.zig.Ast.Node.Index = @enumFromInt(index);
        if (tree.nodes.items(.tag)[index] != .fn_decl) {
            continue;
        }

        var proto_buf: [1]std.zig.Ast.Node.Index = undefined;
        const proto = tree.fullFnProto(&proto_buf, node) orelse continue;
        const name_token = proto.name_token orelse continue;
        const body_node = tree.nodeData(node).node_and_node[1];
        if (body_node == .root or @intFromEnum(body_node) >= tree.nodes.len) {
            continue;
        }
        if (!function_body_has_runtime_true_while(tree, body_node)) {
            continue;
        }
        try function_names.put(tree.tokenSlice(name_token), {});
    }
}

fn function_body_has_runtime_true_while(
    tree: *const std.zig.Ast,
    body_node: std.zig.Ast.Node.Index,
) bool {
    if (body_node == .root or @intFromEnum(body_node) >= tree.nodes.len) {
        return false;
    }

    var ctx = RuntimeLoopWhileVisitCtx{ .found = false };
    ast_walk.walk(tree, body_node, &ctx, runtime_loop_while_visit_node) catch return false;
    return ctx.found;
}

fn runtime_loop_while_visit_node(
    tree: *const std.zig.Ast,
    node: std.zig.Ast.Node.Index,
    ctx_opaque: *anyopaque,
) anyerror!void {
    assert(tree.nodes.items(.tag).len == tree.nodes.len);
    assert(node == .root or @intFromEnum(node) < tree.nodes.len);
    const ctx: *RuntimeLoopWhileVisitCtx = @ptrCast(@alignCast(ctx_opaque));
    if (ctx.found) {
        return;
    }
    if (node == .root or @intFromEnum(node) >= tree.nodes.len) {
        return;
    }
    if (!is_while_tag(tree.nodes.items(.tag)[@intFromEnum(node)])) {
        return;
    }

    const full = tree.fullWhile(node) orelse return;
    if (is_literal_true(tree, full.ast.cond_expr)) {
        ctx.found = true;
    }
}

fn is_while_tag(tag: std.zig.Ast.Node.Tag) bool {
    return tag == .while_simple or tag == .while_cont or tag == .@"while";
}

fn find_canonical_call_node(
    call_graph: *const graph.CallGraph,
    file_path: []const u8,
    function_name: []const u8,
) ?[]const u8 {
    assert(file_path.len > 0);
    assert(function_name.len > 0);
    assert(call_graph.files.items.len <= call_graph.files.capacity);
    if (file_path.len == 0) return null;
    if (function_name.len == 0) return null;
    var node_iter = call_graph.nodes.keyIterator();
    while (node_iter.next()) |node| {
        if (!std.mem.startsWith(u8, node.*, file_path)) continue;
        if (node.*.len <= file_path.len + 2) continue;
        if (!std.mem.eql(u8, node.*[file_path.len .. file_path.len + 2], "::")) continue;
        if (std.mem.eql(u8, node.*[file_path.len + 2 ..], function_name)) {
            return node.*;
        }
    }
    return null;
}

fn refill_queue_from_set(
    queue: *std.array_list.Managed([]const u8),
    set: *std.StringHashMap(void),
) !void {
    queue.clearRetainingCapacity();
    var set_it = set.keyIterator();
    while (set_it.next()) |node| {
        if (queue.items.len >= phase_queue_bound_limit) {
            return error.PhaseQueueBoundExceeded;
        }
        try queue.append(node.*);
    }
}

fn propagate_phase(
    queue: *std.array_list.Managed([]const u8),
    edges_by_caller: *const std.StringHashMap(std.array_list.Managed([]const u8)),
    phase: *std.StringHashMap(void),
) !void {
    assert(queue.items.len <= phase_queue_bound_limit);
    assert(phase.count() >= queue.items.len);
    var index: usize = 0;
    while (index < queue.items.len) : (index += 1) {
        const current = queue.items[index];
        if (edges_by_caller.get(current)) |callees| {
            for (callees.items) |callee| {
                if (!phase.contains(callee)) {
                    try phase.put(callee, {});
                    if (queue.items.len >= phase_queue_bound_limit) {
                        return error.PhaseQueueBoundExceeded;
                    }
                    try queue.append(callee);
                }
            }
        }
    }
}

fn detect_recursion(
    allocator: std.mem.Allocator,
    call_graph: *const graph.CallGraph,
    result: *Result,
) !void {
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    assert(call_graph.nodes.count() > 0 or call_graph.edges.count() == 0);
    var state = std.StringHashMap(u8).init(allocator);
    defer state.deinit();

    var adjacency = std.StringHashMap(std.array_list.Managed([]const u8)).init(allocator);
    defer {
        var it = adjacency.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.deinit();
        }
        adjacency.deinit();
    }

    var edge_iter = call_graph.edges.keyIterator();
    while (edge_iter.next()) |edge| {
        const sep = std.mem.indexOf(u8, edge.*, "->") orelse continue;
        const caller = edge.*[0..sep];
        const callee = edge.*[sep + 2 ..];
        const gop = try adjacency.getOrPut(caller);
        if (!gop.found_existing) {
            gop.value_ptr.* = std.array_list.Managed([]const u8).init(allocator);
        }
        try gop.value_ptr.append(callee);
    }

    var cycle_reported = false;

    var node_iter = call_graph.nodes.keyIterator();
    while (node_iter.next()) |node| {
        if (cycle_reported) break;
        if ((state.get(node.*) orelse 0) == 0) {
            try dfs_detect_cycle(node.*, &adjacency, &state, result, &cycle_reported);
        }
    }
}

fn dfs_detect_cycle(
    node: []const u8,
    adjacency: *const std.StringHashMap(std.array_list.Managed([]const u8)),
    state: *std.StringHashMap(u8),
    result: *Result,
    cycle_reported: *bool,
) !void {
    assert(node.len > 0);
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    if (node.len == 0) return;
    if (result.diagnostics.items.len != result.warning_count + result.critical_count) return;
    if (cycle_reported.*) return;
    try state.put(node, 1);

    if (adjacency.get(node)) |callees| {
        for (callees.items) |callee| {
            const callee_state = state.get(callee) orelse 0;
            if (callee_state == 1) {
                try append_diag_pair(
                    result,
                    .critical,
                    .N01_CONTROL_FLOW,
                    .TS01_SIMPLE_FLOW,
                    file_from_canonical(node),
                    "cycle detected in call graph",
                );
                cycle_reported.* = true;
                return;
            }
            if (callee_state == 0) {
                try dfs_detect_cycle(callee, adjacency, state, result, cycle_reported);
                if (cycle_reported.*) return;
            }
        }
    }

    try state.put(node, 2);
}

fn append_first_unbounded_loop_diag(
    allocator: std.mem.Allocator,
    function_facts: []const taint.FunctionFacts,
    file_path: []const u8,
    result: *Result,
) !void {
    assert(file_path.len > 0);
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    if (file_path.len == 0) return;
    if (result.diagnostics.items.len != result.warning_count + result.critical_count) return;
    for (function_facts) |facts| {
        if (!facts.has_unbounded_loop) continue;
        const msg = try std.fmt.allocPrint(
            allocator,
            "unproven loop bound in `{s}` (must be const/comptime/init-time immutable); " ++
                "rewrite with explicit finite upper bound",
            .{facts.function_name},
        );
        try append_diag_pair(
            result,
            .critical,
            .N02_BOUNDED_LOOPS,
            .TS02_EXPLICIT_BOUNDS,
            file_path,
            msg,
        );
        return;
    }
}

fn detect_local_quality_violations(
    allocator: std.mem.Allocator,
    call_graph: *const graph.CallGraph,
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

    const source = try std.Io.Dir.cwd().readFileAllocOptions(
        std.Options.debug_io,
        file_path,
        allocator,
        std.Io.Limit.limited(16 * 1024 * 1024),
        .of(u8),
        0,
    );
    defer allocator.free(source);

    const tree = try std.zig.Ast.parse(allocator, source, .zig);
    defer {
        var t = tree;
        t.deinit(allocator);
    }

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
        source,
        &tree,
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

    try append_style_diagnostics_with_parsed(allocator, file_path, tree, result);

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
    try append_line_length_diag(
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
    try append_metric_quality_diagnostics(allocator, max_function_lines, &file_metrics, result);
    try append_assert_quality_diagnostics(allocator, &file_metrics, &file_asserts, result);
    try detect_architecture_shape_violations_with_parsed(
        allocator,
        file_path,
        source,
        tree,
        result,
    );
    try detect_global_state_and_pointer_violations_with_parsed(
        allocator,
        tree,
        source,
        file_path,
        result,
    );
    try append_taint_phase_and_loop_diagnostics_with_parsed(
        allocator,
        taint_green_functions,
        tree,
        file_path,
        green,
        red,
        result,
    );
}

fn append_taint_phase_and_loop_diagnostics_with_parsed(
    allocator: std.mem.Allocator,
    taint_green_functions: *const std.StringHashMap(void),
    tree: *const std.zig.Ast,
    file_path: []const u8,
    green: *const std.StringHashMap(void),
    red: *const std.StringHashMap(void),
    result: *Result,
) !void {
    assert(file_path.len > 0);
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    if (file_path.len == 0) return;
    if (result.diagnostics.items.len != result.warning_count + result.critical_count) return;

    var file_facts = try taint.analyze_file_with_parsed_and_green_functions(
        allocator,
        file_path,
        tree,
        taint_green_functions,
    );
    defer file_facts.deinit();

    try append_memory_phase_diags_from_facts(
        allocator,
        file_facts.functions.items,
        green,
        red,
        result,
    );
    try append_first_unbounded_loop_diag(allocator, file_facts.functions.items, file_path, result);
}

fn append_memory_phase_diags_from_facts(
    allocator: std.mem.Allocator,
    function_facts: []const taint.FunctionFacts,
    green: *const std.StringHashMap(void),
    red: *const std.StringHashMap(void),
    result: *Result,
) !void {
    assert(function_facts.len <= std.math.maxInt(u32));
    assert(green.count() <= std.math.maxInt(u32));
    assert(red.count() <= std.math.maxInt(u32));
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    if (function_facts.len == 0) return;
    if (green.count() == 0 and red.count() == 0) return;
    if (result.diagnostics.items.len != result.warning_count + result.critical_count) return;
    for (function_facts) |facts| {
        if (!facts.has_forbidden_alloc) continue;
        const in_green = green.contains(facts.canonical_name);
        const in_red = red.contains(facts.canonical_name);
        if (!in_red) continue;
        try append_memory_phase_diag_for_fact(allocator, facts, in_green, result);
    }
}

fn append_memory_phase_diag_for_fact(
    allocator: std.mem.Allocator,
    facts: taint.FunctionFacts,
    in_green: bool,
    result: *Result,
) !void {
    assert(facts.file_path.len > 0);
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    if (facts.file_path.len == 0) return;
    if (in_green) {
        const mixed_msg = try std.fmt.allocPrint(
            allocator,
            "runtime allocation reaches execution path in `{s}` (mixed GREEN/RED reachability)",
            .{facts.function_name},
        );
        try append_diag_pair(
            result,
            .critical,
            .N03_STATIC_MEMORY,
            .TS07_MEMORY_PHASE,
            facts.file_path,
            mixed_msg,
        );
        return;
    }

    const red_msg = try std.fmt.allocPrint(
        allocator,
        "runtime allocation reaches execution path in `{s}` (RED)",
        .{facts.function_name},
    );
    try append_diag_pair(
        result,
        .critical,
        .N03_STATIC_MEMORY,
        .TS07_MEMORY_PHASE,
        facts.file_path,
        red_msg,
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

fn append_style_diagnostics_with_parsed(
    allocator: std.mem.Allocator,
    file_path: []const u8,
    tree: *const std.zig.Ast,
    result: *Result,
) !void {
    assert(file_path.len > 0);
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    if (file_path.len == 0) return;
    if (result.diagnostics.items.len != result.warning_count + result.critical_count) return;
    var style_diagnostics = std.array_list.Managed(style.StyleDiagnostic).init(allocator);
    defer style_diagnostics.deinit();
    try style.analyze_file_with_parsed(allocator, file_path, tree, &style_diagnostics);
    for (style_diagnostics.items) |diag| {
        try append_diag(result, .warning, diag.rule_id, diag.file_path, diag.message);
    }
}

fn append_line_length_diag(
    allocator: std.mem.Allocator,
    file_path: []const u8,
    file_metrics: *const metrics.FileMetrics,
    line_length_limit: u32,
    result: *Result,
) !void {
    assert(file_path.len > 0);
    assert(line_length_limit > 0);
    if (file_path.len == 0) return;
    if (line_length_limit == 0) return;
    const long_line_count = count_lines_over_limit(file_metrics, line_length_limit);
    if (long_line_count == 0) return;
    const msg = try std.fmt.allocPrint(
        allocator,
        "TS26_LINE_LENGTH: {d} line(s) exceed {d} column limit (max: {d})",
        .{
            long_line_count,
            line_length_limit,
            file_metrics.max_line_length,
        },
    );
    try append_diag(result, .warning, .TS26_LINE_LENGTH, file_path, msg);
}

fn detect_architecture_shape_violations_with_parsed(
    allocator: std.mem.Allocator,
    file_path: []const u8,
    source: []const u8,
    tree: *const std.zig.Ast,
    result: *Result,
) !void {
    assert(file_path.len > 0);
    assert(source.len > 0);
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    if (file_path.len == 0) return;
    if (source.len == 0) return;
    if (result.diagnostics.items.len != result.warning_count + result.critical_count) return;

    var role_index = roles.SemanticIndex.init(allocator, tree);
    defer role_index.deinit();

    for (tree.rootDecls()) |decl| {
        try detect_architecture_shape_fn_decl(
            allocator,
            file_path,
            source,
            tree,
            decl,
            &role_index,
            result,
        );
    }
}

fn detect_architecture_shape_fn_decl(
    allocator: std.mem.Allocator,
    file_path: []const u8,
    source: []const u8,
    tree: *const std.zig.Ast,
    decl: std.zig.Ast.Node.Index,
    role_index: *roles.SemanticIndex,
    result: *Result,
) !void {
    assert(file_path.len > 0);
    assert(source.len > 0);
    assert(decl == .root or @intFromEnum(decl) < tree.nodes.len);
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    if (file_path.len == 0) return;
    if (source.len == 0) return;
    if (decl == .root or @intFromEnum(decl) >= tree.nodes.len) return;
    if (result.diagnostics.items.len != result.warning_count + result.critical_count) return;
    if (tree.nodes.items(.tag)[@intFromEnum(decl)] != .fn_decl) return;
    var fn_buf: [1]std.zig.Ast.Node.Index = undefined;
    const proto = tree.fullFnProto(&fn_buf, decl) orelse return;
    const fn_name_token = proto.name_token orelse return;
    const fn_name = tree.tokenSlice(fn_name_token);
    const body_node = tree.nodeData(decl).node_and_node[1];
    if (body_node == .root) return;

    try detect_context_bundle_violation(allocator, tree, proto, file_path, fn_name, result);
    try detect_tag_dispatch_violation(
        allocator,
        tree,
        source,
        body_node,
        file_path,
        fn_name,
        result,
    );
    try detect_plane_boundary_violation(
        allocator,
        role_index,
        body_node,
        file_path,
        fn_name,
        result,
    );
}

fn detect_context_bundle_violation(
    allocator: std.mem.Allocator,
    tree: *const std.zig.Ast,
    proto: std.zig.Ast.full.FnProto,
    file_path: []const u8,
    fn_name: []const u8,
    result: *Result,
) !void {
    assert(file_path.len > 0);
    assert(fn_name.len > 0);
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    if (file_path.len == 0) return;
    if (fn_name.len == 0) return;
    if (result.diagnostics.items.len != result.warning_count + result.critical_count) return;
    if (!is_implicit_related_function(fn_name)) return;
    if (!fn_uses_walk_plumbing_signature(tree, proto)) return;
    const msg = try std.fmt.allocPrint(
        allocator,
        "Use context bundling for implicit-walk family `{s}` " ++
            "to avoid repeated plumbing parameters.",
        .{fn_name},
    );
    try append_diag(result, .warning, .TB04_CONTEXT_BUNDLE, file_path, msg);
}

fn detect_tag_dispatch_violation(
    allocator: std.mem.Allocator,
    tree: *const std.zig.Ast,
    source: []const u8,
    body_node: std.zig.Ast.Node.Index,
    file_path: []const u8,
    fn_name: []const u8,
    result: *Result,
) !void {
    assert(file_path.len > 0);
    assert(fn_name.len > 0);
    assert(source.len > 0);
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    if (file_path.len == 0) return;
    if (fn_name.len == 0) return;
    if (source.len == 0) return;
    if (result.diagnostics.items.len != result.warning_count + result.critical_count) return;
    if (!std.mem.endsWith(u8, fn_name, "_family")) return;
    const tag_guard_count = count_substring_in_function_body(
        tree,
        source,
        body_node,
        "tag_in_set(",
    );
    if (tag_guard_count < 3) return;
    const msg = try std.fmt.allocPrint(
        allocator,
        "Function `{s}` uses repeated tag-set guards ({d}); " ++
            "prefer direct tag dispatch.",
        .{ fn_name, tag_guard_count },
    );
    try append_diag(result, .warning, .TB05_TAG_DISPATCH, file_path, msg);
}

fn detect_plane_boundary_violation(
    allocator: std.mem.Allocator,
    role_index: *roles.SemanticIndex,
    body_node: std.zig.Ast.Node.Index,
    file_path: []const u8,
    fn_name: []const u8,
    result: *Result,
) !void {
    assert(file_path.len > 0);
    assert(fn_name.len > 0);
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    if (file_path.len == 0) return;
    if (fn_name.len == 0) return;
    if (result.diagnostics.items.len != result.warning_count + result.critical_count) return;
    if (!control_data_boundary.has_violation(role_index, body_node)) return;
    const msg = try std.fmt.allocPrint(
        allocator,
        "TS12_PLANE_BOUNDARY: function `{s}` mixes control-plane and data-plane " ++
            "operations without explicit boundary handoff; extract a boundary adapter " ++
            "function between planes",
        .{fn_name},
    );
    try append_diag(result, .warning, .TS12_PLANE_BOUNDARY, file_path, msg);
}

fn is_implicit_related_function(fn_name: []const u8) bool {
    assert(fn_name.len > 0);
    if (fn_name.len == 0) return false;
    return std.mem.startsWith(u8, fn_name, "walk_implicit_") and
        std.mem.endsWith(u8, fn_name, "_related");
}

fn fn_uses_walk_plumbing_signature(tree: *const std.zig.Ast, proto: std.zig.Ast.full.FnProto) bool {
    assert(tree.nodes.items(.main_token).len == tree.nodes.len);
    assert(tree.tokens.len > 0);
    if (tree.nodes.items(.main_token).len != tree.nodes.len) return false;
    if (tree.tokens.len == 0) return false;
    var flags: WalkPlumbingFlags = .{};
    var param_count: u8 = 0;

    var it = proto.iterate(tree);
    while (it.next()) |param| {
        if (param_count < std.math.maxInt(u8)) {
            param_count += 1;
        }
        const name_token = param.name_token orelse continue;
        set_walk_plumbing_flag(tree.tokenSlice(name_token), &flags);
    }

    return param_count >= 6 and flags.all_set();
}

const WalkPlumbingFlags = struct {
    has_tree: bool = false,
    has_source: bool = false,
    has_node: bool = false,
    has_file_path: bool = false,
    has_result: bool = false,
    has_visited: bool = false,

    fn all_set(self: *const WalkPlumbingFlags) bool {
        return self.has_tree and
            self.has_source and
            self.has_node and
            self.has_file_path and
            self.has_result and
            self.has_visited;
    }
};

const WalkPlumbingParam = enum {
    tree,
    source,
    node,
    file_path,
    result,
    visited,
};

fn set_walk_plumbing_flag(param_name: []const u8, flags: *WalkPlumbingFlags) void {
    assert(param_name.len > 0);
    assert(param_name.len <= 32);
    if (param_name.len == 0) return;
    if (param_name.len > 32) return;
    if (std.meta.stringToEnum(WalkPlumbingParam, param_name)) |param| {
        switch (param) {
            .tree => flags.has_tree = true,
            .source => flags.has_source = true,
            .node => flags.has_node = true,
            .file_path => flags.has_file_path = true,
            .result => flags.has_result = true,
            .visited => flags.has_visited = true,
        }
    }
}

fn count_substring_in_function_body(
    tree: *const std.zig.Ast,
    source: []const u8,
    body_node: std.zig.Ast.Node.Index,
    needle: []const u8,
) u32 {
    assert(std.mem.indexOfScalar(u8, source, 0) == null);
    assert(needle.len > 0);
    assert(body_node == .root or @intFromEnum(body_node) < tree.nodes.len);
    if (body_node == .root or @intFromEnum(body_node) >= tree.nodes.len) {
        return 0;
    }

    const first_token = tree.firstToken(body_node);
    const last_token = tree.lastToken(body_node);
    if (first_token >= tree.tokens.len or last_token >= tree.tokens.len) {
        return 0;
    }

    const start = tree.tokens.items(.start)[first_token];
    const end = tree.tokens.items(.start)[last_token] + tree.tokenSlice(last_token).len;
    if (start >= source.len) return 0;
    if (end > source.len) return 0;
    if (start >= end) return 0;

    const count = std.mem.count(u8, source[start..end], needle);
    if (count > std.math.maxInt(u32)) {
        return std.math.maxInt(u32);
    }
    return @intCast(count);
}

fn append_metric_quality_diagnostics(
    allocator: std.mem.Allocator,
    max_function_lines: u32,
    file_metrics: *const metrics.FileMetrics,
    result: *Result,
) !void {
    assert(max_function_lines > 0);
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    for (file_metrics.functions.items) |m| {
        if (m.logical_line_count > max_function_lines) {
            const msg = try std.fmt.allocPrint(
                allocator,
                "Function exceeds Tiger Style size limit in `{s}` ({d} > {d} lines).",
                .{ m.function_name, m.logical_line_count, max_function_lines },
            );
            try append_diag_pair(
                result,
                .warning,
                .N04_FUNCTION_SIZE,
                .TS09_FUNCTION_SHAPE,
                m.file_path,
                msg,
            );
        }
        if (m.cyclomatic_complexity > 10) {
            const msg = try std.fmt.allocPrint(
                allocator,
                "Cyclomatic complexity too high in `{s}` (complexity={d}); split control-plane " ++
                    "branching from data-plane execution.",
                .{ m.function_name, m.cyclomatic_complexity },
            );
            try append_diag(result, .warning, .TS12_PLANE_BOUNDARY, m.file_path, msg);
        }
        if (m.comptime_max_nesting > 3) {
            const msg = try std.fmt.allocPrint(
                allocator,
                "Comptime complexity too high in `{s}` (max nesting={d}). " ++
                    "Refactor metaprogramming logic.",
                .{ m.function_name, m.comptime_max_nesting },
            );
            try append_diag(
                result,
                .warning,
                .N08_PREPROCESSOR_OR_COMPTIME_BUDGET,
                m.file_path,
                msg,
            );
        }
        if (m.total_node_count > 0 and (m.comptime_node_count * 100) > (m.total_node_count * 20)) {
            const msg = try std.fmt.allocPrint(
                allocator,
                "Comptime node budget exceeded in `{s}` (comptime={d}, total={d}). " ++
                    "Reduce metaprogramming surface.",
                .{ m.function_name, m.comptime_node_count, m.total_node_count },
            );
            try append_diag(
                result,
                .warning,
                .N08_PREPROCESSOR_OR_COMPTIME_BUDGET,
                m.file_path,
                msg,
            );
        }
    }
}

fn append_assert_quality_diagnostics(
    allocator: std.mem.Allocator,
    file_metrics: *const metrics.FileMetrics,
    file_asserts: *const asserts.FileAssertFacts,
    result: *Result,
) !void {
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    assert(file_asserts.functions.items.len <= file_asserts.functions.capacity);
    for (file_asserts.functions.items) |a| {
        const metric = find_metric(file_metrics, a.canonical_name) orelse continue;
        if (metric.statement_count > 10 and a.assert_count == 0) {
            const msg = try std.fmt.allocPrint(
                allocator,
                "N05_ASSERTION_DENSITY: Unsafe complexity (0 assertions) in `{s}`.",
                .{a.function_name},
            );
            try append_diag(result, .warning, .N05_ASSERTION_DENSITY, a.file_path, msg);
        }
        if (metric.cyclomatic_complexity > 5 and a.assert_count < 2) {
            const msg = try std.fmt.allocPrint(
                allocator,
                "High complexity requires stronger invariants in `{s}` " ++
                    "(complexity={d}, asserts={d}).",
                .{ a.function_name, metric.cyclomatic_complexity, a.assert_count },
            );
            try append_diag(result, .warning, .N05_ASSERTION_DENSITY, a.file_path, msg);
        }
        if (a.has_relevant_params and !has_complete_param_assert_coverage(a)) {
            const msg = try std.fmt.allocPrint(
                allocator,
                "TS06_POS_NEG_ASSERT: function `{s}` needs both positive " ++
                    "assertions and negative-space guards for inputs",
                .{a.function_name},
            );
            try append_diag(result, .warning, .TS06_POS_NEG_ASSERT, a.file_path, msg);
        }
        if (a.has_unpaired_path_assert) {
            const msg = try std.fmt.allocPrint(
                allocator,
                "TS05_PAIR_ASSERT: function `{s}` has independent param paths " ++
                    "with unpaired assertions",
                .{a.function_name},
            );
            try append_diag(result, .warning, .TS05_PAIR_ASSERT, a.file_path, msg);
        }
        if (a.has_split_assert) {
            try append_diag(
                result,
                .critical,
                .TS13_BOOLEAN_SPLIT,
                a.file_path,
                "Ambiguous assertion. Split `assert(A and B)` into " ++
                    "`assert(A); assert(B);`.",
            );
        }
        if (!a.has_param_precondition) {
            try append_missing_param_precondition_diagnostics(allocator, a, result);
        }
        if (a.has_negative_invariant) {
            try append_diag(
                result,
                .warning,
                .TS14_POSITIVE_INVARIANTS,
                a.file_path,
                "TS14_POSITIVE_INVARIANTS: Prefer positive invariant forms. " ++
                    "Use ordered boundary checks instead of negated comparisons " ++
                    "(except null checks).",
            );
        }
    }
}

fn has_complete_param_assert_coverage(facts: asserts.FunctionAssertFacts) bool {
    if (!facts.has_positive_param_assert) return false;
    return facts.has_negative_param_guard;
}

fn append_missing_param_precondition_diagnostics(
    allocator: std.mem.Allocator,
    facts: asserts.FunctionAssertFacts,
    result: *Result,
) !void {
    const n07_msg = try std.fmt.allocPrint(
        allocator,
        "N07_RETURN_AND_PARAM_CHECKS: missing parameter precondition coverage in `{s}`",
        .{facts.function_name},
    );
    try append_diag(
        result,
        .warning,
        .N07_RETURN_AND_PARAM_CHECKS,
        facts.file_path,
        n07_msg,
    );
    const msg = try std.fmt.allocPrint(
        allocator,
        "Missing pre-condition check for arguments in `{s}`.",
        .{facts.function_name},
    );
    try append_diag(result, .warning, .TS04_ASSERTIONS, facts.file_path, msg);
}

fn find_metric(
    file_metrics: *const metrics.FileMetrics,
    canonical_name: []const u8,
) ?metrics.FunctionMetric {
    assert(canonical_name.len > 0);
    assert(std.mem.indexOf(u8, canonical_name, "::") != null);
    if (canonical_name.len == 0) return null;
    if (std.mem.indexOf(u8, canonical_name, "::") == null) return null;
    for (file_metrics.functions.items) |m| {
        if (std.mem.eql(u8, m.canonical_name, canonical_name)) {
            return m;
        }
    }
    return null;
}

fn detect_error_handling_violations(
    allocator: std.mem.Allocator,
    call_graph: *const graph.CallGraph,
    result: *Result,
) !void {
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    for (call_graph.files.items) |file_path| {
        const source = try std.Io.Dir.cwd().readFileAllocOptions(
            std.Options.debug_io,
            file_path,
            allocator,
            std.Io.Limit.limited(16 * 1024 * 1024),
            .of(u8),
            0,
        );
        defer allocator.free(source);

        const tree = try std.zig.Ast.parse(allocator, source, .zig);
        defer {
            var t = tree;
            t.deinit(allocator);
        }

        for (tree.rootDecls()) |decl| {
            if (tree.nodes.items(.tag)[@intFromEnum(decl)] != .fn_decl) continue;
            const body_node = tree.nodeData(decl).node_and_node[1];
            if (body_node == .root or @intFromEnum(body_node) >= tree.nodes.len) continue;
            try detect_error_handling_in_function(&tree, body_node, file_path, result);
        }
    }
}

fn detect_error_handling_in_function(
    tree: *const std.zig.Ast,
    body_node: std.zig.Ast.Node.Index,
    file_path: []const u8,
    result: *Result,
) !void {
    assert(file_path.len > 0);
    assert(body_node == .root or @intFromEnum(body_node) < tree.nodes.len);
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    if (file_path.len == 0) return;
    if (body_node == .root or @intFromEnum(body_node) >= tree.nodes.len) return;

    var ctx = ErrorDisciplineVisitCtx{
        .file_path = file_path,
        .result = result,
    };
    try ast_walk.walk(tree, body_node, &ctx, error_discipline_visit_node);
}

const ErrorDisciplineVisitCtx = struct {
    file_path: []const u8,
    result: *Result,
};

fn error_discipline_visit_node(
    tree: *const std.zig.Ast,
    node: std.zig.Ast.Node.Index,
    ctx_opaque: *anyopaque,
) anyerror!void {
    const ctx: *ErrorDisciplineVisitCtx = @ptrCast(@alignCast(ctx_opaque));
    try detect_error_violation_here(tree, node, ctx.file_path, ctx.result);
}

fn detect_error_violation_here(
    tree: *const std.zig.Ast,
    node: std.zig.Ast.Node.Index,
    file_path: []const u8,
    result: *Result,
) !void {
    assert(file_path.len > 0);
    assert(node == .root or @intFromEnum(node) < tree.nodes.len);
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    if (file_path.len == 0) return;
    if (node == .root or @intFromEnum(node) >= tree.nodes.len) return;
    const tag = tree.nodes.items(.tag)[@intFromEnum(node)];
    switch (tag) {
        .assign => {
            const lhs, const rhs = tree.nodeData(node).node_and_node;
            if (is_discard_identifier(tree, lhs) and is_discarded_fallible_expr(tree, rhs)) {
                try append_diag(
                    result,
                    .warning,
                    .N07_RETURN_AND_PARAM_CHECKS,
                    file_path,
                    "Explicit discard `_ = ...` is discouraged for function calls. " ++
                        "Handle the result or cast to `void` explicitly if safe.",
                );
                try append_diag(
                    result,
                    .warning,
                    .TS15_ERROR_HANDLING,
                    file_path,
                    "TS15_ERROR_HANDLING: discarded fallible result; " ++
                        "handle or propagate explicitly",
                );
            }
        },
        .@"catch" => {
            if (catch_has_silent_suppression(tree, node)) {
                try append_diag(
                    result,
                    .critical,
                    .N07_RETURN_AND_PARAM_CHECKS,
                    file_path,
                    "Silent error suppression is forbidden. Log or handle the error.",
                );
                try append_diag(
                    result,
                    .critical,
                    .TS15_ERROR_HANDLING,
                    file_path,
                    "TS15_ERROR_HANDLING: silent catch suppression is forbidden",
                );
            }
        },
        else => {},
    }
}

fn is_discard_identifier(tree: *const std.zig.Ast, node: std.zig.Ast.Node.Index) bool {
    if (node == .root or @intFromEnum(node) >= tree.nodes.len) return false;
    if (tree.nodes.items(.tag)[@intFromEnum(node)] != .identifier) return false;
    const tok = tree.nodes.items(.main_token)[@intFromEnum(node)];
    return std.mem.eql(u8, tree.tokenSlice(tok), "_");
}

fn is_discarded_fallible_expr(tree: *const std.zig.Ast, node: std.zig.Ast.Node.Index) bool {
    if (node == .root or @intFromEnum(node) >= tree.nodes.len) return false;
    return switch (tree.nodes.items(.tag)[@intFromEnum(node)]) {
        .call,
        .call_comma,
        .call_one,
        .call_one_comma,
        .@"try",
        .@"catch",
        => true,
        else => false,
    };
}

fn catch_has_silent_suppression(tree: *const std.zig.Ast, catch_node: std.zig.Ast.Node.Index) bool {
    assert(tree.nodes.len > 0);
    assert(catch_node == .root or @intFromEnum(catch_node) < tree.nodes.len);
    if (catch_node == .root or @intFromEnum(catch_node) >= tree.nodes.len) return false;
    if (tree.nodes.items(.tag)[@intFromEnum(catch_node)] != .@"catch") return false;

    const handler_node = tree.nodeData(catch_node).node_and_node[1];
    if (is_empty_block_expr(tree, handler_node)) {
        return true;
    }

    const catch_tok = tree.nodes.items(.main_token)[@intFromEnum(catch_node)];
    if (catch_tok + 2 >= tree.tokens.len) return false;
    if (tree.tokens.items(.tag)[catch_tok + 1] != .pipe) return false;
    if (tree.tokens.items(.tag)[catch_tok + 2] != .identifier) return false;
    if (std.mem.eql(u8, tree.tokenSlice(catch_tok + 2), "_")) return true;

    return false;
}

fn is_empty_block_expr(tree: *const std.zig.Ast, node: std.zig.Ast.Node.Index) bool {
    if (node == .root or @intFromEnum(node) >= tree.nodes.len) return false;
    const tag = tree.nodes.items(.tag)[@intFromEnum(node)];
    return switch (tag) {
        .block,
        .block_semicolon,
        => tree.extraDataSlice(tree.nodeData(node).extra_range, std.zig.Ast.Node.Index).len == 0,
        .block_two,
        .block_two_semicolon,
        => blk: {
            const first, const second = tree.nodeData(node).opt_node_and_opt_node;
            break :blk first == .none and second == .none;
        },
        else => false,
    };
}

fn detect_global_state_and_pointer_violations(
    allocator: std.mem.Allocator,
    call_graph: *const graph.CallGraph,
    result: *Result,
) !void {
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    assert(call_graph.files.items.len <= call_graph.files.capacity);
    for (call_graph.files.items) |file_path| {
        const source = try std.Io.Dir.cwd().readFileAllocOptions(
            std.Options.debug_io,
            file_path,
            allocator,
            std.Io.Limit.limited(16 * 1024 * 1024),
            .of(u8),
            0,
        );
        defer allocator.free(source);

        const tree = try std.zig.Ast.parse(allocator, source, .zig);
        defer {
            var t = tree;
            t.deinit(allocator);
        }

        try detect_global_state_and_pointer_violations_with_parsed(
            allocator,
            &tree,
            source,
            file_path,
            result,
        );
    }
}

fn detect_global_state_and_pointer_violations_with_parsed(
    allocator: std.mem.Allocator,
    tree: *const std.zig.Ast,
    source: []const u8,
    file_path: []const u8,
    result: *Result,
) !void {
    assert(source.len > 0);
    assert(file_path.len > 0);
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    if (source.len == 0) return;
    if (file_path.len == 0) return;

    var large_arg_symbols = try build_large_arg_symbol_index(allocator, tree);
    defer large_arg_symbols.deinit();

    for (tree.rootDecls()) |decl| {
        const tag = tree.nodes.items(.tag)[@intFromEnum(decl)];
        switch (tag) {
            .fn_decl => {
                try analyze_root_fn_decl(
                    allocator,
                    tree,
                    source,
                    file_path,
                    decl,
                    &large_arg_symbols,
                    result,
                );
            },
            .global_var_decl,
            .local_var_decl,
            .simple_var_decl,
            .aligned_var_decl,
            => {
                try analyze_root_var_decl(allocator, tree, file_path, decl, result);
            },
            else => {},
        }
    }
}

fn analyze_root_fn_decl(
    allocator: std.mem.Allocator,
    tree: *const std.zig.Ast,
    source: []const u8,
    file_path: []const u8,
    decl: std.zig.Ast.Node.Index,
    large_arg_symbols: *LargeArgSymbolIndex,
    result: *Result,
) !void {
    assert(source.len > 0);
    assert(file_path.len > 0);
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    assert(decl == .root or @intFromEnum(decl) < tree.nodes.len);
    if (source.len == 0) return;
    if (file_path.len == 0) return;
    if (decl == .root or @intFromEnum(decl) >= tree.nodes.len) return;
    var fn_buf: [1]std.zig.Ast.Node.Index = undefined;
    const proto = tree.fullFnProto(&fn_buf, decl) orelse return;
    const fn_name_tok = proto.name_token orelse return;
    const fn_name = tree.tokenSlice(fn_name_tok);

    const alias_overlap_risk = try analyze_fn_params_for_pointer_rules(
        allocator,
        tree,
        file_path,
        fn_name,
        proto,
        large_arg_symbols,
        result,
    );
    try analyze_fn_return_type_for_fixed_width(allocator, tree, file_path, fn_name, proto, result);
    try analyze_fn_return_type_for_in_place_init(
        allocator,
        tree,
        file_path,
        fn_name,
        proto,
        large_arg_symbols,
        result,
    );
    if (alias_overlap_risk) {
        const msg = try std.fmt.allocPrint(
            allocator,
            "Potential Aliasing in `{s}`. Ensure pointer params do not overlap.",
            .{fn_name},
        );
        try append_diag(result, .warning, .TB01_ALIASING, file_path, msg);
    }

    const body_node = tree.nodeData(decl).node_and_node[1];
    if (body_node == .root) return;

    try analyze_function_declaration_locality(
        allocator,
        tree,
        file_path,
        fn_name,
        body_node,
        result,
    );

    try detect_error_handling_in_function(tree, body_node, file_path, result);
    try detect_local_pointer_depth(tree, body_node, file_path, result);

    try detect_implicit_alloc_and_switch_else(
        allocator,
        tree,
        source,
        body_node,
        file_path,
        result,
    );
}

fn analyze_fn_params_for_pointer_rules(
    allocator: std.mem.Allocator,
    tree: *const std.zig.Ast,
    file_path: []const u8,
    fn_name: []const u8,
    proto: std.zig.Ast.full.FnProto,
    large_arg_symbols: *LargeArgSymbolIndex,
    result: *Result,
) !bool {
    assert(file_path.len > 0);
    assert(fn_name.len > 0);
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    if (file_path.len == 0) return false;
    if (fn_name.len == 0) return false;
    var alias_keys: [16][]const u8 = undefined;
    var alias_key_len: u32 = 0;
    var alias_overlap_risk = false;

    var it = proto.iterate(tree);
    while (it.next()) |param| {
        const type_expr = param.type_expr orelse continue;
        var param_name: ?[]const u8 = null;
        if (param.name_token) |name_token| {
            param_name = tree.tokenSlice(name_token);
        }
        try analyze_pointer_depth_param(tree, type_expr, file_path, result);
        try analyze_function_pointer_param(
            allocator,
            tree,
            type_expr,
            file_path,
            fn_name,
            param_name,
            result,
        );
        update_alias_overlap(tree, type_expr, &alias_keys, &alias_key_len, &alias_overlap_risk);
        try analyze_fixed_width_param(allocator, tree, type_expr, file_path, fn_name, result);
        try analyze_large_arg_pointer_param(
            allocator,
            tree,
            type_expr,
            file_path,
            fn_name,
            param_name,
            large_arg_symbols,
            result,
        );
    }

    return alias_overlap_risk;
}

fn analyze_large_arg_pointer_param(
    allocator: std.mem.Allocator,
    tree: *const std.zig.Ast,
    type_expr: std.zig.Ast.Node.Index,
    file_path: []const u8,
    fn_name: []const u8,
    param_name: ?[]const u8,
    large_arg_symbols: *LargeArgSymbolIndex,
    result: *Result,
) !void {
    assert(file_path.len > 0);
    assert(fn_name.len > 0);
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    if (file_path.len == 0) return;
    if (fn_name.len == 0) return;
    if (pointer_depth(tree, type_expr) > 0) return;

    if (estimated_value_size_bytes(tree, type_expr, large_arg_symbols)) |size_bytes| {
        if (size_bytes < large_arg_value_threshold_bytes) return;
        var msg: []const u8 = undefined;
        if (param_name) |name| {
            msg = try std.fmt.allocPrint(
                allocator,
                "TS23_LARGE_ARG_POINTER: parameter `{s}` in `{s}` passes ~{d} bytes by " ++
                    "value; prefer pointer/slice",
                .{ name, fn_name, size_bytes },
            );
        } else {
            msg = try std.fmt.allocPrint(
                allocator,
                "TS23_LARGE_ARG_POINTER: function `{s}` passes ~{d} bytes by value; " ++
                    "prefer pointer/slice",
                .{ fn_name, size_bytes },
            );
        }
        try append_diag(result, .warning, .TS23_LARGE_ARG_POINTER, file_path, msg);
        return;
    }

    const array_len = fixed_array_length_value(tree, type_expr, large_arg_symbols) orelse return;
    if (array_len < large_arg_array_threshold) return;

    var msg: []const u8 = undefined;
    if (param_name) |name| {
        msg = try std.fmt.allocPrint(
            allocator,
            "TS23_LARGE_ARG_POINTER: parameter `{s}` in `{s}` passes [{d}] by value; " ++
                "prefer pointer/slice",
            .{ name, fn_name, array_len },
        );
    } else {
        msg = try std.fmt.allocPrint(
            allocator,
            "TS23_LARGE_ARG_POINTER: function `{s}` passes [{d}] by value; " ++
                "prefer pointer/slice",
            .{ fn_name, array_len },
        );
    }
    try append_diag(result, .warning, .TS23_LARGE_ARG_POINTER, file_path, msg);
}

fn build_large_arg_symbol_index(
    allocator: std.mem.Allocator,
    tree: *const std.zig.Ast,
) !LargeArgSymbolIndex {
    assert(tree.nodes.len > 0);
    assert(tree.nodes.items(.main_token).len == tree.nodes.len);
    var symbols = LargeArgSymbolIndex.init(allocator);
    errdefer symbols.deinit();

    for (tree.rootDecls()) |decl| {
        const var_decl = tree.fullVarDecl(decl) orelse continue;
        if (tree.tokens.items(.tag)[var_decl.ast.mut_token] != .keyword_const) {
            continue;
        }

        const init_node = var_decl.ast.init_node.unwrap() orelse continue;
        const name = tree.tokenSlice(var_decl.ast.mut_token + 1);
        try symbols.const_expr_nodes.put(name, init_node);

        var container_buf: [2]std.zig.Ast.Node.Index = undefined;
        if (tree.fullContainerDecl(&container_buf, init_node) != null) {
            try symbols.type_decl_nodes.put(name, init_node);
        }
    }

    return symbols;
}

fn fixed_array_length_value(
    tree: *const std.zig.Ast,
    type_node: std.zig.Ast.Node.Index,
    symbols: *LargeArgSymbolIndex,
) ?u64 {
    assert(tree.nodes.len > 0);

    const unwrapped_type = unwrap_optional_grouped_type(tree, type_node) orelse return null;
    const array_type = tree.fullArrayType(unwrapped_type) orelse return null;

    var const_state = ConstVisitState{};
    return eval_const_u64_expr(
        tree,
        array_type.ast.elem_count,
        symbols,
        &const_state,
    );
}

fn estimated_value_size_bytes(
    tree: *const std.zig.Ast,
    type_node: std.zig.Ast.Node.Index,
    symbols: *LargeArgSymbolIndex,
) ?u64 {
    var const_state = ConstVisitState{};
    var type_state = TypeVisitState{};
    return estimate_type_size_bytes(
        tree,
        type_node,
        symbols,
        &const_state,
        &type_state,
    );
}

fn estimate_type_size_bytes(
    tree: *const std.zig.Ast,
    type_node: std.zig.Ast.Node.Index,
    symbols: *LargeArgSymbolIndex,
    const_state: *ConstVisitState,
    type_state: *TypeVisitState,
) ?u64 {
    assert(tree.nodes.len > 0);
    assert(type_state.len <= type_state.names.len);

    const unwrapped_type = unwrap_optional_grouped_type(tree, type_node) orelse return null;

    if (tree.fullPtrType(unwrapped_type)) |ptr_type| {
        if (ptr_type.size == .slice) {
            return slice_size_bytes;
        }
        return pointer_size_bytes;
    }

    if (tree.fullArrayType(unwrapped_type)) |array_type| {
        const len = eval_const_u64_expr(
            tree,
            array_type.ast.elem_count,
            symbols,
            const_state,
        ) orelse return null;
        const elem_size = estimate_type_size_bytes(
            tree,
            array_type.ast.elem_type,
            symbols,
            const_state,
            type_state,
        ) orelse return null;
        return std.math.mul(u64, len, elem_size) catch null;
    }

    const tag = tree.nodes.items(.tag)[@intFromEnum(unwrapped_type)];
    if (tag == .identifier) {
        const type_token = tree.nodes.items(.main_token)[@intFromEnum(unwrapped_type)];
        const type_name = tree.tokenSlice(type_token);
        if (primitive_type_size_bytes(type_name)) |size| {
            return size;
        }
        return estimate_named_type_size_bytes(
            tree,
            type_name,
            symbols,
            const_state,
            type_state,
        );
    }

    var container_buf: [2]std.zig.Ast.Node.Index = undefined;
    if (tree.fullContainerDecl(&container_buf, unwrapped_type) != null) {
        return estimate_container_decl_size_bytes(
            tree,
            unwrapped_type,
            symbols,
            const_state,
            type_state,
        );
    }

    return null;
}

fn estimate_named_type_size_bytes(
    tree: *const std.zig.Ast,
    type_name: []const u8,
    symbols: *LargeArgSymbolIndex,
    const_state: *ConstVisitState,
    type_state: *TypeVisitState,
) ?u64 {
    assert(type_name.len > 0);
    if (type_name.len == 0) return null;

    const decl_node = symbols.type_decl_nodes.get(type_name) orelse return null;
    if (!push_type_visiting_name(type_state, type_name)) return null;
    defer pop_type_visiting_name(type_state);

    return estimate_container_decl_size_bytes(
        tree,
        decl_node,
        symbols,
        const_state,
        type_state,
    );
}

fn estimate_container_decl_size_bytes(
    tree: *const std.zig.Ast,
    container_node: std.zig.Ast.Node.Index,
    symbols: *LargeArgSymbolIndex,
    const_state: *ConstVisitState,
    type_state: *TypeVisitState,
) ?u64 {
    assert(type_state.len <= type_state.names.len);
    assert(container_node == .root or @intFromEnum(container_node) < tree.nodes.len);
    assert(tree.nodes.items(.main_token).len == tree.nodes.len);
    if (container_node == .root or @intFromEnum(container_node) >= tree.nodes.len) return null;

    var container_buf: [2]std.zig.Ast.Node.Index = undefined;
    const container = tree.fullContainerDecl(&container_buf, container_node) orelse return null;
    const size_kind = container_size_kind(tree, container.ast.main_token) orelse return null;
    return estimate_container_members_size(
        tree,
        container.ast.members,
        size_kind,
        symbols,
        const_state,
        type_state,
    );
}

const ContainerSizeKind = enum {
    union_kind,
    aggregate_kind,
};

fn container_size_kind(
    tree: *const std.zig.Ast,
    main_token: std.zig.Ast.TokenIndex,
) ?ContainerSizeKind {
    if (main_token >= tree.tokens.len) return null;
    const container_token = tree.tokens.items(.tag)[main_token];
    if (container_token == .keyword_enum) return null;
    if (container_token == .keyword_union) return .union_kind;
    return .aggregate_kind;
}

fn estimate_container_members_size(
    tree: *const std.zig.Ast,
    members: []const std.zig.Ast.Node.Index,
    size_kind: ContainerSizeKind,
    symbols: *LargeArgSymbolIndex,
    const_state: *ConstVisitState,
    type_state: *TypeVisitState,
) ?u64 {
    assert(members.len <= tree.nodes.len);
    assert(const_state.len <= const_state.names.len);
    assert(type_state.len <= type_state.names.len);
    if (members.len > tree.nodes.len) return null;
    if (const_state.len > const_state.names.len) return null;
    if (type_state.len > type_state.names.len) return null;
    var total_size: u64 = 0;
    var max_field_size: u64 = 0;
    for (members) |member| {
        const field = tree.fullContainerField(member) orelse continue;
        const field_type = field.ast.type_expr.unwrap() orelse return null;
        const field_size = estimate_type_size_bytes(
            tree,
            field_type,
            symbols,
            const_state,
            type_state,
        ) orelse return null;
        if (size_kind == .union_kind) {
            max_field_size = @max(max_field_size, field_size);
        } else {
            total_size = std.math.add(u64, total_size, field_size) catch return null;
        }
    }

    return switch (size_kind) {
        .union_kind => max_field_size,
        .aggregate_kind => total_size,
    };
}

fn primitive_type_size_bytes(type_name: []const u8) ?u64 {
    assert(type_name.len > 0);
    assert(type_name.len <= std.math.maxInt(u32));
    if (type_name.len == 0) return null;
    if (type_name.len > std.math.maxInt(u32)) return null;
    if (primitive_type_is_one_byte(type_name)) return 1;
    if (primitive_type_is_two_bytes(type_name)) return 2;
    if (primitive_type_is_four_bytes(type_name)) return 4;
    if (primitive_type_is_eight_bytes(type_name)) return 8;
    if (primitive_type_is_sixteen_bytes(type_name)) return 16;
    return null;
}

fn primitive_type_is_one_byte(type_name: []const u8) bool {
    assert(type_name.len > 0);
    if (type_name.len == 0) return false;
    if (std.mem.eql(u8, type_name, "bool")) return true;
    if (std.mem.eql(u8, type_name, "u8")) return true;
    return std.mem.eql(u8, type_name, "i8");
}

fn primitive_type_is_two_bytes(type_name: []const u8) bool {
    assert(type_name.len > 0);
    if (type_name.len == 0) return false;
    if (std.mem.eql(u8, type_name, "u16")) return true;
    if (std.mem.eql(u8, type_name, "i16")) return true;
    return std.mem.eql(u8, type_name, "f16");
}

fn primitive_type_is_four_bytes(type_name: []const u8) bool {
    assert(type_name.len > 0);
    if (type_name.len == 0) return false;
    if (std.mem.eql(u8, type_name, "u32")) return true;
    if (std.mem.eql(u8, type_name, "i32")) return true;
    return std.mem.eql(u8, type_name, "f32");
}

fn primitive_type_is_eight_bytes(type_name: []const u8) bool {
    assert(type_name.len > 0);
    assert(type_name.len <= std.math.maxInt(u32));
    if (type_name.len == 0) return false;
    if (type_name.len > std.math.maxInt(u32)) return false;
    if (std.mem.eql(u8, type_name, "u64")) return true;
    if (std.mem.eql(u8, type_name, "i64")) return true;
    if (std.mem.eql(u8, type_name, "f64")) return true;
    if (std.mem.eql(u8, type_name, "usize")) return true;
    return std.mem.eql(u8, type_name, "isize");
}

fn primitive_type_is_sixteen_bytes(type_name: []const u8) bool {
    assert(type_name.len > 0);
    if (type_name.len == 0) return false;
    if (std.mem.eql(u8, type_name, "u128")) return true;
    if (std.mem.eql(u8, type_name, "i128")) return true;
    return std.mem.eql(u8, type_name, "f128");
}

fn eval_const_u64_expr(
    tree: *const std.zig.Ast,
    node: std.zig.Ast.Node.Index,
    symbols: *LargeArgSymbolIndex,
    const_state: *ConstVisitState,
) ?u64 {
    assert(tree.nodes.items(.main_token).len == tree.nodes.len);
    assert(const_state.len <= const_state.names.len);
    if (node == .root or @intFromEnum(node) >= tree.nodes.len) return null;

    const tag = tree.nodes.items(.tag)[@intFromEnum(node)];
    switch (tag) {
        .number_literal => {
            const token = tree.nodes.items(.main_token)[@intFromEnum(node)];
            return parse_unsigned_integer_literal(tree.tokenSlice(token));
        },
        .identifier => {
            const token = tree.nodes.items(.main_token)[@intFromEnum(node)];
            return resolve_const_identifier_value(
                tree,
                tree.tokenSlice(token),
                symbols,
                const_state,
            );
        },
        .grouped_expression => {
            const child = tree.nodeData(node).node_and_token[0];
            return eval_const_u64_expr(tree, child, symbols, const_state);
        },
        .@"comptime" => {
            const child = tree.nodeData(node).node;
            return eval_const_u64_expr(tree, child, symbols, const_state);
        },
        .add,
        .sub,
        .mul,
        .div,
        .mod,
        .shl,
        .shr,
        .add_wrap,
        .sub_wrap,
        .mul_wrap,
        .add_sat,
        .sub_sat,
        .mul_sat,
        .shl_sat,
        => {
            return eval_const_binary_expr(tree, node, tag, symbols, const_state);
        },
        .builtin_call,
        .builtin_call_comma,
        .builtin_call_two,
        .builtin_call_two_comma,
        => return eval_const_builtin_expr(tree, node, symbols, const_state),
        else => return null,
    }
}

fn eval_const_binary_expr(
    tree: *const std.zig.Ast,
    node: std.zig.Ast.Node.Index,
    tag: std.zig.Ast.Node.Tag,
    symbols: *LargeArgSymbolIndex,
    const_state: *ConstVisitState,
) ?u64 {
    const lhs_node, const rhs_node = tree.nodeData(node).node_and_node;
    const lhs = eval_const_u64_expr(tree, lhs_node, symbols, const_state) orelse
        return null;
    const rhs = eval_const_u64_expr(tree, rhs_node, symbols, const_state) orelse
        return null;

    return switch (tag) {
        .add, .add_wrap, .add_sat => std.math.add(u64, lhs, rhs) catch null,
        .sub, .sub_wrap, .sub_sat => std.math.sub(u64, lhs, rhs) catch null,
        .mul, .mul_wrap, .mul_sat => std.math.mul(u64, lhs, rhs) catch null,
        .div => eval_div_u64(lhs, rhs),
        .mod => eval_mod_u64(lhs, rhs),
        .shl, .shl_sat => eval_shift_left_u64(lhs, rhs),
        .shr => eval_shift_right_u64(lhs, rhs),
        else => null,
    };
}

fn eval_div_u64(lhs: u64, rhs: u64) ?u64 {
    if (rhs == 0) return null;
    return lhs / rhs;
}

fn eval_mod_u64(lhs: u64, rhs: u64) ?u64 {
    if (rhs == 0) return null;
    return lhs % rhs;
}

fn eval_shift_left_u64(lhs: u64, rhs: u64) ?u64 {
    if (rhs >= 64) return null;
    return lhs << @as(u6, @intCast(rhs));
}

fn eval_shift_right_u64(lhs: u64, rhs: u64) ?u64 {
    if (rhs >= 64) return null;
    return lhs >> @as(u6, @intCast(rhs));
}

fn eval_const_builtin_expr(
    tree: *const std.zig.Ast,
    node: std.zig.Ast.Node.Index,
    symbols: *LargeArgSymbolIndex,
    const_state: *ConstVisitState,
) ?u64 {
    assert(tree.nodes.items(.main_token).len == tree.nodes.len);
    assert(const_state.len <= const_state.names.len);
    const token = tree.nodes.items(.main_token)[@intFromEnum(node)];
    if (token >= tree.tokens.len) return null;
    const builtin_name = tree.tokenSlice(token);

    var arg_nodes: [2]std.zig.Ast.Node.Index = undefined;
    var arg_len: u8 = 0;
    if (!collect_builtin_arg_nodes(tree, node, &arg_nodes, &arg_len)) return null;

    if (std.mem.eql(u8, builtin_name, "@as")) {
        return eval_builtin_as(tree, symbols, const_state, &arg_nodes, arg_len);
    }
    if (std.mem.eql(u8, builtin_name, "@intCast")) {
        return eval_builtin_int_cast(tree, symbols, const_state, &arg_nodes, arg_len);
    }
    if (std.mem.eql(u8, builtin_name, "@max")) {
        return eval_builtin_extrema(tree, symbols, const_state, &arg_nodes, arg_len, true);
    }
    if (std.mem.eql(u8, builtin_name, "@min")) {
        return eval_builtin_extrema(tree, symbols, const_state, &arg_nodes, arg_len, false);
    }

    return null;
}

fn collect_builtin_arg_nodes(
    tree: *const std.zig.Ast,
    node: std.zig.Ast.Node.Index,
    arg_nodes: *[2]std.zig.Ast.Node.Index,
    arg_len: *u8,
) bool {
    assert(arg_len.* <= arg_nodes.len);
    assert(node == .root or @intFromEnum(node) < tree.nodes.len);
    switch (tree.nodes.items(.tag)[@intFromEnum(node)]) {
        .builtin_call,
        .builtin_call_comma,
        => {
            const args = tree.extraDataSlice(
                tree.nodeData(node).extra_range,
                std.zig.Ast.Node.Index,
            );
            if (args.len > arg_nodes.len) return false;
            for (args) |arg| {
                arg_nodes[@as(usize, arg_len.*)] = arg;
                arg_len.* += 1;
            }
            return true;
        },
        .builtin_call_two,
        .builtin_call_two_comma,
        => {
            const first, const second = tree.nodeData(node).opt_node_and_opt_node;
            if (first.unwrap()) |first_arg| {
                arg_nodes[@as(usize, arg_len.*)] = first_arg;
                arg_len.* += 1;
            }
            if (second.unwrap()) |second_arg| {
                arg_nodes[@as(usize, arg_len.*)] = second_arg;
                arg_len.* += 1;
            }
            return true;
        },
        else => return false,
    }
}

fn eval_builtin_as(
    tree: *const std.zig.Ast,
    symbols: *LargeArgSymbolIndex,
    const_state: *ConstVisitState,
    arg_nodes: *const [2]std.zig.Ast.Node.Index,
    arg_len: u8,
) ?u64 {
    if (arg_len != 2) return null;
    return eval_const_u64_expr(tree, arg_nodes[1], symbols, const_state);
}

fn eval_builtin_int_cast(
    tree: *const std.zig.Ast,
    symbols: *LargeArgSymbolIndex,
    const_state: *ConstVisitState,
    arg_nodes: *const [2]std.zig.Ast.Node.Index,
    arg_len: u8,
) ?u64 {
    if (arg_len == 0) return null;
    return eval_const_u64_expr(tree, arg_nodes[arg_len - 1], symbols, const_state);
}

fn eval_builtin_extrema(
    tree: *const std.zig.Ast,
    symbols: *LargeArgSymbolIndex,
    const_state: *ConstVisitState,
    arg_nodes: *const [2]std.zig.Ast.Node.Index,
    arg_len: u8,
    is_max: bool,
) ?u64 {
    assert(arg_len <= arg_nodes.len);
    assert(const_state.len <= const_state.names.len);
    if (arg_len > arg_nodes.len) return null;
    if (const_state.len > const_state.names.len) return null;
    if (arg_len != 2) return null;
    const lhs = eval_const_u64_expr(tree, arg_nodes[0], symbols, const_state) orelse return null;
    const rhs = eval_const_u64_expr(tree, arg_nodes[1], symbols, const_state) orelse return null;
    if (is_max) {
        return @max(lhs, rhs);
    }
    return @min(lhs, rhs);
}

fn resolve_const_identifier_value(
    tree: *const std.zig.Ast,
    name: []const u8,
    symbols: *LargeArgSymbolIndex,
    const_state: *ConstVisitState,
) ?u64 {
    assert(name.len > 0);
    assert(const_state.len <= const_state.names.len);
    if (name.len == 0) return null;
    if (const_state.len > const_state.names.len) return null;
    if (!push_const_visiting_name(const_state, name)) return null;
    defer pop_const_visiting_name(const_state);

    const expr_node = symbols.const_expr_nodes.get(name) orelse return null;
    return eval_const_u64_expr(tree, expr_node, symbols, const_state);
}

fn parse_unsigned_integer_literal(text_input: []const u8) ?u64 {
    assert(text_input.len > 0);
    assert(text_input.len <= 4096);
    if (text_input.len == 0) return null;
    const text = std.mem.trim(u8, text_input, " \t\r\n");
    if (text.len == 0) return null;

    var compact: [128]u8 = undefined;
    var compact_len: usize = 0;
    for (text) |c| {
        if (c == '_') continue;
        if (compact_len >= compact.len) return null;
        compact[compact_len] = c;
        compact_len += 1;
    }
    if (compact_len == 0) return null;

    var digits = compact[0..compact_len];
    const base_info = integer_literal_base_info(digits);
    const base = base_info.base;
    digits = digits[base_info.prefix_len..];
    if (digits.len == 0) return null;

    return std.fmt.parseInt(u64, digits, base) catch null;
}

const IntegerLiteralBaseInfo = struct {
    base: u8,
    prefix_len: usize,
};

fn integer_literal_base_info(digits: []const u8) IntegerLiteralBaseInfo {
    assert(digits.len > 0);
    if (digits.len == 0) {
        return .{ .base = 10, .prefix_len = 0 };
    }
    if (digits.len <= 2 or digits[0] != '0') {
        return .{ .base = 10, .prefix_len = 0 };
    }

    const prefix = std.ascii.toLower(digits[1]);
    return switch (prefix) {
        'x' => .{ .base = 16, .prefix_len = 2 },
        'o' => .{ .base = 8, .prefix_len = 2 },
        'b' => .{ .base = 2, .prefix_len = 2 },
        else => .{ .base = 10, .prefix_len = 0 },
    };
}

fn push_const_visiting_name(state: *ConstVisitState, name: []const u8) bool {
    assert(name.len > 0);
    assert(state.len <= state.names.len);
    if (name.len == 0) return false;
    if (state.len > state.names.len) return false;
    if (has_const_visiting_name(state, name)) return false;
    if (state.len >= state.names.len) return false;
    state.names[@as(usize, state.len)] = name;
    state.len += 1;
    return true;
}

fn pop_const_visiting_name(state: *ConstVisitState) void {
    if (state.len == 0) return;
    state.len -= 1;
}

fn has_const_visiting_name(state: *const ConstVisitState, name: []const u8) bool {
    assert(name.len > 0);
    if (name.len == 0) return false;
    for (state.names[0..@as(usize, state.len)]) |entry| {
        if (std.mem.eql(u8, entry, name)) {
            return true;
        }
    }
    return false;
}

fn push_type_visiting_name(state: *TypeVisitState, name: []const u8) bool {
    assert(name.len > 0);
    assert(state.len <= state.names.len);
    if (name.len == 0) return false;
    if (state.len > state.names.len) return false;
    if (has_type_visiting_name(state, name)) return false;
    if (state.len >= state.names.len) return false;
    state.names[@as(usize, state.len)] = name;
    state.len += 1;
    return true;
}

fn pop_type_visiting_name(state: *TypeVisitState) void {
    if (state.len == 0) return;
    state.len -= 1;
}

fn has_type_visiting_name(state: *const TypeVisitState, name: []const u8) bool {
    assert(name.len > 0);
    if (name.len == 0) return false;
    for (state.names[0..@as(usize, state.len)]) |entry| {
        if (std.mem.eql(u8, entry, name)) {
            return true;
        }
    }
    return false;
}

fn unwrap_optional_grouped_type(
    tree: *const std.zig.Ast,
    type_node: std.zig.Ast.Node.Index,
) ?std.zig.Ast.Node.Index {
    assert(tree.nodes.len > 0);
    if (type_node == .root or @intFromEnum(type_node) >= tree.nodes.len) return null;

    var current = type_node;
    while (current != .root and @intFromEnum(current) < tree.nodes.len) {
        const tag = tree.nodes.items(.tag)[@intFromEnum(current)];
        if (tag == .optional_type) {
            current = tree.nodeData(current).node;
            continue;
        }
        if (tag == .grouped_expression) {
            current = tree.nodeData(current).node_and_token[0];
            continue;
        }
        return current;
    }
    return null;
}

fn analyze_pointer_depth_param(
    tree: *const std.zig.Ast,
    type_expr: std.zig.Ast.Node.Index,
    file_path: []const u8,
    result: *Result,
) !void {
    assert(file_path.len > 0);
    assert(type_expr == .root or @intFromEnum(type_expr) < tree.nodes.len);
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    if (file_path.len == 0) return;
    if (type_expr == .root or @intFromEnum(type_expr) >= tree.nodes.len) return;
    const depth = pointer_depth(tree, type_expr);
    if (depth >= 2) {
        try append_diag(
            result,
            .critical,
            .N09_POINTER_DISCIPLINE,
            file_path,
            "multi-level pointer is forbidden (`**T` or deeper)",
        );
    }
}

fn analyze_function_pointer_param(
    allocator: std.mem.Allocator,
    tree: *const std.zig.Ast,
    type_expr: std.zig.Ast.Node.Index,
    file_path: []const u8,
    fn_name: []const u8,
    param_name: ?[]const u8,
    result: *Result,
) !void {
    assert(file_path.len > 0);
    assert(fn_name.len > 0);
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    if (file_path.len == 0) return;
    if (fn_name.len == 0) return;
    if (!is_function_pointer_type(tree, type_expr)) return;

    var msg: []const u8 = undefined;
    if (param_name) |name| {
        msg = try std.fmt.allocPrint(
            allocator,
            "N09_POINTER_DISCIPLINE: parameter `{s}` in `{s}` uses function pointer; " ++
                "prefer explicit enum/tag dispatch",
            .{ name, fn_name },
        );
    } else {
        msg = try std.fmt.allocPrint(
            allocator,
            "N09_POINTER_DISCIPLINE: function `{s}` uses function-pointer parameter; " ++
                "prefer explicit enum/tag dispatch",
            .{fn_name},
        );
    }
    try append_diag(result, .critical, .N09_POINTER_DISCIPLINE, file_path, msg);
}

fn is_function_pointer_type(tree: *const std.zig.Ast, type_node: std.zig.Ast.Node.Index) bool {
    assert(type_node == .root or @intFromEnum(type_node) < tree.nodes.len);
    assert(tree.nodes.items(.main_token).len == tree.nodes.len);
    if (type_node == .root or @intFromEnum(type_node) >= tree.nodes.len) return false;
    const tag = tree.nodes.items(.tag)[@intFromEnum(type_node)];

    if (tag == .optional_type) {
        return is_function_pointer_type(tree, tree.nodeData(type_node).node);
    }
    if (tag == .grouped_expression) {
        return is_function_pointer_type(tree, tree.nodeData(type_node).node_and_token[0]);
    }

    if (tree.fullPtrType(type_node)) |ptr| {
        if (is_function_type_node(tree, ptr.ast.child_type)) return true;
        return is_function_pointer_type(tree, ptr.ast.child_type);
    }

    return false;
}

fn is_function_type_node(tree: *const std.zig.Ast, node: std.zig.Ast.Node.Index) bool {
    if (node == .root or @intFromEnum(node) >= tree.nodes.len) return false;
    const tag = tree.nodes.items(.tag)[@intFromEnum(node)];
    return tag == .fn_proto or
        tag == .fn_proto_simple or
        tag == .fn_proto_multi or
        tag == .fn_proto_one;
}

fn update_alias_overlap(
    tree: *const std.zig.Ast,
    type_expr: std.zig.Ast.Node.Index,
    alias_keys: *[16][]const u8,
    alias_key_len: *u32,
    alias_overlap_risk: *bool,
) void {
    assert(type_expr == .root or @intFromEnum(type_expr) < tree.nodes.len);
    assert(@as(usize, alias_key_len.*) <= alias_keys.len);
    if (alias_risk_pointer_key(tree, type_expr)) |key| {
        var seen = false;
        for (alias_keys[0..@as(usize, alias_key_len.*)]) |existing_key| {
            if (std.mem.eql(u8, existing_key, key)) {
                alias_overlap_risk.* = true;
                seen = true;
                break;
            }
        }

        if (!seen and @as(usize, alias_key_len.*) < alias_keys.len) {
            alias_keys[@as(usize, alias_key_len.*)] = key;
            alias_key_len.* += 1;
        }
    }
}

fn analyze_fixed_width_param(
    allocator: std.mem.Allocator,
    tree: *const std.zig.Ast,
    type_expr: std.zig.Ast.Node.Index,
    file_path: []const u8,
    fn_name: []const u8,
    result: *Result,
) !void {
    assert(file_path.len > 0);
    assert(fn_name.len > 0);
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    if (file_path.len == 0) return;
    if (fn_name.len == 0) return;
    if (type_expr == .root or @intFromEnum(type_expr) >= tree.nodes.len) return;
    if (!is_arch_sized_type(tree, type_expr)) return;

    const msg = try std.fmt.allocPrint(
        allocator,
        "TS03_FIXED_WIDTH_TYPES: Parameter uses usize/isize in `{s}`. " ++
            "Use explicitly-sized types (u32, u64, etc.) for " ++
            "protocol/persistence boundaries.",
        .{fn_name},
    );
    try append_diag(result, .warning, .TS03_FIXED_WIDTH_TYPES, file_path, msg);
}

fn analyze_fn_return_type_for_fixed_width(
    allocator: std.mem.Allocator,
    tree: *const std.zig.Ast,
    file_path: []const u8,
    fn_name: []const u8,
    proto: std.zig.Ast.full.FnProto,
    result: *Result,
) !void {
    assert(file_path.len > 0);
    assert(fn_name.len > 0);
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    if (file_path.len == 0) return;
    if (fn_name.len == 0) return;
    const return_type = proto.ast.return_type.unwrap() orelse return;
    if (!is_arch_sized_type(tree, return_type)) return;

    const msg = try std.fmt.allocPrint(
        allocator,
        "TS03_FIXED_WIDTH_TYPES: Return type uses usize/isize in `{s}`. " ++
            "Use explicitly-sized types (u32, u64, etc.) for " ++
            "protocol/persistence boundaries.",
        .{fn_name},
    );
    try append_diag(result, .warning, .TS03_FIXED_WIDTH_TYPES, file_path, msg);
}

fn analyze_fn_return_type_for_in_place_init(
    allocator: std.mem.Allocator,
    tree: *const std.zig.Ast,
    file_path: []const u8,
    fn_name: []const u8,
    proto: std.zig.Ast.full.FnProto,
    large_arg_symbols: *LargeArgSymbolIndex,
    result: *Result,
) !void {
    assert(file_path.len > 0);
    assert(fn_name.len > 0);
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    if (file_path.len == 0) return;
    if (fn_name.len == 0) return;

    const return_type = proto.ast.return_type.unwrap() orelse return;
    if (!is_struct_return_type(tree, return_type, large_arg_symbols)) return;
    const size_bytes = estimated_value_size_bytes(
        tree,
        return_type,
        large_arg_symbols,
    ) orelse return;
    if (size_bytes < large_arg_value_threshold_bytes) return;

    const msg = try std.fmt.allocPrint(
        allocator,
        "TS24_IN_PLACE_INIT: function `{s}` returns ~{d} bytes by value; " ++
            "prefer `out: *T` in-place initialization",
        .{ fn_name, size_bytes },
    );
    try append_diag(result, .warning, .TS24_IN_PLACE_INIT, file_path, msg);
}

fn is_struct_return_type(
    tree: *const std.zig.Ast,
    type_node: std.zig.Ast.Node.Index,
    symbols: *const LargeArgSymbolIndex,
) bool {
    assert(tree.nodes.len > 0);
    const unwrapped_type = unwrap_optional_grouped_type(tree, type_node) orelse return false;

    var container_buf: [2]std.zig.Ast.Node.Index = undefined;
    if (tree.fullContainerDecl(&container_buf, unwrapped_type) != null) {
        return node_is_struct_container_decl(tree, unwrapped_type);
    }

    if (tree.nodes.items(.tag)[@intFromEnum(unwrapped_type)] != .identifier) return false;
    const type_token = tree.nodes.items(.main_token)[@intFromEnum(unwrapped_type)];
    const type_name = tree.tokenSlice(type_token);
    const decl_node = symbols.type_decl_nodes.get(type_name) orelse return false;
    return node_is_struct_container_decl(tree, decl_node);
}

fn node_is_struct_container_decl(
    tree: *const std.zig.Ast,
    node: std.zig.Ast.Node.Index,
) bool {
    var container_buf: [2]std.zig.Ast.Node.Index = undefined;
    const container = tree.fullContainerDecl(&container_buf, node) orelse return false;
    return tree.tokens.items(.tag)[container.ast.main_token] == .keyword_struct;
}

fn analyze_root_var_decl(
    allocator: std.mem.Allocator,
    tree: *const std.zig.Ast,
    file_path: []const u8,
    decl: std.zig.Ast.Node.Index,
    result: *Result,
) !void {
    assert(file_path.len > 0);
    assert(decl == .root or @intFromEnum(decl) < tree.nodes.len);
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    if (file_path.len == 0) return;
    if (decl == .root or @intFromEnum(decl) >= tree.nodes.len) return;
    const var_decl = tree.fullVarDecl(decl) orelse return;
    const mut_tag = tree.tokens.items(.tag)[var_decl.ast.mut_token];

    if (var_decl.ast.type_node.unwrap()) |type_node| {
        try analyze_root_function_pointer_var_decl(
            allocator,
            tree,
            file_path,
            var_decl,
            type_node,
            result,
        );
    }

    if (mut_tag == .keyword_var and var_decl.threadlocal_token == null) {
        try append_diag(
            result,
            .critical,
            .N06_SCOPE_MINIMIZATION,
            file_path,
            "mutable global state is forbidden (Rule 6)",
        );
        try append_diag(
            result,
            .warning,
            .TS08_SCOPE,
            file_path,
            "mutable global state widens scope; keep state local",
        );
    }

    if (mut_tag == .keyword_const and try const_global_is_risky(allocator, tree, var_decl)) {
        try append_diag(
            result,
            .warning,
            .N06_SCOPE_MINIMIZATION,
            file_path,
            "const global contains pointer/allocator; manual audit required",
        );
        try append_diag(
            result,
            .warning,
            .TS08_SCOPE,
            file_path,
            "prefer narrower declaration scope over global pointer state",
        );
    }
}

fn analyze_root_function_pointer_var_decl(
    allocator: std.mem.Allocator,
    tree: *const std.zig.Ast,
    file_path: []const u8,
    var_decl: std.zig.Ast.full.VarDecl,
    type_node: std.zig.Ast.Node.Index,
    result: *Result,
) !void {
    assert(file_path.len > 0);
    assert(type_node == .root or @intFromEnum(type_node) < tree.nodes.len);
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    if (file_path.len == 0) return;
    if (type_node == .root or @intFromEnum(type_node) >= tree.nodes.len) return;
    if (!is_function_pointer_type(tree, type_node)) return;

    const name_token = var_decl.ast.mut_token + 1;
    if (name_token >= tree.tokens.len or tree.tokens.items(.tag)[name_token] != .identifier) {
        return;
    }
    const var_name = tree.tokenSlice(name_token);
    const msg = try std.fmt.allocPrint(
        allocator,
        "N09_POINTER_DISCIPLINE: global `{s}` uses function pointer type; " ++
            "prefer explicit enum/tag dispatch",
        .{var_name},
    );
    try append_diag(result, .critical, .N09_POINTER_DISCIPLINE, file_path, msg);
}

fn analyze_function_declaration_locality(
    allocator: std.mem.Allocator,
    tree: *const std.zig.Ast,
    file_path: []const u8,
    fn_name: []const u8,
    body_node: std.zig.Ast.Node.Index,
    result: *Result,
) !void {
    assert(file_path.len > 0);
    assert(fn_name.len > 0);
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    if (file_path.len == 0) return;
    if (fn_name.len == 0) return;

    var statements = std.array_list.Managed(std.zig.Ast.Node.Index).init(allocator);
    defer statements.deinit();
    try collect_function_top_level_statements(tree, body_node, &statements);

    for (statements.items, 0..) |stmt, stmt_index| {
        if (stmt_index > std.math.maxInt(u32)) continue;
        const statement_index: u32 = @intCast(stmt_index);
        const candidate = locality_decl_candidate(tree, stmt, statement_index) orelse continue;
        try emit_locality_gap_diag(
            allocator,
            tree,
            statements.items,
            file_path,
            fn_name,
            candidate,
            result,
        );
    }
}

const LocalityDeclCandidate = struct {
    name: []const u8,
    declaration_index: u32,
    search_start_index: u32,
};

fn locality_decl_candidate(
    tree: *const std.zig.Ast,
    statement: std.zig.Ast.Node.Index,
    statement_index: u32,
) ?LocalityDeclCandidate {
    assert(statement == .root or @intFromEnum(statement) < tree.nodes.len);
    assert(statement_index <= std.math.maxInt(u32));
    if (statement == .root or @intFromEnum(statement) >= tree.nodes.len) return null;
    const tag = tree.nodes.items(.tag)[@intFromEnum(statement)];
    if (!is_local_var_decl_tag(tag)) return null;

    const var_decl = tree.fullVarDecl(statement) orelse return null;
    const name_token = var_decl.ast.mut_token + 1;
    if (name_token >= tree.tokens.len) return null;
    if (tree.tokens.items(.tag)[name_token] != .identifier) return null;

    const var_name = tree.tokenSlice(name_token);
    if (var_name.len == 0 or std.mem.eql(u8, var_name, "_")) return null;
    if (statement_index == std.math.maxInt(u32)) return null;

    return .{
        .name = var_name,
        .declaration_index = statement_index,
        .search_start_index = statement_index + 1,
    };
}

fn emit_locality_gap_diag(
    allocator: std.mem.Allocator,
    tree: *const std.zig.Ast,
    statements: []const std.zig.Ast.Node.Index,
    file_path: []const u8,
    fn_name: []const u8,
    candidate: LocalityDeclCandidate,
    result: *Result,
) !void {
    assert(file_path.len > 0);
    assert(fn_name.len > 0);
    assert(candidate.name.len > 0);
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    if (file_path.len == 0) return;
    if (fn_name.len == 0) return;
    if (candidate.name.len == 0) return;
    const first_use_index = first_statement_using_identifier(
        tree,
        statements,
        candidate.search_start_index,
        candidate.name,
    ) orelse return;

    const gap = @as(usize, first_use_index - candidate.declaration_index);
    if (gap < declaration_locality_gap_statements) return;

    const msg = try std.fmt.allocPrint(
        allocator,
        "`{s}` in `{s}` is declared {d} statements " ++
            "before first use; narrow declaration scope",
        .{ candidate.name, fn_name, gap },
    );
    try append_diag_pair(
        result,
        .warning,
        .N06_SCOPE_MINIMIZATION,
        .TS08_SCOPE,
        file_path,
        msg,
    );
}

fn collect_function_top_level_statements(
    tree: *const std.zig.Ast,
    body_node: std.zig.Ast.Node.Index,
    out: *std.array_list.Managed(std.zig.Ast.Node.Index),
) !void {
    assert(tree.nodes.items(.tag).len == tree.nodes.len);
    assert(body_node == .root or @intFromEnum(body_node) < tree.nodes.len);
    if (body_node == .root or @intFromEnum(body_node) >= tree.nodes.len) return;
    const tag = tree.nodes.items(.tag)[@intFromEnum(body_node)];

    switch (tag) {
        .block,
        .block_semicolon,
        => {
            const stmts = tree.extraDataSlice(
                tree.nodeData(body_node).extra_range,
                std.zig.Ast.Node.Index,
            );
            for (stmts) |stmt| {
                try out.append(stmt);
            }
        },
        .block_two,
        .block_two_semicolon,
        => {
            const first, const second = tree.nodeData(body_node).opt_node_and_opt_node;
            if (first.unwrap()) |first_stmt| {
                try out.append(first_stmt);
            }
            if (second.unwrap()) |second_stmt| {
                try out.append(second_stmt);
            }
        },
        else => {
            try out.append(body_node);
        },
    }
}

fn is_local_var_decl_tag(tag: std.zig.Ast.Node.Tag) bool {
    return tag == .local_var_decl or tag == .simple_var_decl or tag == .aligned_var_decl;
}

fn first_statement_using_identifier(
    tree: *const std.zig.Ast,
    statements: []const std.zig.Ast.Node.Index,
    start_index: u32,
    identifier: []const u8,
) ?u32 {
    assert(identifier.len > 0);
    if (identifier.len == 0) return null;
    var index = start_index;
    while (@as(usize, index) < statements.len) : (index += 1) {
        if (node_contains_identifier_token(tree, statements[@as(usize, index)], identifier)) {
            return index;
        }
    }
    return null;
}

fn node_contains_identifier_token(
    tree: *const std.zig.Ast,
    node: std.zig.Ast.Node.Index,
    identifier: []const u8,
) bool {
    assert(identifier.len > 0);
    assert(node == .root or @intFromEnum(node) < tree.nodes.len);
    if (identifier.len == 0) return false;
    if (node == .root or @intFromEnum(node) >= tree.nodes.len) return false;
    const first = tree.firstToken(node);
    const last = tree.lastToken(node);
    if (first >= tree.tokens.len) return false;
    if (last >= tree.tokens.len) return false;
    if (first > last) return false;

    const end = @as(usize, last) + 1;
    for (@as(usize, first)..end) |token_index| {
        const token: std.zig.Ast.TokenIndex = @intCast(token_index);
        if (tree.tokens.items(.tag)[token] != .identifier) continue;
        if (std.mem.eql(u8, tree.tokenSlice(token), identifier)) {
            return true;
        }
    }
    return false;
}

fn const_global_is_risky(
    allocator: std.mem.Allocator,
    tree: *const std.zig.Ast,
    var_decl: std.zig.Ast.full.VarDecl,
) !bool {
    assert(tree.nodes.len > 0);
    assert(tree.tokens.len > 0);
    if (tree.nodes.len == 0) return false;
    if (tree.tokens.len == 0) return false;
    var type_risky = false;
    if (var_decl.ast.type_node.unwrap()) |type_node| {
        type_risky = type_has_pointer_or_optional(tree, type_node);
    }
    var init_visited = std.AutoHashMap(std.zig.Ast.Node.Index, void).init(allocator);
    defer init_visited.deinit();
    var init_risky = false;
    if (var_decl.ast.init_node.unwrap()) |init_node| {
        init_risky = expr_contains_allocator(tree, init_node, &init_visited);
    }
    return type_risky or init_risky;
}

fn detect_local_pointer_depth(
    tree: *const std.zig.Ast,
    node: std.zig.Ast.Node.Index,
    file_path: []const u8,
    result: *Result,
) anyerror!void {
    assert(file_path.len > 0);
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    if (file_path.len == 0) return;
    if (node == .root or @intFromEnum(node) >= tree.nodes.len) return;

    var ctx = PointerDepthVisitCtx{
        .file_path = file_path,
        .result = result,
    };
    try ast_walk.walk(tree, node, &ctx, pointer_depth_visit_node);
}

const PointerDepthVisitCtx = struct {
    file_path: []const u8,
    result: *Result,
};

fn pointer_depth_visit_node(
    tree: *const std.zig.Ast,
    node: std.zig.Ast.Node.Index,
    ctx_opaque: *anyopaque,
) anyerror!void {
    const ctx: *PointerDepthVisitCtx = @ptrCast(@alignCast(ctx_opaque));
    try detect_pointer_depth_here(tree, node, ctx.file_path, ctx.result);
}

fn detect_pointer_depth_here(
    tree: *const std.zig.Ast,
    node: std.zig.Ast.Node.Index,
    file_path: []const u8,
    result: *Result,
) !void {
    assert(file_path.len > 0);
    assert(node == .root or @intFromEnum(node) < tree.nodes.len);
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    if (file_path.len == 0) return;
    if (node == .root or @intFromEnum(node) >= tree.nodes.len) return;
    const tag = tree.nodes.items(.tag)[@intFromEnum(node)];
    switch (tag) {
        .local_var_decl,
        .simple_var_decl,
        .aligned_var_decl,
        => {
            if (tree.fullVarDecl(node)) |var_decl| {
                if (var_decl.ast.type_node.unwrap()) |type_node| {
                    if (pointer_depth(tree, type_node) >= 2) {
                        try append_diag(
                            result,
                            .critical,
                            .N09_POINTER_DISCIPLINE,
                            file_path,
                            "multi-level pointer is forbidden (`**T` or deeper)",
                        );
                    }
                    if (is_function_pointer_type(tree, type_node)) {
                        const name_token = var_decl.ast.mut_token + 1;
                        if (name_token < tree.tokens.len and
                            tree.tokens.items(.tag)[name_token] == .identifier)
                        {
                            const name = tree.tokenSlice(name_token);
                            const msg = try std.fmt.allocPrint(
                                result.diagnostics.allocator,
                                "N09_POINTER_DISCIPLINE: local `{s}` uses " ++
                                    "function pointer type; " ++
                                    "prefer explicit enum/tag dispatch",
                                .{name},
                            );
                            try append_diag(
                                result,
                                .critical,
                                .N09_POINTER_DISCIPLINE,
                                file_path,
                                msg,
                            );
                        }
                    }
                }
            }
        },
        else => {},
    }
}

fn pointer_depth(tree: *const std.zig.Ast, type_node: std.zig.Ast.Node.Index) u8 {
    assert(tree.nodes.len > 0);
    if (type_node == .root or @intFromEnum(type_node) >= tree.nodes.len) return 0;

    const tag = tree.nodes.items(.tag)[@intFromEnum(type_node)];
    if (tag == .optional_type) {
        const child = tree.nodeData(type_node).node;
        return pointer_depth(tree, child);
    }
    if (tree.fullPtrType(type_node)) |ptr| {
        return 1 + pointer_depth(tree, ptr.ast.child_type);
    }
    if (tag == .grouped_expression) {
        return pointer_depth(tree, tree.nodeData(type_node).node_and_token[0]);
    }
    return 0;
}

fn type_has_pointer_or_optional(tree: *const std.zig.Ast, type_node: std.zig.Ast.Node.Index) bool {
    if (type_node == .root or @intFromEnum(type_node) >= tree.nodes.len) return false;
    const tag = tree.nodes.items(.tag)[@intFromEnum(type_node)];
    if (tag == .optional_type) return true;
    if (tree.fullPtrType(type_node)) |_| return true;
    return false;
}

fn alias_risk_pointer_key(tree: *const std.zig.Ast, type_node: std.zig.Ast.Node.Index) ?[]const u8 {
    if (type_node == .root or @intFromEnum(type_node) >= tree.nodes.len) return null;
    if (tree.nodes.items(.tag)[@intFromEnum(type_node)] == .optional_type) {
        return alias_risk_pointer_key(tree, tree.nodeData(type_node).node);
    }
    if (tree.fullPtrType(type_node)) |ptr| {
        if (ptr.size == .slice or ptr.const_token != null) return null;
        return type_alias_key(tree, ptr.ast.child_type);
    }
    return null;
}

fn type_alias_key(tree: *const std.zig.Ast, type_node: std.zig.Ast.Node.Index) []const u8 {
    if (type_node == .root or @intFromEnum(type_node) >= tree.nodes.len) return "<unknown>";

    const tag = tree.nodes.items(.tag)[@intFromEnum(type_node)];
    return switch (tag) {
        .grouped_expression => type_alias_key(tree, tree.nodeData(type_node).node_and_token[0]),
        .optional_type => type_alias_key(tree, tree.nodeData(type_node).node),
        .identifier => tree.tokenSlice(tree.nodes.items(.main_token)[@intFromEnum(type_node)]),
        .field_access => tree.tokenSlice(tree.nodeData(type_node).node_and_token[1]),
        .call,
        .call_comma,
        .call_one,
        .call_one_comma,
        => blk: {
            var call_buf: [1]std.zig.Ast.Node.Index = undefined;
            const call = tree.fullCall(&call_buf, type_node) orelse break :blk "<call-type>";
            break :blk type_alias_key(tree, call.ast.fn_expr);
        },
        else => tree.tokenSlice(tree.nodes.items(.main_token)[@intFromEnum(type_node)]),
    };
}

fn expr_contains_allocator(
    tree: *const std.zig.Ast,
    expr_node: std.zig.Ast.Node.Index,
    visited: *std.AutoHashMap(std.zig.Ast.Node.Index, void),
) bool {
    assert(tree.nodes.len > 0);
    assert(tree.nodes.items(.main_token).len == tree.nodes.len);
    if (expr_node == .root or @intFromEnum(expr_node) >= tree.nodes.len) return false;
    if (visited.count() > ast_walk_nodes_max) return false;
    if (visited.contains(expr_node)) return false;
    visited.put(expr_node, {}) catch return false;

    const tag = tree.nodes.items(.tag)[@intFromEnum(expr_node)];
    if (expr_is_allocator_symbol(tree, expr_node, tag)) return true;
    return expr_children_contain_allocator(tree, expr_node, tag, visited);
}

fn expr_is_allocator_symbol(
    tree: *const std.zig.Ast,
    expr_node: std.zig.Ast.Node.Index,
    tag: std.zig.Ast.Node.Tag,
) bool {
    assert(expr_node == .root or @intFromEnum(expr_node) < tree.nodes.len);
    assert(tree.nodes.items(.main_token).len == tree.nodes.len);
    if (expr_node == .root or @intFromEnum(expr_node) >= tree.nodes.len) return false;
    if (tag == .identifier) {
        const token = tree.nodes.items(.main_token)[@intFromEnum(expr_node)];
        const ident = tree.tokenSlice(token);
        return std.mem.eql(u8, ident, "allocator") or
            std.mem.eql(u8, ident, "page_allocator");
    }
    if (tag == .field_access) {
        const data = tree.nodeData(expr_node).node_and_token;
        const field_name = tree.tokenSlice(data[1]);
        return std.mem.eql(u8, field_name, "allocator") or
            std.mem.eql(u8, field_name, "page_allocator") or
            std.mem.eql(u8, field_name, "alloc") or
            std.mem.eql(u8, field_name, "create");
    }
    return false;
}

fn expr_children_contain_allocator(
    tree: *const std.zig.Ast,
    expr_node: std.zig.Ast.Node.Index,
    tag: std.zig.Ast.Node.Tag,
    visited: *std.AutoHashMap(std.zig.Ast.Node.Index, void),
) bool {
    assert(expr_node == .root or @intFromEnum(expr_node) < tree.nodes.len);
    assert(visited.count() <= ast_walk_nodes_max + 1);
    if (expr_node == .root or @intFromEnum(expr_node) >= tree.nodes.len) return false;
    switch (tag) {
        .field_access,
        .unwrap_optional,
        .grouped_expression,
        => {
            const child = tree.nodeData(expr_node).node_and_token[0];
            return expr_contains_allocator(tree, child, visited);
        },
        .@"try" => {
            const child = tree.nodeData(expr_node).node;
            return expr_contains_allocator(tree, child, visited);
        },
        .bool_and,
        .bool_or,
        .@"catch",
        .@"orelse",
        .assign,
        => {
            const pair = tree.nodeData(expr_node).node_and_node;
            return expr_contains_allocator(tree, pair[0], visited) or
                expr_contains_allocator(tree, pair[1], visited);
        },
        .call,
        .call_comma,
        .call_one,
        .call_one_comma,
        => return call_expr_contains_allocator(tree, expr_node, visited),
        else => return false,
    }
}

fn call_expr_contains_allocator(
    tree: *const std.zig.Ast,
    expr_node: std.zig.Ast.Node.Index,
    visited: *std.AutoHashMap(std.zig.Ast.Node.Index, void),
) bool {
    assert(expr_node == .root or @intFromEnum(expr_node) < tree.nodes.len);
    assert(visited.count() <= ast_walk_nodes_max + 1);
    if (expr_node == .root or @intFromEnum(expr_node) >= tree.nodes.len) return false;
    var call_buf: [1]std.zig.Ast.Node.Index = undefined;
    const call = tree.fullCall(&call_buf, expr_node) orelse return false;
    if (expr_contains_allocator(tree, call.ast.fn_expr, visited)) return true;
    for (call.ast.params) |param| {
        if (expr_contains_allocator(tree, param, visited)) return true;
    }
    return false;
}

fn detect_implicit_alloc_and_switch_else(
    allocator: std.mem.Allocator,
    tree: *const std.zig.Ast,
    source: []const u8,
    node: std.zig.Ast.Node.Index,
    file_path: []const u8,
    result: *Result,
) anyerror!void {
    assert(source.len > 0);
    assert(file_path.len > 0);
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    if (source.len == 0) return;
    if (file_path.len == 0) return;
    if (node == .root or @intFromEnum(node) >= tree.nodes.len) return;

    var role_index = roles.SemanticIndex.init(allocator, tree);
    defer role_index.deinit();

    var ctx = ImplicitVisitCtx{
        .tree = tree,
        .role_index = &role_index,
        .source = source,
        .file_path = file_path,
        .enable_tigerbeetle_profile_rules = is_tigerbeetle_style_target_file(file_path),
        .result = result,
    };

    ast_walk.walk_with_options(tree, node, &ctx, implicit_visit_node, .{
        .max_nodes = ast_walk_nodes_max,
    }) catch |err| {
        if (err == error.AstWalkLimit) return;
        return err;
    };
}

const ImplicitVisitCtx = struct {
    tree: *const std.zig.Ast,
    role_index: *roles.SemanticIndex,
    source: []const u8,
    file_path: []const u8,
    enable_tigerbeetle_profile_rules: bool,
    result: *Result,
};

fn assert_implicit_walk_ctx(ctx: *const ImplicitVisitCtx) void {
    assert(ctx.file_path.len > 0);
    assert(ctx.source.len > 0);
    const diag_len = ctx.result.diagnostics.items.len;
    const diag_count = ctx.result.warning_count + ctx.result.critical_count;
    assert(diag_len == diag_count);
}

fn implicit_visit_node(
    tree: *const std.zig.Ast,
    node: std.zig.Ast.Node.Index,
    ctx_opaque: *anyopaque,
) anyerror!ast_walk.VisitDecision {
    const ctx: *ImplicitVisitCtx = @ptrCast(@alignCast(ctx_opaque));
    assert(node == .root or @intFromEnum(node) < tree.nodes.len);
    assert(tree.nodes.items(.main_token).len == tree.nodes.len);
    if (node == .root or @intFromEnum(node) >= tree.nodes.len) return .visit_children;
    assert_implicit_walk_ctx(ctx);
    const tag = tree.nodes.items(.tag)[@intFromEnum(node)];

    switch (tag) {
        .call,
        .call_comma,
        .call_one,
        .call_one_comma,
        => {
            var call_buf: [1]std.zig.Ast.Node.Index = undefined;
            const call = tree.fullCall(&call_buf, node) orelse return .visit_children;
            try detect_implicit_call_style_violations(ctx, node, call.ast.fn_expr);
        },
        .builtin_call,
        .builtin_call_comma,
        .builtin_call_two,
        .builtin_call_two_comma,
        => {
            try detect_implicit_builtin_style_violations(ctx, node);
        },
        .@"while",
        .while_simple,
        .while_cont,
        => try walk_implicit_while(
            ctx.role_index,
            tree,
            node,
            ctx.file_path,
            ctx.result,
        ),
        .@"if",
        .if_simple,
        => try walk_implicit_if(tree, ctx.source, node, ctx.file_path, ctx.result),
        .@"for",
        .for_simple,
        => try walk_implicit_for(ctx.role_index, tree, node, ctx.file_path, ctx.result),
        .@"switch",
        .switch_comma,
        => try walk_implicit_switch(tree, ctx.source, node, ctx.file_path, ctx.result),
        else => {},
    }
    return .visit_children;
}

fn detect_implicit_call_style_violations(
    ctx: *ImplicitVisitCtx,
    call_node: std.zig.Ast.Node.Index,
    fn_expr: std.zig.Ast.Node.Index,
) anyerror!void {
    assert_implicit_walk_ctx(ctx);
    assert(call_node == .root or @intFromEnum(call_node) < ctx.tree.nodes.len);
    assert(fn_expr == .root or @intFromEnum(fn_expr) < ctx.tree.nodes.len);
    if (is_page_allocator_call(ctx.tree, fn_expr)) {
        try append_diag_pair(
            ctx.result,
            .warning,
            .N03_STATIC_MEMORY,
            .TS07_MEMORY_PHASE,
            ctx.file_path,
            "implicit allocator use (`std.heap.page_allocator`) is forbidden; " ++
                "pass Allocator explicitly",
        );
    }
    if (ctx.enable_tigerbeetle_profile_rules) {
        if (is_qualified_std_debug_assert_call(ctx.tree, fn_expr)) {
            try append_diag(
                ctx.result,
                .warning,
                .TB02_ASSERT_ALIAS,
                ctx.file_path,
                "qualified `std.debug.assert` is banned; use unqualified `assert` alias",
            );
        }

        if (is_std_mem_copy_call(ctx.tree, fn_expr)) {
            if (!is_tigerbeetle_stdx_copy_impl_file(ctx.file_path)) {
                if (!has_inline_tidy_bypass_comment(ctx.tree, ctx.source, fn_expr)) {
                    try append_diag(
                        ctx.result,
                        .warning,
                        .TB03_COPY_API,
                        ctx.file_path,
                        tb03_copy_api_message,
                    );
                }
            }
        }
    }
    if (is_std_process_run_call_with_empty_options(ctx.tree, ctx.source, call_node, fn_expr)) {
        try append_diag(
            ctx.result,
            .warning,
            .TS16_EXPLICIT_OPTIONS,
            ctx.file_path,
            "TS16_EXPLICIT_OPTIONS: std.process.run uses empty options `.{};` " ++
                "specify options explicitly",
        );
    }
}

fn detect_implicit_builtin_style_violations(
    ctx: *ImplicitVisitCtx,
    node: std.zig.Ast.Node.Index,
) anyerror!void {
    assert_implicit_walk_ctx(ctx);
    if (is_builtin_named(ctx.tree, node, "@call")) {
        try append_diag(
            ctx.result,
            .warning,
            .N08_PREPROCESSOR_OR_COMPTIME_BUDGET,
            ctx.file_path,
            "N08_PREPROCESSOR_OR_COMPTIME_BUDGET: hidden control flow via `@call` is " ++
                "forbidden; use direct calls or explicit dispatch",
        );
    }
    if (ctx.enable_tigerbeetle_profile_rules) {
        if (is_builtin_named(ctx.tree, node, "@memcpy")) {
            if (!has_inline_tidy_bypass_comment(ctx.tree, ctx.source, node)) {
                try append_diag(
                    ctx.result,
                    .warning,
                    .TB03_COPY_API,
                    ctx.file_path,
                    tb03_copy_api_message,
                );
            }
        }
    }
}

fn walk_implicit_while(
    role_index: *roles.SemanticIndex,
    tree: *const std.zig.Ast,
    node: std.zig.Ast.Node.Index,
    file_path: []const u8,
    result: *Result,
) anyerror!void {
    assert(file_path.len > 0);
    assert(node == .root or @intFromEnum(node) < tree.nodes.len);
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    if (file_path.len == 0) return;
    if (node == .root or @intFromEnum(node) >= tree.nodes.len) return;
    const full = tree.fullWhile(node) orelse return;
    if (boolean_condition_operator_count(tree, full.ast.cond_expr) >= 2) {
        try append_diag(
            result,
            .critical,
            .TS13_BOOLEAN_SPLIT,
            file_path,
            "TS13_BOOLEAN_SPLIT: split dense loop condition into explicit guard checks",
        );
    }
    if (queue_growth_bounds.loop_has_unbounded_queue_growth(
        role_index,
        full.ast.cond_expr,
        full.ast.then_expr,
    )) {
        try append_diag(
            result,
            .warning,
            .TS02_EXPLICIT_BOUNDS,
            file_path,
            "TS02_EXPLICIT_BOUNDS: queue growth in loop requires explicit queue-capacity bounds",
        );
    }
    if (!is_self_analysis_source_file(file_path) and
        event_pacing.loop_has_unpaced_external_mutation(role_index, full.ast.then_expr))
    {
        try append_diag(
            result,
            .warning,
            .TS11_PACED_CONTROL,
            file_path,
            "TS11_PACED_CONTROL: require explicit batch boundary before state updates",
        );
    }
    if (is_literal_true(tree, full.ast.cond_expr)) {
        try append_diag_pair(
            result,
            .warning,
            .N02_BOUNDED_LOOPS,
            .TS02_EXPLICIT_BOUNDS,
            file_path,
            "literal `while (true)` loop is unbounded; rewrite with explicit finite bound",
        );
    }
}

fn walk_implicit_if(
    tree: *const std.zig.Ast,
    source: []const u8,
    node: std.zig.Ast.Node.Index,
    file_path: []const u8,
    result: *Result,
) anyerror!void {
    assert(file_path.len > 0);
    assert(node == .root or @intFromEnum(node) < tree.nodes.len);
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    if (file_path.len == 0) return;
    if (node == .root or @intFromEnum(node) >= tree.nodes.len) return;
    const full = tree.fullIf(node) orelse return;
    if (boolean_condition_operator_count(tree, full.ast.cond_expr) >= 2) {
        try append_diag(
            result,
            .critical,
            .TS13_BOOLEAN_SPLIT,
            file_path,
            "TS13_BOOLEAN_SPLIT: split dense branch condition into explicit guard checks",
        );
    }
    const tags = tree.nodes.items(.tag);

    if (!is_braced_block_tag(tags[@intFromEnum(full.ast.then_expr)]) and
        !is_single_line_if(tree, source, node, full.ast.then_expr))
    {
        try append_diag(
            result,
            .warning,
            .TS25_IF_BRACES,
            file_path,
            "TS25_IF_BRACES: if statement body must use braces (single-line exception allowed)",
        );
    }

    if (full.ast.else_expr.unwrap()) |else_expr| {
        const else_tag = tags[@intFromEnum(else_expr)];
        if (!is_else_if_or_braced(else_tag)) {
            try append_diag(
                result,
                .warning,
                .TS25_IF_BRACES,
                file_path,
                "TS25_IF_BRACES: else statement body must use braces",
            );
        }
    }
}

fn walk_implicit_for(
    role_index: *roles.SemanticIndex,
    tree: *const std.zig.Ast,
    node: std.zig.Ast.Node.Index,
    file_path: []const u8,
    result: *Result,
) anyerror!void {
    assert(file_path.len > 0);
    assert(node == .root or @intFromEnum(node) < tree.nodes.len);
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    if (file_path.len == 0) return;
    if (node == .root or @intFromEnum(node) >= tree.nodes.len) return;
    const full = tree.fullFor(node) orelse return;
    if (queue_growth_bounds.loop_has_unbounded_queue_growth(
        role_index,
        .root,
        full.ast.then_expr,
    )) {
        try append_diag(
            result,
            .warning,
            .TS02_EXPLICIT_BOUNDS,
            file_path,
            "TS02_EXPLICIT_BOUNDS: queue growth in loop requires explicit queue-capacity bounds",
        );
    }
    if (!is_self_analysis_source_file(file_path) and
        event_pacing.loop_has_unpaced_external_mutation(role_index, full.ast.then_expr))
    {
        try append_diag(
            result,
            .warning,
            .TS11_PACED_CONTROL,
            file_path,
            "TS11_PACED_CONTROL: require explicit batch boundary before state updates",
        );
    }
}

fn walk_implicit_switch(
    tree: *const std.zig.Ast,
    _: []const u8,
    node: std.zig.Ast.Node.Index,
    file_path: []const u8,
    result: *Result,
) anyerror!void {
    assert(file_path.len > 0);
    assert(node == .root or @intFromEnum(node) < tree.nodes.len);
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    if (file_path.len == 0) return;
    if (node == .root or @intFromEnum(node) >= tree.nodes.len) return;
    const full = tree.switchFull(node);
    if (!switch_condition_prefers_exhaustive_ts01(tree, full.ast.condition)) return;
    const warn_else = true;
    for (full.ast.cases) |case_node| {
        if (warn_else and switch_case_is_else_branch(tree, case_node)) {
            try append_diag(
                result,
                .warning,
                .TS01_SIMPLE_FLOW,
                file_path,
                "switch `else` branch is discouraged; enumerate all enum variants explicitly",
            );
        }
    }
}

fn switch_condition_prefers_exhaustive_ts01(
    tree: *const std.zig.Ast,
    condition_node: std.zig.Ast.Node.Index,
) bool {
    assert(condition_node == .root or @intFromEnum(condition_node) < tree.nodes.len);
    assert(tree.nodes.items(.main_token).len == tree.nodes.len);
    if (condition_node == .root or @intFromEnum(condition_node) >= tree.nodes.len) return false;
    if (tree.nodes.items(.tag)[@intFromEnum(condition_node)] != .identifier) return false;
    const token = tree.nodes.items(.main_token)[@intFromEnum(condition_node)];
    const name = tree.tokenSlice(token);
    if (std.mem.eql(u8, name, "tag")) return false;
    if (std.mem.endsWith(u8, name, "_tag")) return false;
    return true;
}

fn boolean_condition_operator_count(
    tree: *const std.zig.Ast,
    node: std.zig.Ast.Node.Index,
) u8 {
    assert(tree.nodes.items(.main_token).len == tree.nodes.len);
    assert(node == .root or @intFromEnum(node) < tree.nodes.len);
    if (node == .root or @intFromEnum(node) >= tree.nodes.len) return 0;
    const tag = tree.nodes.items(.tag)[@intFromEnum(node)];

    switch (tag) {
        .bool_and,
        .bool_or,
        => {
            const pair = tree.nodeData(node).node_and_node;
            const left = boolean_condition_operator_count(tree, pair[0]);
            const right = boolean_condition_operator_count(tree, pair[1]);
            const subtotal = @as(u16, left) + @as(u16, right) + 1;
            return saturating_u8_from_u16(subtotal);
        },
        .grouped_expression,
        .field_access,
        .unwrap_optional,
        => {
            const child = tree.nodeData(node).node_and_token[0];
            return boolean_condition_operator_count(tree, child);
        },
        .@"try",
        .@"comptime",
        .deref,
        .bool_not,
        .negation,
        .bit_not,
        .negation_wrap,
        .address_of,
        => {
            const child = tree.nodeData(node).node;
            return boolean_condition_operator_count(tree, child);
        },
        .@"catch",
        .@"orelse",
        .assign,
        => {
            const pair = tree.nodeData(node).node_and_node;
            const left = boolean_condition_operator_count(tree, pair[0]);
            const right = boolean_condition_operator_count(tree, pair[1]);
            const subtotal = @as(u16, left) + @as(u16, right);
            return saturating_u8_from_u16(subtotal);
        },
        .call,
        .call_comma,
        .call_one,
        .call_one_comma,
        => {
            var total: u8 = 0;
            var call_buf: [1]std.zig.Ast.Node.Index = undefined;
            const call = tree.fullCall(&call_buf, node) orelse return 0;
            total = saturating_u8_add(
                total,
                boolean_condition_operator_count(tree, call.ast.fn_expr),
            );
            for (call.ast.params) |param| {
                total = saturating_u8_add(total, boolean_condition_operator_count(tree, param));
            }
            return total;
        },
        else => return 0,
    }
}

fn saturating_u8_add(lhs: u8, rhs: u8) u8 {
    const total = @as(u16, lhs) + @as(u16, rhs);
    return saturating_u8_from_u16(total);
}

fn saturating_u8_from_u16(total: u16) u8 {
    if (total > std.math.maxInt(u8)) {
        return std.math.maxInt(u8);
    }
    return @intCast(total);
}

fn is_braced_block_tag(tag: std.zig.Ast.Node.Tag) bool {
    return tag == .block or
        tag == .block_semicolon or
        tag == .block_two or
        tag == .block_two_semicolon;
}

fn is_else_if_or_braced(tag: std.zig.Ast.Node.Tag) bool {
    return tag == .@"if" or tag == .if_simple or is_braced_block_tag(tag);
}

fn switch_case_is_else_branch(tree: *const std.zig.Ast, case_node: std.zig.Ast.Node.Index) bool {
    const full = tree.fullSwitchCase(case_node) orelse return false;
    return full.ast.values.len == 0;
}

fn is_page_allocator_call(tree: *const std.zig.Ast, fn_expr: std.zig.Ast.Node.Index) bool {
    assert(fn_expr == .root or @intFromEnum(fn_expr) < tree.nodes.len);
    assert(tree.nodes.items(.main_token).len == tree.nodes.len);
    if (fn_expr == .root or @intFromEnum(fn_expr) >= tree.nodes.len) return false;
    var path: [6][]const u8 = undefined;
    var len: u8 = 0;
    collect_call_path(tree, fn_expr, &path, &len);
    if (len < 4) return false;
    if (!std.mem.eql(u8, path[0], "std")) return false;
    if (!std.mem.eql(u8, path[1], "heap")) return false;
    return std.mem.eql(u8, path[2], "page_allocator");
}

fn is_qualified_std_debug_assert_call(
    tree: *const std.zig.Ast,
    fn_expr: std.zig.Ast.Node.Index,
) bool {
    var path: [6][]const u8 = undefined;
    var len: u8 = 0;
    collect_call_path(tree, fn_expr, &path, &len);

    return len >= 3 and
        std.mem.eql(u8, path[0], "std") and
        std.mem.eql(u8, path[1], "debug") and
        std.mem.eql(u8, path[2], "assert");
}

fn is_std_process_run_call_with_empty_options(
    tree: *const std.zig.Ast,
    source: []const u8,
    call_node: std.zig.Ast.Node.Index,
    fn_expr: std.zig.Ast.Node.Index,
) bool {
    assert(source.len > 0);
    assert(call_node == .root or @intFromEnum(call_node) < tree.nodes.len);
    assert(tree.nodes.items(.main_token).len == tree.nodes.len);
    if (source.len == 0) return false;
    if (call_node == .root or @intFromEnum(call_node) >= tree.nodes.len) return false;
    if (!is_std_process_run_call(tree, fn_expr)) return false;
    var call_buf: [1]std.zig.Ast.Node.Index = undefined;
    const call = tree.fullCall(&call_buf, call_node) orelse return false;
    for (call.ast.params) |param| {
        if (expr_is_empty_struct_literal(tree, source, param)) {
            return true;
        }
    }
    return false;
}

fn is_std_process_run_call(tree: *const std.zig.Ast, fn_expr: std.zig.Ast.Node.Index) bool {
    var path: [6][]const u8 = undefined;
    var len: u8 = 0;
    collect_call_path(tree, fn_expr, &path, &len);
    return len >= 3 and
        std.mem.eql(u8, path[0], "std") and
        std.mem.eql(u8, path[1], "process") and
        std.mem.eql(u8, path[2], "run");
}

fn is_std_mem_copy_call(tree: *const std.zig.Ast, fn_expr: std.zig.Ast.Node.Index) bool {
    var path: [6][]const u8 = undefined;
    var len: u8 = 0;
    collect_call_path(tree, fn_expr, &path, &len);
    return len >= 3 and
        std.mem.eql(u8, path[0], "std") and
        std.mem.eql(u8, path[1], "mem") and
        (std.mem.eql(u8, path[2], "copyForwards") or
            std.mem.eql(u8, path[2], "copyBackwards"));
}

fn expr_is_empty_struct_literal(
    tree: *const std.zig.Ast,
    source: []const u8,
    node: std.zig.Ast.Node.Index,
) bool {
    assert(node == .root or @intFromEnum(node) < tree.nodes.len);
    assert(source.len <= std.math.maxInt(u32));
    if (source.len == 0) return false;
    if (node == .root or @intFromEnum(node) >= tree.nodes.len) return false;
    const first_token = tree.firstToken(node);
    const last_token = tree.lastToken(node);
    if (first_token >= tree.tokens.len or last_token >= tree.tokens.len) {
        return false;
    }

    const start = tree.tokens.items(.start)[first_token];
    const end = tree.tokens.items(.start)[last_token] + tree.tokenSlice(last_token).len;
    if (start >= source.len) return false;
    if (end > source.len) return false;
    if (start >= end) return false;

    return compact_source_equals(source[start..end], ".{}");
}

fn compact_source_equals(segment: []const u8, expected: []const u8) bool {
    assert(expected.len > 0);
    assert(segment.len > 0);
    if (expected.len == 0) return false;
    if (segment.len == 0) return false;
    var compact: [16]u8 = undefined;
    var compact_len: usize = 0;
    for (segment) |c| {
        if (std.ascii.isWhitespace(c)) continue;
        if (compact_len >= compact.len) return false;
        compact[compact_len] = c;
        compact_len += 1;
    }
    return compact_len == expected.len and std.mem.eql(u8, compact[0..compact_len], expected);
}

fn is_builtin_named(
    tree: *const std.zig.Ast,
    node: std.zig.Ast.Node.Index,
    builtin_name: []const u8,
) bool {
    assert(builtin_name.len > 0);
    assert(node == .root or @intFromEnum(node) < tree.nodes.len);
    assert(tree.nodes.items(.main_token).len == tree.nodes.len);
    if (builtin_name.len == 0) return false;
    if (node == .root or @intFromEnum(node) >= tree.nodes.len) return false;
    const tag = tree.nodes.items(.tag)[@intFromEnum(node)];
    switch (tag) {
        .builtin_call,
        .builtin_call_comma,
        .builtin_call_two,
        .builtin_call_two_comma,
        => {},
        else => return false,
    }
    const token = tree.nodes.items(.main_token)[@intFromEnum(node)];
    if (token >= tree.tokens.len) return false;
    return std.mem.eql(u8, tree.tokenSlice(token), builtin_name);
}

fn has_inline_tidy_bypass_comment(
    tree: *const std.zig.Ast,
    source: []const u8,
    node: std.zig.Ast.Node.Index,
) bool {
    assert(source.len > 0);
    assert(node == .root or @intFromEnum(node) < tree.nodes.len);
    assert(tree.nodes.items(.main_token).len == tree.nodes.len);
    if (source.len == 0) return false;
    if (node == .root or @intFromEnum(node) >= tree.nodes.len) return false;
    const token = tree.nodes.items(.main_token)[@intFromEnum(node)];
    if (token >= tree.tokens.len) return false;
    const token_start = tree.tokens.items(.start)[token];
    if (token_start >= source.len) return false;
    const line_end = std.mem.indexOfPos(u8, source, token_start, "\n") orelse source.len;
    const line = source[token_start..line_end];
    return std.mem.indexOf(u8, line, "Bypass tidy") != null;
}

fn is_tigerbeetle_style_target_file(file_path: []const u8) bool {
    assert(file_path.len > 0);
    if (file_path.len == 0) return false;
    return std.mem.indexOf(u8, file_path, "/tigerbeetle/src/") != null or
        std.mem.startsWith(u8, file_path, "tigerbeetle/src/") or
        std.mem.indexOf(u8, file_path, "/tests/corpus/tigerbeetle/") != null or
        std.mem.startsWith(u8, file_path, "tests/corpus/tigerbeetle/");
}

fn is_tigerbeetle_stdx_copy_impl_file(file_path: []const u8) bool {
    assert(file_path.len > 0);
    if (file_path.len == 0) return false;
    return std.mem.indexOf(u8, file_path, "/tigerbeetle/src/stdx/stdx.zig") != null or
        std.mem.eql(u8, file_path, "tigerbeetle/src/stdx/stdx.zig");
}

fn is_self_analysis_source_file(file_path: []const u8) bool {
    assert(file_path.len > 0);
    if (file_path.len == 0) return false;
    return std.mem.indexOf(u8, file_path, "/src/libtigercheck/analysis/") != null or
        std.mem.startsWith(u8, file_path, "src/libtigercheck/analysis/");
}

fn is_literal_true(tree: *const std.zig.Ast, node: std.zig.Ast.Node.Index) bool {
    assert(tree.nodes.items(.tag).len == tree.nodes.len);
    assert(node == .root or @intFromEnum(node) < tree.nodes.len);
    if (node == .root or @intFromEnum(node) >= tree.nodes.len) return false;
    var current = node;
    while (current != .root and @intFromEnum(current) < tree.nodes.len) {
        const tag = tree.nodes.items(.tag)[@intFromEnum(current)];
        if (tag == .grouped_expression or tag == .unwrap_optional) {
            current = tree.nodeData(current).node_and_token[0];
            continue;
        }
        if (tag == .@"try") {
            current = tree.nodeData(current).node;
            continue;
        }
        if (tag != .identifier) return false;
        const tok = tree.nodes.items(.main_token)[@intFromEnum(current)];
        return std.mem.eql(u8, tree.tokenSlice(tok), "true");
    }
    return false;
}

fn is_single_line_if(
    tree: *const std.zig.Ast,
    source: []const u8,
    if_node: std.zig.Ast.Node.Index,
    then_expr: std.zig.Ast.Node.Index,
) bool {
    // Single-line exception: if (cond) expr; is allowed
    assert(if_node == .root or @intFromEnum(if_node) < tree.nodes.len);
    assert(then_expr == .root or @intFromEnum(then_expr) < tree.nodes.len);
    assert(source.len > 0);
    if (source.len == 0) return false;
    if (if_node == .root or @intFromEnum(if_node) >= tree.nodes.len) return false;
    if (then_expr == .root or @intFromEnum(then_expr) >= tree.nodes.len) return false;
    const if_token = tree.nodes.items(.main_token)[@intFromEnum(if_node)];
    const then_last_token = tree.lastToken(then_expr);

    if (if_token >= tree.tokens.len or then_last_token >= tree.tokens.len) return false;

    const if_start = tree.tokens.items(.start)[if_token];
    const then_end =
        tree.tokens.items(.start)[then_last_token] + tree.tokenSlice(then_last_token).len;

    if (if_start >= source.len or then_end > source.len) return false;

    // Check if there are any newlines between if and the end of then expression
    const segment = source[if_start..then_end];
    return std.mem.indexOfScalar(u8, segment, '\n') == null;
}

fn is_arch_sized_type(tree: *const std.zig.Ast, type_node: std.zig.Ast.Node.Index) bool {
    assert(tree.nodes.len > 0);
    assert(tree.nodes.items(.main_token).len == tree.nodes.len);
    if (type_node == .root or @intFromEnum(type_node) >= tree.nodes.len) return false;

    const tag = tree.nodes.items(.tag)[@intFromEnum(type_node)];

    // Handle optional types (e.g., ?usize)
    if (tag == .optional_type) {
        const child = tree.nodeData(type_node).node;
        return is_arch_sized_type(tree, child);
    }

    // Handle pointer types (e.g., *usize, []usize)
    if (tree.fullPtrType(type_node)) |ptr| {
        return is_arch_sized_type(tree, ptr.ast.child_type);
    }

    // Handle grouped expressions
    if (tag == .grouped_expression) {
        const child = tree.nodeData(type_node).node_and_token[0];
        return is_arch_sized_type(tree, child);
    }

    // Check if it's a usize or isize identifier
    if (tag == .identifier) {
        const token = tree.nodes.items(.main_token)[@intFromEnum(type_node)];
        const name = tree.tokenSlice(token);
        return std.mem.eql(u8, name, "usize") or std.mem.eql(u8, name, "isize");
    }

    return false;
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

fn count_lines_over_limit(file_metrics: *const metrics.FileMetrics, limit: u32) u32 {
    assert(limit > 0);
    var count: u32 = 0;
    for (file_metrics.line_lengths.items) |line_length| {
        if (line_length > limit) {
            count += 1;
        }
    }
    return count;
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

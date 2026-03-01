const std = @import("std");
const assert = std.debug.assert;
const graph = @import("../graph.zig");
const ast_walk = @import("../ast_walk.zig");
const rules = @import("../rules.zig");
const file_cache = @import("file_cache.zig");
const diagnostics = @import("diagnostics.zig");

const phase_queue_bound_limit: usize = 32768;
const append_diag = diagnostics.append;
const Result = diagnostics.Result;

pub const PhaseSets = struct {
    green: *std.StringHashMap(void),
    red: *std.StringHashMap(void),
};

pub fn seed_green_and_red(
    allocator: std.mem.Allocator,
    call_graph: *const graph.CallGraph,
    parsed_files: *const file_cache.Cache,
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
    try seed_red_from_runtime_loops(allocator, call_graph, parsed_files, phase_sets.red);
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
    parsed_files: *const file_cache.Cache,
    red: *std.StringHashMap(void),
) !void {
    assert(call_graph.files.items.len <= call_graph.files.capacity);
    assert(red.count() <= call_graph.nodes.count());
    for (call_graph.files.items) |file_path| {
        assert(file_path.len > 0);
        const parsed = parsed_files.get(file_path) orelse return error.MissingParsedFile;

        var function_names = std.StringHashMap(void).init(allocator);
        defer function_names.deinit();
        try collect_runtime_loop_function_names(&parsed.tree, &function_names);

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

pub fn detect_recursion(
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
                try diagnostics.append_pair(
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

fn file_from_canonical(canonical: []const u8) []const u8 {
    assert(canonical.len > 0);
    if (canonical.len == 0) return "";
    const sep = std.mem.indexOf(u8, canonical, "::") orelse return canonical;
    return canonical[0..sep];
}

const std = @import("std");
const ast_walk = @import("../ast_walk.zig");
const roles = @import("roles.zig");
const call_expr = @import("call_expr.zig");
const assert = std.debug.assert;

const Ast = std.zig.Ast;

const QueueBoundFacts = struct {
    has_queue_growth_call: bool = false,
    has_queue_bound_guard: bool = false,
};

const QueueBoundVisitCtx = struct {
    role_index: *roles.SemanticIndex,
    facts: *QueueBoundFacts,
};

pub fn loop_has_unbounded_queue_growth(
    role_index: *roles.SemanticIndex,
    cond_expr: Ast.Node.Index,
    body_node: Ast.Node.Index,
) bool {
    assert(role_index.tree.nodes.len > 0);
    if (role_index.tree.nodes.len == 0) return false;

    const tree = role_index.tree;
    assert(body_node == .root or @intFromEnum(body_node) < tree.nodes.len);
    if (body_node == .root or @intFromEnum(body_node) >= tree.nodes.len) return false;

    var facts: QueueBoundFacts = .{};
    if (cond_expr != .root) {
        assert(cond_expr == .root or @intFromEnum(cond_expr) < tree.nodes.len);
        if (cond_expr != .root and @intFromEnum(cond_expr) >= tree.nodes.len) return false;

        if (expr_has_explicit_queue_bound_guard(role_index, cond_expr)) {
            facts.has_queue_bound_guard = true;
        }
    }
    collect_queue_bound_facts(role_index, body_node, &facts);
    return facts.has_queue_growth_call and !facts.has_queue_bound_guard;
}

fn collect_queue_bound_facts(
    role_index: *roles.SemanticIndex,
    node: Ast.Node.Index,
    facts: *QueueBoundFacts,
) void {
    assert(node == .root or @intFromEnum(node) < role_index.tree.nodes.len);
    const tree = role_index.tree;
    if (node == .root or @intFromEnum(node) >= tree.nodes.len) return;
    var ctx = QueueBoundVisitCtx{ .role_index = role_index, .facts = facts };
    ast_walk.walk(tree, node, &ctx, queue_bound_visit_node) catch |err| {
        std.debug.panic("queue-bound walk failed: {}", .{err});
    };
}

fn queue_bound_visit_node(
    tree: *const Ast,
    node: Ast.Node.Index,
    ctx_opaque: *anyopaque,
) anyerror!void {
    const ctx: *QueueBoundVisitCtx = @ptrCast(@alignCast(ctx_opaque));
    assert(node == .root or @intFromEnum(node) < tree.nodes.len);
    assert(ctx.role_index.tree == tree);
    const tag = tree.nodes.items(.tag)[@intFromEnum(node)];
    if (is_call_tag(tag)) {
        queue_bound_note_call(tree, node, ctx);
        return;
    }
    if (is_if_tag(tag)) {
        const full = tree.fullIf(node) orelse return;
        queue_bound_note_cond_guard(ctx, full.ast.cond_expr);
        return;
    }
    if (is_while_tag(tag)) {
        const full = tree.fullWhile(node) orelse return;
        queue_bound_note_cond_guard(ctx, full.ast.cond_expr);
    }
}

fn queue_bound_note_call(tree: *const Ast, node: Ast.Node.Index, ctx: *QueueBoundVisitCtx) void {
    var call_buf: [1]Ast.Node.Index = undefined;
    const call = tree.fullCall(&call_buf, node) orelse return;
    if (is_queue_growth_call(ctx.role_index, call.ast.fn_expr)) {
        ctx.facts.has_queue_growth_call = true;
    }
}

fn queue_bound_note_cond_guard(ctx: *QueueBoundVisitCtx, cond_expr: Ast.Node.Index) void {
    if (expr_has_explicit_queue_bound_guard(ctx.role_index, cond_expr)) {
        ctx.facts.has_queue_bound_guard = true;
    }
}

fn is_call_tag(tag: Ast.Node.Tag) bool {
    return tag == .call or
        tag == .call_comma or
        tag == .call_one or
        tag == .call_one_comma;
}

fn is_if_tag(tag: Ast.Node.Tag) bool {
    return switch (tag) {
        .@"if", .if_simple => true,
        else => false,
    };
}

fn is_while_tag(tag: Ast.Node.Tag) bool {
    return switch (tag) {
        .@"while", .while_simple, .while_cont => true,
        else => false,
    };
}

fn is_queue_growth_call(role_index: *roles.SemanticIndex, fn_expr: Ast.Node.Index) bool {
    const tree = role_index.tree;
    assert(tree.nodes.items(.main_token).len == tree.nodes.len);
    assert(fn_expr == .root or @intFromEnum(fn_expr) < tree.nodes.len);
    var path: [6][]const u8 = undefined;
    var len: u8 = 0;
    call_expr.collect_call_path(tree, fn_expr, &path, &len);
    if (len == 0) return false;

    const leaf = path[@as(usize, len - 1)];
    if (std.mem.eql(u8, leaf, "enqueue") or std.mem.eql(u8, leaf, "tryEnqueue")) {
        return true;
    }

    const growth_like = std.mem.eql(u8, leaf, "append") or
        std.mem.eql(u8, leaf, "appendSlice") or
        std.mem.eql(u8, leaf, "appendAssumeCapacity") or
        std.mem.eql(u8, leaf, "put") or
        std.mem.eql(u8, leaf, "putAssumeCapacity") or
        std.mem.eql(u8, leaf, "putNoClobber") or
        std.mem.eql(u8, leaf, "push") or
        std.mem.eql(u8, leaf, "pushBack") or
        std.mem.eql(u8, leaf, "add");
    if (!growth_like) return false;

    const receiver = call_expr.call_receiver_identifier(tree, fn_expr) orelse return false;
    const role_mask = role_index.symbol_role_mask_for_identifier_cached(receiver);
    if (!roles.token_has_queue_role_hint(receiver)) return false;
    if (roles.has_role(role_mask, roles.role_queue)) return true;
    return roles.has_role(role_mask, roles.role_data_plane);
}

fn expr_has_explicit_queue_bound_guard(
    role_index: *roles.SemanticIndex,
    cond_node: Ast.Node.Index,
) bool {
    const tree = role_index.tree;
    if (cond_node == .root or @intFromEnum(cond_node) >= tree.nodes.len) return false;
    return expr_contains_queue_bound_comparison(role_index, cond_node);
}

fn expr_contains_queue_bound_comparison(
    role_index: *roles.SemanticIndex,
    node: Ast.Node.Index,
) bool {
    const tree = role_index.tree;
    assert(tree.nodes.items(.tag).len == tree.nodes.len);
    assert(node == .root or @intFromEnum(node) < tree.nodes.len);
    if (node == .root or @intFromEnum(node) >= tree.nodes.len) return false;
    const tag = tree.nodes.items(.tag)[@intFromEnum(node)];
    switch (tag) {
        .less_than,
        .less_or_equal,
        .greater_than,
        .greater_or_equal,
        => {
            const lhs, const rhs = tree.nodeData(node).node_and_node;
            return comparison_has_queue_bound_evidence(role_index, lhs, rhs);
        },
        .bool_and,
        .bool_or,
        .@"catch",
        .@"orelse",
        => {
            const lhs, const rhs = tree.nodeData(node).node_and_node;
            return expr_contains_queue_bound_comparison(role_index, lhs) or
                expr_contains_queue_bound_comparison(role_index, rhs);
        },
        .grouped_expression,
        .unwrap_optional,
        => {
            const child = tree.nodeData(node).node_and_token[0];
            return expr_contains_queue_bound_comparison(role_index, child);
        },
        .@"try",
        .@"comptime",
        .bool_not,
        => {
            const child = tree.nodeData(node).node;
            return expr_contains_queue_bound_comparison(role_index, child);
        },
        else => return false,
    }
}

fn comparison_has_queue_bound_evidence(
    role_index: *roles.SemanticIndex,
    lhs: Ast.Node.Index,
    rhs: Ast.Node.Index,
) bool {
    const lhs_queue_metric = expr_is_queue_size_metric(role_index, lhs);
    const rhs_queue_metric = expr_is_queue_size_metric(role_index, rhs);
    const lhs_bound = expr_has_bound_evidence(role_index, lhs);
    const rhs_bound = expr_has_bound_evidence(role_index, rhs);

    return (lhs_queue_metric and (rhs_bound or rhs_queue_metric)) or
        (rhs_queue_metric and (lhs_bound or lhs_queue_metric));
}

fn expr_is_queue_size_metric(role_index: *roles.SemanticIndex, node: Ast.Node.Index) bool {
    const tree = role_index.tree;
    assert(tree.nodes.items(.main_token).len == tree.nodes.len);
    assert(node == .root or @intFromEnum(node) < tree.nodes.len);
    if (node == .root or @intFromEnum(node) >= tree.nodes.len) return false;
    const tag = tree.nodes.items(.tag)[@intFromEnum(node)];
    switch (tag) {
        .field_access => {
            const owner, const field_token = tree.nodeData(node).node_and_token;
            const field_name = tree.tokenSlice(field_token);
            const queue_metric = is_queue_metric_field_name(field_name);
            if (queue_metric and owner_is_queue_metric(role_index, owner)) {
                return true;
            }
            return expr_is_queue_size_metric(role_index, owner);
        },
        .call,
        .call_comma,
        .call_one,
        .call_one_comma,
        => {
            var call_buf: [1]Ast.Node.Index = undefined;
            const call = tree.fullCall(&call_buf, node) orelse return false;
            return expr_is_queue_metric_method_call(role_index, call.ast.fn_expr);
        },
        .grouped_expression,
        .unwrap_optional,
        => {
            const child = tree.nodeData(node).node_and_token[0];
            return expr_is_queue_size_metric(role_index, child);
        },
        .@"try",
        .@"comptime",
        => {
            const child = tree.nodeData(node).node;
            return expr_is_queue_size_metric(role_index, child);
        },
        else => return false,
    }
}

fn owner_is_queue_metric(role_index: *roles.SemanticIndex, owner: Ast.Node.Index) bool {
    if (expr_is_queue_reference(role_index, owner)) return true;
    return expr_is_queue_items_access(role_index, owner);
}

fn expr_is_queue_metric_method_call(
    role_index: *roles.SemanticIndex,
    fn_expr: Ast.Node.Index,
) bool {
    const tree = role_index.tree;
    assert(tree.nodes.items(.main_token).len == tree.nodes.len);
    assert(fn_expr == .root or @intFromEnum(fn_expr) < tree.nodes.len);
    if (fn_expr == .root or @intFromEnum(fn_expr) >= tree.nodes.len) return false;
    if (tree.nodes.items(.tag)[@intFromEnum(fn_expr)] != .field_access) return false;

    const receiver, const method_token = tree.nodeData(fn_expr).node_and_token;
    const method_name = tree.tokenSlice(method_token);
    if (!is_queue_metric_field_name(method_name)) return false;
    return expr_is_queue_reference(role_index, receiver) or
        expr_is_queue_items_access(role_index, receiver);
}

fn expr_is_queue_items_access(role_index: *roles.SemanticIndex, node: Ast.Node.Index) bool {
    const tree = role_index.tree;
    assert(tree.nodes.items(.main_token).len == tree.nodes.len);
    assert(node == .root or @intFromEnum(node) < tree.nodes.len);
    if (node == .root or @intFromEnum(node) >= tree.nodes.len) return false;
    const tag = tree.nodes.items(.tag)[@intFromEnum(node)];
    switch (tag) {
        .field_access => {
            const owner, const field_token = tree.nodeData(node).node_and_token;
            if (!std.mem.eql(u8, tree.tokenSlice(field_token), "items")) return false;
            return expr_is_queue_reference(role_index, owner);
        },
        .grouped_expression,
        .unwrap_optional,
        => {
            const child = tree.nodeData(node).node_and_token[0];
            return expr_is_queue_items_access(role_index, child);
        },
        .@"try",
        .@"comptime",
        => {
            const child = tree.nodeData(node).node;
            return expr_is_queue_items_access(role_index, child);
        },
        else => return false,
    }
}

fn expr_is_queue_reference(role_index: *roles.SemanticIndex, node: Ast.Node.Index) bool {
    const tree = role_index.tree;
    const name = root_identifier_in_expr(tree, node) orelse return false;
    const role_mask = role_index.symbol_role_mask_for_identifier_cached(name);
    if (roles.has_role(role_mask, roles.role_queue)) return true;
    return roles.token_has_queue_role_hint(name) and
        roles.has_role(role_mask, roles.role_data_plane);
}

fn root_identifier_in_expr(tree: *const Ast, node: Ast.Node.Index) ?[]const u8 {
    assert(tree.nodes.items(.main_token).len == tree.nodes.len);
    assert(node == .root or @intFromEnum(node) < tree.nodes.len);
    if (node == .root or @intFromEnum(node) >= tree.nodes.len) return null;

    var current = node;
    while (current != .root and @intFromEnum(current) < tree.nodes.len) {
        const tag = tree.nodes.items(.tag)[@intFromEnum(current)];
        switch (tag) {
            .identifier => {
                const token = tree.nodes.items(.main_token)[@intFromEnum(current)];
                return tree.tokenSlice(token);
            },
            .field_access,
            .grouped_expression,
            .unwrap_optional,
            => {
                current = tree.nodeData(current).node_and_token[0];
            },
            .@"try",
            .@"comptime",
            => {
                current = tree.nodeData(current).node;
            },
            else => return null,
        }
    }

    return null;
}

fn expr_has_bound_evidence(role_index: *roles.SemanticIndex, node: Ast.Node.Index) bool {
    const tree = role_index.tree;
    assert(tree.nodes.items(.main_token).len == tree.nodes.len);
    assert(node == .root or @intFromEnum(node) < tree.nodes.len);
    if (node == .root or @intFromEnum(node) >= tree.nodes.len) return false;
    const tag = tree.nodes.items(.tag)[@intFromEnum(node)];
    switch (tag) {
        .number_literal => return true,
        .identifier => {
            const token = tree.nodes.items(.main_token)[@intFromEnum(node)];
            return token_has_bound_hint(tree.tokenSlice(token));
        },
        .field_access => {
            const owner, const field_token = tree.nodeData(node).node_and_token;
            const field_name = tree.tokenSlice(field_token);
            if (std.mem.eql(u8, field_name, "capacity") and
                expr_is_queue_reference(role_index, owner))
            {
                return true;
            }
            if (token_has_bound_hint(field_name)) {
                return true;
            }
            return expr_has_bound_evidence(role_index, owner);
        },
        .grouped_expression,
        .unwrap_optional,
        => {
            const child = tree.nodeData(node).node_and_token[0];
            return expr_has_bound_evidence(role_index, child);
        },
        .@"try",
        .@"comptime",
        => {
            const child = tree.nodeData(node).node;
            return expr_has_bound_evidence(role_index, child);
        },
        else => return false,
    }
}

fn is_queue_metric_field_name(name: []const u8) bool {
    assert(name.len > 0);
    if (name.len == 0) return false;
    return std.mem.eql(u8, name, "len") or
        std.mem.eql(u8, name, "count") or
        std.mem.eql(u8, name, "capacity");
}

fn token_has_bound_hint(token: []const u8) bool {
    assert(token.len > 0);
    if (token.len == 0) return false;
    return roles.contains_ascii_case_insensitive(token, "max") or
        roles.contains_ascii_case_insensitive(token, "cap") or
        roles.contains_ascii_case_insensitive(token, "limit") or
        roles.contains_ascii_case_insensitive(token, "bound") or
        roles.contains_ascii_case_insensitive(token, "quota");
}

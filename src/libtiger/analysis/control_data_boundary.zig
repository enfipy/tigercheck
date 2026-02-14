const std = @import("std");
const ast_walk = @import("../ast_walk.zig");
const roles = @import("roles.zig");
const call_expr = @import("call_expr.zig");
const assert = std.debug.assert;

const Ast = std.zig.Ast;

const ControlDataBoundaryFacts = struct {
    call_count: u16 = 0,
    has_control_plane_call: bool = false,
    has_data_plane_call: bool = false,
    has_boundary_call: bool = false,
};

const ControlDataBoundaryVisitCtx = struct {
    role_index: *roles.SemanticIndex,
    facts: *ControlDataBoundaryFacts,
};

pub fn has_violation(
    role_index: *roles.SemanticIndex,
    body_node: Ast.Node.Index,
) bool {
    assert(role_index.tree.nodes.len > 0);
    const tree = role_index.tree;
    if (body_node == .root or @intFromEnum(body_node) >= tree.nodes.len) return false;

    var facts: ControlDataBoundaryFacts = .{};
    collect_facts(role_index, body_node, &facts);

    if (facts.call_count < 2) return false;
    if (!facts.has_control_plane_call or !facts.has_data_plane_call) return false;
    if (facts.has_boundary_call) return false;
    return true;
}

fn collect_facts(
    role_index: *roles.SemanticIndex,
    node: Ast.Node.Index,
    facts: *ControlDataBoundaryFacts,
) void {
    const tree = role_index.tree;
    if (node == .root or @intFromEnum(node) >= tree.nodes.len) return;
    var ctx = ControlDataBoundaryVisitCtx{ .role_index = role_index, .facts = facts };
    ast_walk.walk(tree, node, &ctx, visit_node) catch |err| {
        std.debug.panic("plane-boundary walk failed: {}", .{err});
    };
}

fn visit_node(
    tree: *const Ast,
    node: Ast.Node.Index,
    ctx_opaque: *anyopaque,
) anyerror!void {
    const ctx: *ControlDataBoundaryVisitCtx = @ptrCast(@alignCast(ctx_opaque));
    const tag = tree.nodes.items(.tag)[@intFromEnum(node)];
    switch (tag) {
        .call,
        .call_comma,
        .call_one,
        .call_one_comma,
        => {
            var call_buf: [1]Ast.Node.Index = undefined;
            const call = tree.fullCall(&call_buf, node) orelse return;
            collect_call(ctx.role_index, call.ast.fn_expr, ctx.facts);
        },
        else => {},
    }
}

fn collect_call(
    role_index: *roles.SemanticIndex,
    fn_expr: Ast.Node.Index,
    facts: *ControlDataBoundaryFacts,
) void {
    assert(facts.call_count <= std.math.maxInt(u16));
    assert(fn_expr == .root or @intFromEnum(fn_expr) < role_index.tree.nodes.len);
    const tree = role_index.tree;
    var path: [6][]const u8 = undefined;
    var len: u8 = 0;
    call_expr.collect_call_path(tree, fn_expr, &path, &len);
    if (len == 0) return;

    if (facts.call_count < std.math.maxInt(u16)) {
        facts.call_count += 1;
    }

    var hits = RoleHits{};

    const leaf_name = path[@as(usize, len - 1)];
    const callee_facts = role_index.function_role_facts_by_name_cached(leaf_name);
    role_mask_note_hits(callee_facts.role_mask, &hits);

    if (call_expr.call_receiver_identifier(tree, fn_expr)) |receiver| {
        const role_mask = role_index.symbol_role_mask_for_identifier_cached(receiver);
        role_mask_note_hits(role_mask, &hits);
    }

    for (path[0..len]) |segment| {
        note_segment_hits(role_index, segment, &hits);
    }

    if (hits.control) facts.has_control_plane_call = true;
    if (hits.data) facts.has_data_plane_call = true;
    if (hits.boundary) facts.has_boundary_call = true;
}

const RoleHits = struct {
    control: bool = false,
    data: bool = false,
    boundary: bool = false,
};

fn role_mask_note_hits(role_mask: roles.SymbolRoleMask, hits: *RoleHits) void {
    if (roles.has_role(role_mask, roles.role_control_plane)) hits.control = true;
    if (roles.has_role(role_mask, roles.role_data_plane)) hits.data = true;
    if (roles.has_role(role_mask, roles.role_boundary)) hits.boundary = true;
}

fn note_segment_hits(role_index: *roles.SemanticIndex, segment: []const u8, hits: *RoleHits) void {
    assert(segment.len > 0);
    assert(role_index.tree.nodes.len > 0);
    if (segment.len == 0) return;
    const segment_roles = role_index.symbol_role_mask_for_identifier_cached(segment);

    if (roles.has_role(segment_roles, roles.role_control_plane)) {
        hits.control = true;
    } else if (roles.token_has_control_role_hint(segment)) {
        hits.control = true;
    }

    if (roles.has_role(segment_roles, roles.role_data_plane)) {
        hits.data = true;
    } else if (roles.token_has_data_role_hint(segment)) {
        hits.data = true;
    }

    if (roles.has_role(segment_roles, roles.role_boundary)) {
        hits.boundary = true;
    } else if (roles.token_has_boundary_role_hint(segment)) {
        hits.boundary = true;
    }
}

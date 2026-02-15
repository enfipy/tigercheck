const std = @import("std");
const ast_walk = @import("../ast_walk.zig");
const roles = @import("roles.zig");
const call_expr = @import("call_expr.zig");
const assert = std.debug.assert;

const Ast = std.zig.Ast;

const LoopPacingFacts = struct {
    has_external_event_call: bool = false,
    has_direct_mutation_call: bool = false,
    has_batch_boundary_call: bool = false,
};

const LoopPacingVisitCtx = struct {
    role_index: *roles.SemanticIndex,
    facts: *LoopPacingFacts,
};

const LoopPacingCallInfo = struct {
    leaf_name: []const u8,
    parent_name: []const u8,
    leaf_roles: roles.SymbolRoleMask,
    parent_roles: roles.SymbolRoleMask,
    receiver_roles: roles.SymbolRoleMask,
    callee_roles: roles.SymbolRoleMask,
    receiver_mutable: bool,
    callee_has_mutable_self: bool,
};

pub fn loop_has_unpaced_external_mutation(
    role_index: *roles.SemanticIndex,
    body_node: Ast.Node.Index,
) bool {
    const tree = role_index.tree;
    if (body_node == .root or @intFromEnum(body_node) >= tree.nodes.len) return false;
    var facts: LoopPacingFacts = .{};
    collect_loop_pacing_facts(role_index, body_node, &facts);
    return facts.has_external_event_call and
        facts.has_direct_mutation_call and
        !facts.has_batch_boundary_call;
}

fn collect_loop_pacing_facts(
    role_index: *roles.SemanticIndex,
    node: Ast.Node.Index,
    facts: *LoopPacingFacts,
) void {
    const tree = role_index.tree;
    if (node == .root or @intFromEnum(node) >= tree.nodes.len) return;
    var ctx = LoopPacingVisitCtx{ .role_index = role_index, .facts = facts };
    ast_walk.walk(tree, node, &ctx, loop_pacing_visit_node) catch |err| {
        std.debug.panic("loop-pacing walk failed: {}", .{err});
    };
}

fn loop_pacing_visit_node(
    tree: *const Ast,
    node: Ast.Node.Index,
    ctx_opaque: *anyopaque,
) anyerror!void {
    const ctx: *LoopPacingVisitCtx = @ptrCast(@alignCast(ctx_opaque));
    const tag = tree.nodes.items(.tag)[@intFromEnum(node)];
    switch (tag) {
        .call,
        .call_comma,
        .call_one,
        .call_one_comma,
        => {
            var call_buf: [1]Ast.Node.Index = undefined;
            const call = tree.fullCall(&call_buf, node) orelse return;
            track_loop_pacing_call(ctx.role_index, call.ast.fn_expr, ctx.facts);
        },
        else => {},
    }
}

fn track_loop_pacing_call(
    role_index: *roles.SemanticIndex,
    fn_expr: Ast.Node.Index,
    facts: *LoopPacingFacts,
) void {
    const tree = role_index.tree;
    assert(fn_expr == .root or @intFromEnum(fn_expr) < tree.nodes.len);
    assert(tree.nodes.items(.main_token).len == tree.nodes.len);
    var path: [6][]const u8 = undefined;
    var len: u8 = 0;
    call_expr.collect_call_path(tree, fn_expr, &path, &len);
    if (len == 0) return;

    const leaf = path[@as(usize, len - 1)];
    var parent: []const u8 = "";
    if (len > 1) {
        parent = path[@as(usize, len - 2)];
    }

    const leaf_roles = role_index.symbol_role_mask_for_identifier_cached(leaf);
    assert(leaf_roles <= std.math.maxInt(roles.SymbolRoleMask));
    var parent_roles: roles.SymbolRoleMask = 0;
    if (parent.len > 0) {
        parent_roles = role_index.symbol_role_mask_for_identifier_cached(parent);
    }
    const receiver = call_expr.call_receiver_identifier(tree, fn_expr);
    var receiver_roles: roles.SymbolRoleMask = 0;
    if (receiver) |name| {
        receiver_roles = role_index.symbol_role_mask_for_identifier_cached(name);
    }
    const callee_facts = role_index.function_role_facts_by_name_cached(leaf);
    const call_info = LoopPacingCallInfo{
        .leaf_name = leaf,
        .parent_name = parent,
        .leaf_roles = leaf_roles,
        .parent_roles = parent_roles,
        .receiver_roles = receiver_roles,
        .callee_roles = callee_facts.role_mask,
        .receiver_mutable = receiver != null and callee_facts.has_mutable_self_param,
        .callee_has_mutable_self = callee_facts.has_mutable_self_param,
    };

    if (call_is_external_event(call_info)) {
        facts.has_external_event_call = true;
    }
    if (call_is_direct_mutation(call_info)) {
        facts.has_direct_mutation_call = true;
    }
    if (call_is_batch_boundary(call_info)) {
        facts.has_batch_boundary_call = true;
    }
}

fn call_is_external_event(info: LoopPacingCallInfo) bool {
    assert(info.leaf_name.len > 0);
    assert(info.parent_name.len <= std.math.maxInt(u32));
    if (roles.has_role(info.receiver_roles, roles.role_event_source)) return true;
    if (roles.has_role(info.parent_roles, roles.role_event_source)) return true;
    if (roles.has_role(info.leaf_roles, roles.role_event_source)) return true;
    if (roles.has_role(info.callee_roles, roles.role_event_source)) return true;

    const name = info.leaf_name;
    if (is_external_event_call_name(name)) {
        return roles.token_has_event_role_hint(info.parent_name);
    }
    return false;
}

fn is_external_event_call_name(name: []const u8) bool {
    assert(name.len > 0);
    if (name.len == 0) return false;
    if (std.mem.eql(u8, name, "next")) return true;
    return std.mem.eql(u8, name, "recv") or
        std.mem.eql(u8, name, "receive") or
        std.mem.eql(u8, name, "accept") or
        std.mem.eql(u8, name, "poll") or
        std.mem.eql(u8, name, "wait_event") or
        std.mem.eql(u8, name, "next_event") or
        std.mem.eql(u8, name, "read_event");
}

fn call_is_direct_mutation(info: LoopPacingCallInfo) bool {
    if (receiver_is_mutable_data_role(info.receiver_roles)) {
        if (info.receiver_mutable) return true;
        return is_likely_mutating_method_name(info.leaf_name);
    }

    if (!info.callee_has_mutable_self) return false;
    return receiver_is_mutable_data_role(info.callee_roles);
}

fn receiver_is_mutable_data_role(role_mask: roles.SymbolRoleMask) bool {
    if (roles.has_role(role_mask, roles.role_queue)) return true;
    return roles.has_role(role_mask, roles.role_data_plane);
}

fn is_likely_mutating_method_name(name: []const u8) bool {
    assert(name.len > 0);
    if (name.len == 0) return false;
    return std.mem.eql(u8, name, "append") or
        std.mem.eql(u8, name, "appendSlice") or
        std.mem.eql(u8, name, "appendAssumeCapacity") or
        std.mem.eql(u8, name, "put") or
        std.mem.eql(u8, name, "putAssumeCapacity") or
        std.mem.eql(u8, name, "putNoClobber") or
        std.mem.eql(u8, name, "insert") or
        std.mem.eql(u8, name, "remove") or
        std.mem.eql(u8, name, "swapRemove") or
        std.mem.eql(u8, name, "orderedRemove") or
        std.mem.eql(u8, name, "write") or
        std.mem.eql(u8, name, "writeAll") or
        std.mem.eql(u8, name, "set") or
        std.mem.eql(u8, name, "update") or
        std.mem.eql(u8, name, "create") or
        std.mem.eql(u8, name, "destroy");
}

fn call_is_batch_boundary(info: LoopPacingCallInfo) bool {
    assert(info.leaf_name.len > 0);
    if (roles.has_role(info.receiver_roles, roles.role_boundary)) return true;
    if (roles.has_role(info.parent_roles, roles.role_boundary)) return true;
    if (roles.has_role(info.leaf_roles, roles.role_boundary)) return true;
    if (roles.has_role(info.callee_roles, roles.role_boundary)) return true;
    return is_batch_boundary_call_name(info.leaf_name);
}

fn is_batch_boundary_call_name(name: []const u8) bool {
    assert(name.len > 0);
    if (name.len == 0) return false;
    return std.mem.eql(u8, name, "flush") or
        std.mem.eql(u8, name, "drain") or
        std.mem.eql(u8, name, "drainAll") or
        std.mem.eql(u8, name, "commit") or
        std.mem.eql(u8, name, "applyBatch") or
        std.mem.eql(u8, name, "apply_batch") or
        std.mem.eql(u8, name, "processBatch") or
        std.mem.eql(u8, name, "process_batch") or
        std.mem.eql(u8, name, "submitBatch") or
        std.mem.eql(u8, name, "submit_batch");
}

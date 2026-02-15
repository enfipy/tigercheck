const std = @import("std");
const Ast = std.zig.Ast;
const assert = std.debug.assert;

pub fn collect_call_path(
    tree: *const Ast,
    expr_node: Ast.Node.Index,
    path: *[6][]const u8,
    len: *u8,
) void {
    assert(tree.nodes.items(.main_token).len == tree.nodes.len);
    assert(len.* <= path.len);
    if (expr_node == .root or @intFromEnum(expr_node) >= tree.nodes.len) return;
    const tag = tree.nodes.items(.tag)[@intFromEnum(expr_node)];
    if (tag == .identifier) {
        const token = tree.nodes.items(.main_token)[@intFromEnum(expr_node)];
        if (@as(usize, len.*) >= path.len) return;
        path[@as(usize, len.*)] = tree.tokenSlice(token);
        len.* += 1;
        return;
    }

    if (tag == .field_access) {
        const lhs, const field_token = tree.nodeData(expr_node).node_and_token;
        collect_call_path(tree, lhs, path, len);
        if (@as(usize, len.*) >= path.len) return;
        path[@as(usize, len.*)] = tree.tokenSlice(field_token);
        len.* += 1;
        return;
    }

    if (tag == .unwrap_optional or tag == .grouped_expression) {
        const child = tree.nodeData(expr_node).node_and_token[0];
        collect_call_path(tree, child, path, len);
        return;
    }

    if (is_unary_wrapper_tag(tag)) {
        const child = tree.nodeData(expr_node).node;
        collect_call_path(tree, child, path, len);
    }
}

fn is_unary_wrapper_tag(tag: Ast.Node.Tag) bool {
    assert(@intFromEnum(tag) < @typeInfo(Ast.Node.Tag).@"enum".fields.len);
    assert(@typeInfo(Ast.Node.Tag).@"enum".fields.len > 0);
    if (tag == .@"try") return true;
    if (tag == .@"comptime") return true;
    if (tag == .deref) return true;
    if (tag == .bool_not) return true;
    if (tag == .negation) return true;
    if (tag == .bit_not) return true;
    if (tag == .negation_wrap) return true;
    if (tag == .address_of) return true;
    return tag == .optional_type;
}

pub fn call_receiver_identifier(tree: *const Ast, fn_expr: Ast.Node.Index) ?[]const u8 {
    assert(tree.nodes.items(.tag).len == tree.nodes.len);
    assert(fn_expr == .root or @intFromEnum(fn_expr) < tree.nodes.len);
    if (fn_expr == .root or @intFromEnum(fn_expr) >= tree.nodes.len) return null;
    const tag = tree.nodes.items(.tag)[@intFromEnum(fn_expr)];
    if (tag != .field_access) return null;

    var lhs = tree.nodeData(fn_expr).node_and_token[0];
    while (lhs != .root and @intFromEnum(lhs) < tree.nodes.len) {
        const lhs_tag = tree.nodes.items(.tag)[@intFromEnum(lhs)];
        if (lhs_tag == .identifier) {
            const tok = tree.nodes.items(.main_token)[@intFromEnum(lhs)];
            return tree.tokenSlice(tok);
        }
        if (lhs_tag == .grouped_expression or lhs_tag == .unwrap_optional) {
            lhs = tree.nodeData(lhs).node_and_token[0];
            continue;
        }
        if (lhs_tag == .@"try" or lhs_tag == .@"comptime") {
            lhs = tree.nodeData(lhs).node;
            continue;
        }
        if (lhs_tag == .field_access) {
            lhs = tree.nodeData(lhs).node_and_token[0];
            continue;
        }
        return null;
    }
    return null;
}

test "collect_call_path handles grouped try receiver" {
    const source =
        \\const S = struct {
        \\    fn run(self: *S) void {
        \\        _ = self;
        \\    }
        \\};
        \\
        \\fn get(s: *S) !*S {
        \\    return s;
        \\}
        \\
        \\test "grouped-try receiver" {
        \\    var s = S{};
        \\    (try get(&s)).run();
        \\}
    ;

    var tree = try Ast.parse(std.testing.allocator, source, .zig);
    defer tree.deinit(std.testing.allocator);

    var matched_call = false;

    const tags = tree.nodes.items(.tag);
    var raw_index: usize = 0;
    while (raw_index < tree.nodes.len) : (raw_index += 1) {
        const node: Ast.Node.Index = @enumFromInt(raw_index);
        const tag = tags[raw_index];
        const call_tag = tag == .call or
            tag == .call_comma or
            tag == .call_one or
            tag == .call_one_comma;
        if (!call_tag) continue;

        var call_buf: [1]Ast.Node.Index = undefined;
        const full = tree.fullCall(&call_buf, node) orelse continue;
        const fn_expr = full.ast.fn_expr;
        if (fn_expr == .root or @intFromEnum(fn_expr) >= tree.nodes.len) continue;
        if (tags[@intFromEnum(fn_expr)] != .field_access) continue;

        const field_token = tree.nodeData(fn_expr).node_and_token[1];
        if (!std.mem.eql(u8, tree.tokenSlice(field_token), "run")) continue;

        var path: [6][]const u8 = undefined;
        var len: u8 = 0;
        collect_call_path(&tree, fn_expr, &path, &len);
        try std.testing.expect(len > 0);
        try std.testing.expect(std.mem.eql(u8, path[@as(usize, len - 1)], "run"));
        matched_call = true;
        break;
    }

    try std.testing.expect(matched_call);
}

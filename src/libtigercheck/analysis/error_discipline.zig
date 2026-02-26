const std = @import("std");
const ast_walk = @import("../ast_walk.zig");
const graph = @import("../graph.zig");
const diagnostics = @import("diagnostics.zig");
const kernel_context = @import("kernel_context.zig");

const assert = std.debug.assert;
const append_diag = diagnostics.append;
const Result = diagnostics.Result;

pub fn detect_error_handling_violations(
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

pub fn detect_error_handling_in_function(
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

    var ctx = kernel_context.ErrorDisciplineVisitCtx{
        .file_path = file_path,
        .result = result,
    };
    try ast_walk.walk(tree, body_node, &ctx, visit_error_node);
}

fn visit_error_node(
    tree: *const std.zig.Ast,
    node: std.zig.Ast.Node.Index,
    ctx_opaque: *anyopaque,
) anyerror!void {
    const ctx: *kernel_context.ErrorDisciplineVisitCtx = @ptrCast(@alignCast(ctx_opaque));
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

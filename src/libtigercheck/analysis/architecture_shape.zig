const std = @import("std");
const assert = std.debug.assert;
const roles = @import("roles.zig");
const control_data_boundary = @import("control_data_boundary.zig");
const diagnostics = @import("diagnostics.zig");

const append_diag = diagnostics.append;
const Result = diagnostics.Result;

pub fn detect_with_parsed(
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


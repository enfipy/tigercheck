const std = @import("std");
const assert = std.debug.assert;
const Ast = std.zig.Ast;
const metrics = @import("metrics.zig");
const ast_walk = @import("ast_walk.zig");
const Count = u32;

pub const FunctionAssertFacts = struct {
    canonical_name: []const u8,
    file_path: []const u8,
    function_name: []const u8,
    assert_count: Count,
    has_relevant_params: bool,
    has_split_assert: bool,
    has_param_precondition: bool,
    has_positive_param_assert: bool,
    has_negative_param_guard: bool,
    has_unpaired_path_assert: bool,
    has_negative_invariant: bool,
};

pub const FileAssertFacts = struct {
    functions: std.array_list.Managed(FunctionAssertFacts),

    pub fn init(allocator: std.mem.Allocator) FileAssertFacts {
        return .{ .functions = std.array_list.Managed(FunctionAssertFacts).init(allocator) };
    }

    pub fn deinit(self: *FileAssertFacts) void {
        const allocator = self.functions.allocator;
        for (self.functions.items) |f| {
            allocator.free(f.canonical_name);
            allocator.free(f.function_name);
        }
        self.functions.deinit();
    }
};

const ParamInfo = struct {
    names: std.array_list.Managed([]const u8),

    fn init(allocator: std.mem.Allocator) ParamInfo {
        return .{ .names = std.array_list.Managed([]const u8).init(allocator) };
    }

    fn deinit(self: *ParamInfo) void {
        self.names.deinit();
    }

    fn has_any(self: *const ParamInfo) bool {
        return self.names.items.len > 0;
    }
};

const AssertWalkState = struct {
    assert_count: Count,
    has_split_assert: bool,
    has_negative_invariant: bool,
};

const ParamAssertCoverage = struct {
    has_param_precondition: bool = false,
    has_positive_param_assert: bool = false,
    has_negative_param_guard: bool = false,
    has_unpaired_path_assert: bool = false,
};

pub fn analyze_file(
    allocator: std.mem.Allocator,
    file_path: []const u8,
    file_metrics: *const metrics.FileMetrics,
) !FileAssertFacts {
    assert(file_path.len > 0);
    if (file_path.len == 0) return error.InvalidInputPath;
    const source = try std.Io.Dir.cwd().readFileAllocOptions(
        std.Options.debug_io,
        file_path,
        allocator,
        std.Io.Limit.limited(16 * 1024 * 1024),
        .of(u8),
        0,
    );
    defer allocator.free(source);

    const tree = try Ast.parse(allocator, source, .zig);
    defer {
        var t = tree;
        t.deinit(allocator);
    }

    return analyze_file_with_parsed(allocator, file_path, file_metrics, &tree);
}

pub fn analyze_file_with_parsed(
    allocator: std.mem.Allocator,
    file_path: []const u8,
    file_metrics: *const metrics.FileMetrics,
    tree: *const Ast,
) !FileAssertFacts {
    assert(file_path.len > 0);
    assert(tree.nodes.len > 0);
    if (file_path.len == 0) return error.InvalidInputPath;
    if (tree.nodes.len == 0) return error.InvalidAst;
    var out = FileAssertFacts.init(allocator);
    errdefer out.deinit();

    _ = file_metrics;
    for (tree.rootDecls()) |decl| {
        if (tree.nodes.items(.tag)[@intFromEnum(decl)] != .fn_decl) continue;

        var fn_buf: [1]Ast.Node.Index = undefined;
        const proto = tree.fullFnProto(&fn_buf, decl) orelse continue;
        const name_token = proto.name_token orelse continue;
        const function_name = tree.tokenSlice(name_token);
        const body_node = tree.nodeData(decl).node_and_node[1];
        if (body_node == .root) continue;
        const function_name_owned = try allocator.dupe(u8, function_name);

        var params = ParamInfo.init(allocator);
        defer params.deinit();
        try collect_relevant_param_names(tree, proto, &params);

        var walk_state = AssertWalkState{
            .assert_count = 0,
            .has_split_assert = false,
            .has_negative_invariant = false,
        };
        var coverage: ParamAssertCoverage = .{};

        try collect_assert_facts(
            allocator,
            tree,
            body_node,
            &params,
            &walk_state,
            &coverage,
        );

        const canonical_name =
            try std.fmt.allocPrint(allocator, "{s}::{s}", .{ file_path, function_name });
        try out.functions.append(.{
            .canonical_name = canonical_name,
            .file_path = file_path,
            .function_name = function_name_owned,
            .assert_count = walk_state.assert_count,
            .has_relevant_params = params.has_any(),
            .has_split_assert = walk_state.has_split_assert,
            .has_param_precondition = if (params.has_any())
                coverage.has_param_precondition
            else
                true,
            .has_positive_param_assert = coverage.has_positive_param_assert,
            .has_negative_param_guard = coverage.has_negative_param_guard,
            .has_unpaired_path_assert = coverage.has_unpaired_path_assert,
            .has_negative_invariant = walk_state.has_negative_invariant,
        });
    }

    return out;
}

fn collect_relevant_param_names(
    tree: *const Ast,
    proto: Ast.full.FnProto,
    params: *ParamInfo,
) !void {
    assert(tree.nodes.items(.main_token).len == tree.nodes.len);
    var it = proto.iterate(tree);
    while (it.next()) |param| {
        if (param.name_token == null) continue;
        const type_expr = param.type_expr orelse continue;
        if (!is_relevant_param_type(tree, type_expr)) continue;
        try params.names.append(tree.tokenSlice(param.name_token.?));
    }
}

fn is_relevant_param_type(tree: *const Ast, type_node: Ast.Node.Index) bool {
    if (type_node == .root or @intFromEnum(type_node) >= tree.nodes.len) return false;
    const tag = tree.nodes.items(.tag)[@intFromEnum(type_node)];

    // Optional values can carry null/none and should be guarded.
    if (tag == .optional_type) {
        return true;
    }

    // Require preconditions for slice-like inputs only.
    // Plain pointers (*T / *const T) are non-null in Zig, so they do not need
    // null guards and should not trigger this rule.
    if (tree.fullPtrType(type_node)) |ptr| {
        return ptr.size == .slice;
    }

    return false;
}

fn collect_assert_facts(
    allocator: std.mem.Allocator,
    tree: *const Ast,
    body_node: Ast.Node.Index,
    params: *const ParamInfo,
    walk_state: *AssertWalkState,
    coverage: *ParamAssertCoverage,
) !void {
    assert(tree.nodes.len > 0);
    assert(body_node == .root or @intFromEnum(body_node) < tree.nodes.len);
    var visited = ast_walk.NodeVisited.init(allocator);
    defer visited.deinit();

    var ctx = AssertVisitCtx{ .walk_state = walk_state };
    try ast_walk.walk_with_options(
        tree,
        body_node,
        &ctx,
        assert_visit_node,
        .{ .visited = &visited },
    );

    if (!params.has_any()) {
        coverage.has_param_precondition = true;
        return;
    }

    var first_statements = std.array_list.Managed(Ast.Node.Index).init(allocator);
    defer first_statements.deinit();
    try collect_first_statements(tree, body_node, &first_statements, 10);

    for (first_statements.items) |stmt| {
        if (assert_references_params(tree, stmt, params)) {
            coverage.has_param_precondition = true;
            coverage.has_positive_param_assert = true;
        }
        if (statement_is_param_guard(tree, stmt, params)) {
            coverage.has_param_precondition = true;
            coverage.has_negative_param_guard = true;
        }

        if (if_statement_has_unpaired_param_assert(tree, stmt, params)) {
            coverage.has_unpaired_path_assert = true;
        }
    }
}

const AssertVisitCtx = struct {
    walk_state: *AssertWalkState,
};

fn assert_visit_node(
    tree: *const Ast,
    node: Ast.Node.Index,
    ctx_opaque: *anyopaque,
) anyerror!ast_walk.VisitDecision {
    const ctx: *AssertVisitCtx = @ptrCast(@alignCast(ctx_opaque));
    try process_assert_call_node(tree, node, ctx.walk_state);
    return .visit_children;
}

fn if_statement_has_unpaired_param_assert(
    tree: *const Ast,
    node: Ast.Node.Index,
    params: *const ParamInfo,
) bool {
    assert(tree.nodes.items(.main_token).len == tree.nodes.len);
    assert(node == .root or @intFromEnum(node) < tree.nodes.len);
    if (node == .root or @intFromEnum(node) >= tree.nodes.len) return false;
    const tag = tree.nodes.items(.tag)[@intFromEnum(node)];
    if (tag != .@"if" and tag != .if_simple) return false;

    const full = tree.fullIf(node) orelse return false;
    if (!expr_references_any_param(tree, full.ast.cond_expr, params)) return false;
    const else_expr = full.ast.else_expr.unwrap() orelse return false;

    const then_has_param_assert = branch_contains_param_assert(tree, full.ast.then_expr, params);
    const else_has_param_assert = branch_contains_param_assert(tree, else_expr, params);
    return then_has_param_assert != else_has_param_assert;
}

fn branch_contains_param_assert(
    tree: *const Ast,
    node: Ast.Node.Index,
    params: *const ParamInfo,
) bool {
    if (node == .root or @intFromEnum(node) >= tree.nodes.len) return false;
    var ctx = BranchAssertCtx{
        .tree = tree,
        .params = params,
        .found = false,
    };
    ast_walk.walk_with_options(tree, node, &ctx, branch_assert_visit_node, .{}) catch {
        return false;
    };
    return ctx.found;
}

const BranchAssertCtx = struct {
    tree: *const Ast,
    params: *const ParamInfo,
    found: bool,
};

fn branch_assert_visit_node(
    tree: *const Ast,
    node: Ast.Node.Index,
    ctx_opaque: *anyopaque,
) anyerror!ast_walk.VisitDecision {
    const ctx: *BranchAssertCtx = @ptrCast(@alignCast(ctx_opaque));
    assert(ctx.tree == tree);
    if (assert_references_params(tree, node, ctx.params)) {
        ctx.found = true;
        return .stop;
    }
    return .visit_children;
}

fn statement_is_param_guard(tree: *const Ast, node: Ast.Node.Index, params: *const ParamInfo) bool {
    assert(tree.nodes.len > 0);
    assert(node == .root or @intFromEnum(node) < tree.nodes.len);
    if (node == .root or @intFromEnum(node) >= tree.nodes.len) return false;

    const tag = tree.nodes.items(.tag)[@intFromEnum(node)];
    if (tag == .@"if" or tag == .if_simple) {
        return if_statement_is_param_guard(tree, node, params);
    }

    return switch (tag) {
        .global_var_decl,
        .local_var_decl,
        .simple_var_decl,
        .aligned_var_decl,
        => var_decl_is_param_guard(tree, node, params),
        else => false,
    };
}

fn if_statement_is_param_guard(
    tree: *const Ast,
    if_node: Ast.Node.Index,
    params: *const ParamInfo,
) bool {
    assert(if_node == .root or @intFromEnum(if_node) < tree.nodes.len);
    assert(tree.nodes.items(.main_token).len == tree.nodes.len);
    const full = tree.fullIf(if_node) orelse return false;
    if (!expr_references_any_param(tree, full.ast.cond_expr, params)) return false;
    if (branch_is_early_exit(tree, full.ast.then_expr)) return true;
    const else_expr = full.ast.else_expr.unwrap() orelse return false;
    return branch_is_early_exit(tree, else_expr);
}

fn var_decl_is_param_guard(
    tree: *const Ast,
    decl_node: Ast.Node.Index,
    params: *const ParamInfo,
) bool {
    const var_decl = tree.fullVarDecl(decl_node) orelse return false;
    const init_node = var_decl.ast.init_node.unwrap() orelse return false;
    return init_expr_is_param_guard(tree, init_node, params);
}

fn init_expr_is_param_guard(
    tree: *const Ast,
    init_node: Ast.Node.Index,
    params: *const ParamInfo,
) bool {
    assert(tree.nodes.len > 0);
    assert(tree.nodes.items(.main_token).len == tree.nodes.len);
    if (init_node == .root or @intFromEnum(init_node) >= tree.nodes.len) return false;
    const tag = tree.nodes.items(.tag)[@intFromEnum(init_node)];

    switch (tag) {
        .grouped_expression => {
            const child = tree.nodeData(init_node).node_and_token[0];
            return init_expr_is_param_guard(tree, child, params);
        },
        .@"try" => {
            const child = tree.nodeData(init_node).node;
            return init_expr_is_param_guard(tree, child, params);
        },
        .@"orelse", .@"catch" => {
            const pair = tree.nodeData(init_node).node_and_node;
            if (!expr_references_any_param(tree, pair[0], params)) return false;
            return branch_is_early_exit(tree, pair[1]);
        },
        else => return false,
    }
}

fn branch_is_early_exit(tree: *const Ast, node: Ast.Node.Index) bool {
    assert(tree.nodes.len > 0);
    assert(node == .root or @intFromEnum(node) < tree.nodes.len);
    if (node == .root or @intFromEnum(node) >= tree.nodes.len) return false;

    const tag = tree.nodes.items(.tag)[@intFromEnum(node)];
    return switch (tag) {
        .@"return", .unreachable_literal => true,
        .grouped_expression => branch_is_early_exit(tree, tree.nodeData(node).node_and_token[0]),
        .@"try" => branch_is_early_exit(tree, tree.nodeData(node).node),
        .@"catch", .@"orelse" => branch_is_early_exit(tree, tree.nodeData(node).node_and_node[1]),
        .block, .block_semicolon => block_branch_is_early_exit(tree, node),
        .block_two, .block_two_semicolon => block_two_branch_is_early_exit(tree, node),
        .@"if", .if_simple => if_branch_is_early_exit(tree, node),
        else => false,
    };
}

fn block_branch_is_early_exit(tree: *const Ast, node: Ast.Node.Index) bool {
    const stmts = tree.extraDataSlice(tree.nodeData(node).extra_range, Ast.Node.Index);
    if (stmts.len == 0) return false;
    return branch_is_early_exit(tree, stmts[stmts.len - 1]);
}

fn block_two_branch_is_early_exit(tree: *const Ast, node: Ast.Node.Index) bool {
    const first, const second = tree.nodeData(node).opt_node_and_opt_node;
    if (second.unwrap()) |second_node| {
        return branch_is_early_exit(tree, second_node);
    }
    if (first.unwrap()) |first_node| {
        return branch_is_early_exit(tree, first_node);
    }
    return false;
}

fn if_branch_is_early_exit(tree: *const Ast, node: Ast.Node.Index) bool {
    const full = tree.fullIf(node) orelse return false;
    if (!branch_is_early_exit(tree, full.ast.then_expr)) return false;
    const else_expr = full.ast.else_expr.unwrap() orelse return false;
    return branch_is_early_exit(tree, else_expr);
}

fn collect_first_statements(
    tree: *const Ast,
    body_node: Ast.Node.Index,
    out: *std.array_list.Managed(Ast.Node.Index),
    limit: Count,
) !void {
    assert(tree.nodes.len > 0);
    assert(tree.nodes.items(.main_token).len == tree.nodes.len);
    if (body_node == .root or @intFromEnum(body_node) >= tree.nodes.len) return;

    const tag = tree.nodes.items(.tag)[@intFromEnum(body_node)];
    switch (tag) {
        .block,
        .block_semicolon,
        => try append_block_statements_with_limit(tree, body_node, out, limit),
        .block_two,
        .block_two_semicolon,
        => try append_block_two_statements_with_limit(tree, body_node, out, limit),
        else => {
            try append_statement_if_room(out, body_node, limit);
        },
    }
}

fn append_statement_if_room(
    out: *std.array_list.Managed(Ast.Node.Index),
    stmt: Ast.Node.Index,
    limit: Count,
) !void {
    if (out.items.len >= @as(usize, limit)) return;
    try out.append(stmt);
}

fn append_block_statements_with_limit(
    tree: *const Ast,
    body_node: Ast.Node.Index,
    out: *std.array_list.Managed(Ast.Node.Index),
    limit: Count,
) !void {
    const stmts = tree.extraDataSlice(tree.nodeData(body_node).extra_range, Ast.Node.Index);
    for (stmts) |stmt| {
        if (out.items.len >= @as(usize, limit)) return;
        try out.append(stmt);
    }
}

fn append_block_two_statements_with_limit(
    tree: *const Ast,
    body_node: Ast.Node.Index,
    out: *std.array_list.Managed(Ast.Node.Index),
    limit: Count,
) !void {
    const first, const second = tree.nodeData(body_node).opt_node_and_opt_node;
    if (first.unwrap()) |first_node| {
        try append_statement_if_room(out, first_node, limit);
    }
    if (second.unwrap()) |second_node| {
        try append_statement_if_room(out, second_node, limit);
    }
}

fn process_assert_call_node(
    tree: *const Ast,
    node: Ast.Node.Index,
    walk_state: *AssertWalkState,
) !void {
    assert(node == .root or @intFromEnum(node) < tree.nodes.len);
    assert(tree.nodes.items(.main_token).len == tree.nodes.len);
    const tag = tree.nodes.items(.tag)[@intFromEnum(node)];
    switch (tag) {
        .call,
        .call_comma,
        .call_one,
        .call_one_comma,
        => {
            var call_buf: [1]Ast.Node.Index = undefined;
            const call = tree.fullCall(&call_buf, node) orelse return;
            if (!is_assert_call(tree, call.ast.fn_expr)) return;

            walk_state.assert_count += 1;
            if (call.ast.params.len == 0) return;

            const param = call.ast.params[0];
            if (expr_has_bool_and(tree, param)) {
                walk_state.has_split_assert = true;
            }
            if (is_negative_comparison(tree, param)) {
                walk_state.has_negative_invariant = true;
            }
        },
        else => {},
    }
}

fn assert_references_params(tree: *const Ast, node: Ast.Node.Index, params: *const ParamInfo) bool {
    assert(node == .root or @intFromEnum(node) < tree.nodes.len);
    assert(tree.nodes.items(.main_token).len == tree.nodes.len);
    if (node == .root or @intFromEnum(node) >= tree.nodes.len) return false;

    switch (tree.nodes.items(.tag)[@intFromEnum(node)]) {
        .call,
        .call_comma,
        .call_one,
        .call_one_comma,
        => {
            var call_buf: [1]Ast.Node.Index = undefined;
            const call = tree.fullCall(&call_buf, node) orelse return false;
            if (!is_assert_call(tree, call.ast.fn_expr)) return false;
            if (call.ast.params.len == 0) return false;
            return expr_references_any_param(tree, call.ast.params[0], params);
        },
        else => return false,
    }
}

fn expr_references_any_param(
    tree: *const Ast,
    node: Ast.Node.Index,
    params: *const ParamInfo,
) bool {
    assert(node == .root or @intFromEnum(node) < tree.nodes.len);
    assert(tree.nodes.items(.main_token).len == tree.nodes.len);
    if (node == .root or @intFromEnum(node) >= tree.nodes.len) return false;
    const tag = tree.nodes.items(.tag)[@intFromEnum(node)];
    if (tag == .identifier) {
        const token = tree.nodes.items(.main_token)[@intFromEnum(node)];
        const ident = tree.tokenSlice(token);
        for (params.names.items) |name| {
            if (std.mem.eql(u8, ident, name)) return true;
        }
    }
    if (expr_param_ref_from_unary_like(tree, node, tag, params)) return true;
    if (expr_param_ref_from_node_child(tree, node, tag, params)) return true;
    if (expr_param_ref_from_binary(tree, node, tag, params)) return true;
    return false;
}

fn expr_param_ref_from_unary_like(
    tree: *const Ast,
    node: Ast.Node.Index,
    tag: Ast.Node.Tag,
    params: *const ParamInfo,
) bool {
    switch (tag) {
        .field_access,
        .unwrap_optional,
        .grouped_expression,
        => {
            const child = tree.nodeData(node).node_and_token[0];
            return expr_references_any_param(tree, child, params);
        },
        .@"try" => {
            const child = tree.nodeData(node).node;
            return expr_references_any_param(tree, child, params);
        },
        else => return false,
    }
}

fn expr_param_ref_from_node_child(
    tree: *const Ast,
    node: Ast.Node.Index,
    tag: Ast.Node.Tag,
    params: *const ParamInfo,
) bool {
    switch (tag) {
        .deref,
        .bool_not,
        .negation,
        .bit_not,
        .negation_wrap,
        .address_of,
        .optional_type,
        => {
            const child = tree.nodeData(node).node;
            return expr_references_any_param(tree, child, params);
        },
        else => return false,
    }
}

fn expr_param_ref_from_binary(
    tree: *const Ast,
    node: Ast.Node.Index,
    tag: Ast.Node.Tag,
    params: *const ParamInfo,
) bool {
    switch (tag) {
        .add,
        .sub,
        .mul,
        .div,
        .mod,
        .shl,
        .shr,
        .bit_and,
        .bit_or,
        .bit_xor,
        .bool_and,
        .bool_or,
        .less_than,
        .less_or_equal,
        .greater_than,
        .greater_or_equal,
        .equal_equal,
        .bang_equal,
        .array_access,
        .@"catch",
        .@"orelse",
        .merge_error_sets,
        .error_union,
        .array_cat,
        .array_mult,
        .add_wrap,
        .sub_wrap,
        .mul_wrap,
        .add_sat,
        .sub_sat,
        .mul_sat,
        .shl_sat,
        .switch_range,
        .array_type,
        => {
            const pair = tree.nodeData(node).node_and_node;
            return expr_references_any_param(tree, pair[0], params) or
                expr_references_any_param(tree, pair[1], params);
        },
        else => return false,
    }
}

fn is_assert_call(tree: *const Ast, fn_expr: Ast.Node.Index) bool {
    var path: [4][]const u8 = undefined;
    var len: u8 = 0;
    collect_call_path(tree, fn_expr, &path, &len);
    if (len == 0) return false;
    return std.mem.eql(u8, path[@as(usize, len - 1)], "assert");
}

fn collect_call_path(
    tree: *const Ast,
    expr_node: Ast.Node.Index,
    path: *[4][]const u8,
    len: *u8,
) void {
    assert(tree.nodes.len > 0);
    assert(tree.nodes.items(.main_token).len == tree.nodes.len);
    if (expr_node == .root or @intFromEnum(expr_node) >= tree.nodes.len) return;
    switch (tree.nodes.items(.tag)[@intFromEnum(expr_node)]) {
        .identifier => {
            const token = tree.nodes.items(.main_token)[@intFromEnum(expr_node)];
            if (@as(usize, len.*) < path.len) {
                path[@as(usize, len.*)] = tree.tokenSlice(token);
                len.* += 1;
            }
        },
        .field_access => {
            const lhs, const field_token = tree.nodeData(expr_node).node_and_token;
            collect_call_path(tree, lhs, path, len);
            if (@as(usize, len.*) < path.len) {
                path[@as(usize, len.*)] = tree.tokenSlice(field_token);
                len.* += 1;
            }
        },
        .grouped_expression,
        .unwrap_optional,
        => {
            const child = tree.nodeData(expr_node).node_and_token[0];
            collect_call_path(tree, child, path, len);
        },
        .@"try",
        .@"comptime",
        => {
            const child = tree.nodeData(expr_node).node;
            collect_call_path(tree, child, path, len);
        },
        else => {},
    }
}

fn expr_has_bool_and(tree: *const Ast, node: Ast.Node.Index) bool {
    assert(node == .root or @intFromEnum(node) < tree.nodes.len);
    assert(tree.nodes.items(.main_token).len == tree.nodes.len);
    if (node == .root or @intFromEnum(node) >= tree.nodes.len) return false;
    if (tree.nodes.items(.tag)[@intFromEnum(node)] == .bool_and) return true;
    const tag = tree.nodes.items(.tag)[@intFromEnum(node)];
    if (is_comparison_or_boolean_tag(tag)) {
        const pair = tree.nodeData(node).node_and_node;
        if (expr_has_bool_and(tree, pair[0])) return true;
        if (expr_has_bool_and(tree, pair[1])) return true;
        return false;
    }
    if (is_node_and_token_wrapper_tag(tag)) {
        const child = tree.nodeData(node).node_and_token[0];
        return expr_has_bool_and(tree, child);
    }
    if (is_node_wrapper_tag(tag)) {
        const child = tree.nodeData(node).node;
        return expr_has_bool_and(tree, child);
    }
    return false;
}

fn is_comparison_or_boolean_tag(tag: Ast.Node.Tag) bool {
    return switch (tag) {
        .bool_and,
        .bool_or,
        .less_than,
        .less_or_equal,
        .greater_than,
        .greater_or_equal,
        .equal_equal,
        .bang_equal,
        => true,
        else => false,
    };
}

fn is_node_and_token_wrapper_tag(tag: Ast.Node.Tag) bool {
    return switch (tag) {
        .field_access,
        .unwrap_optional,
        .grouped_expression,
        => true,
        else => false,
    };
}

fn is_node_wrapper_tag(tag: Ast.Node.Tag) bool {
    return switch (tag) {
        .@"try",
        .@"comptime",
        => true,
        else => false,
    };
}

// TS14_POSITIVE_INVARIANTS: Detect negated comparison patterns like !(x < y)
fn is_negative_comparison(tree: *const Ast, node: Ast.Node.Index) bool {
    assert(node == .root or @intFromEnum(node) < tree.nodes.len);
    assert(tree.nodes.items(.main_token).len == tree.nodes.len);
    if (node == .root or @intFromEnum(node) >= tree.nodes.len) return false;

    const tag = tree.nodes.items(.tag)[@intFromEnum(node)];

    // Check for !(comparison) patterns
    if (tag == .bool_not) {
        const inner = tree.nodeData(node).node;
        if (inner != .root and @intFromEnum(inner) < tree.nodes.len) {
            const inner_tag = tree.nodes.items(.tag)[@intFromEnum(inner)];
            // Check if inner is a comparison
            switch (inner_tag) {
                .less_than, .less_or_equal, .greater_than, .greater_or_equal => return true,
                else => {},
            }
        }
    }

    // Check for != comparison patterns (but not != null which is idiomatic)
    if (tag == .bang_equal) {
        const pair = tree.nodeData(node).node_and_node;
        // Check if neither side is null literal
        const left_is_null = is_null_literal(tree, pair[0]);
        const right_is_null = is_null_literal(tree, pair[1]);
        if (!left_is_null and !right_is_null) {
            return true;
        }
    }

    // Recursively check grouped expressions
    if (tag == .grouped_expression) {
        const child = tree.nodeData(node).node_and_token[0];
        return is_negative_comparison(tree, child);
    }

    return false;
}

fn is_null_literal(tree: *const Ast, node: Ast.Node.Index) bool {
    assert(tree.nodes.items(.main_token).len == tree.nodes.len);
    assert(node == .root or @intFromEnum(node) < tree.nodes.len);
    if (node == .root or @intFromEnum(node) >= tree.nodes.len) return false;
    const tag = tree.nodes.items(.tag)[@intFromEnum(node)];
    if (tag != .identifier) return false;
    const token = tree.nodes.items(.main_token)[@intFromEnum(node)];
    const name = tree.tokenSlice(token);
    return std.mem.eql(u8, name, "null");
}

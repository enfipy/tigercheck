const std = @import("std");
const ast_walk = @import("../ast_walk.zig");
const call_expr = @import("call_expr.zig");
const roles = @import("roles.zig");
const diagnostics = @import("diagnostics.zig");
const event_pacing = @import("event_pacing.zig");
const queue_growth_bounds = @import("queue_growth_bounds.zig");
const kernel_context = @import("kernel_context.zig");

const assert = std.debug.assert;
const collect_call_path = call_expr.collect_call_path;
const append_diag = diagnostics.append;
const Result = diagnostics.Result;

pub const implicit_walk_limit_message =
    "AST walk safety limit exceeded during implicit control-flow analysis; fail closed";
pub const tb03_copy_api_message =
    "raw copy API is banned (`@memcpy`, `std.mem.copyForwards`, `std.mem.copyBackwards`); " ++
    "use explicit copy helper (`stdx.copy_disjoint`, `stdx.copy_left`, or `stdx.copy_right`)";

pub fn detect_implicit_alloc_and_switch_else(
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

    try detect_implicit_alloc_and_switch_else_with_limit(
        allocator,
        tree,
        source,
        node,
        file_path,
        result,
        4000,
    );
}

pub fn detect_implicit_alloc_and_switch_else_with_limit(
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
    assert(max_nodes > 0);
    if (source.len == 0) return;
    if (file_path.len == 0) return;
    if (max_nodes == 0) return;
    if (node == .root or @intFromEnum(node) >= tree.nodes.len) return;

    var role_index = roles.SemanticIndex.init(allocator, tree);
    defer role_index.deinit();

    var ctx = kernel_context.ImplicitVisitCtx{
        .tree = tree,
        .role_index = &role_index,
        .source = source,
        .file_path = file_path,
        .enable_tigerbeetle_profile_rules = is_tigerbeetle_style_target_file(file_path),
        .result = result,
    };

    ast_walk.walk_with_options(tree, node, &ctx, implicit_visit_node, .{
        .max_nodes = @as(usize, max_nodes),
    }) catch |err| {
        if (err == error.AstWalkLimit) {
            try append_diag(
                result,
                .critical,
                .N02_BOUNDED_LOOPS,
                file_path,
                implicit_walk_limit_message,
            );
            return;
        }
        return err;
    };
}

fn implicit_visit_node(
    tree: *const std.zig.Ast,
    node: std.zig.Ast.Node.Index,
    ctx_opaque: *anyopaque,
) anyerror!ast_walk.VisitDecision {
    const ctx: *kernel_context.ImplicitVisitCtx = @ptrCast(@alignCast(ctx_opaque));
    assert(node == .root or @intFromEnum(node) < tree.nodes.len);
    assert(tree.nodes.items(.main_token).len == tree.nodes.len);
    if (node == .root or @intFromEnum(node) >= tree.nodes.len) return .visit_children;
    kernel_context.assert_implicit_walk_ctx(ctx);
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
    ctx: *kernel_context.ImplicitVisitCtx,
    call_node: std.zig.Ast.Node.Index,
    fn_expr: std.zig.Ast.Node.Index,
) anyerror!void {
    kernel_context.assert_implicit_walk_ctx(ctx);
    assert(call_node == .root or @intFromEnum(call_node) < ctx.tree.nodes.len);
    assert(fn_expr == .root or @intFromEnum(fn_expr) < ctx.tree.nodes.len);
    if (is_page_allocator_call(ctx.tree, fn_expr)) {
        try diagnostics.append_pair(
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
    ctx: *kernel_context.ImplicitVisitCtx,
    node: std.zig.Ast.Node.Index,
) anyerror!void {
    kernel_context.assert_implicit_walk_ctx(ctx);
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

fn append_ts11_paced_control_diag(
    role_index: *roles.SemanticIndex,
    body_node: std.zig.Ast.Node.Index,
    file_path: []const u8,
    result: *Result,
) anyerror!void {
    assert(file_path.len > 0);
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    if (file_path.len == 0) return;
    const evidence =
        event_pacing.loop_unpaced_external_mutation_evidence(role_index, body_node) orelse return;
    var boundary: []const u8 = "none";
    if (evidence.batch_boundary_call.len > 0) {
        boundary = evidence.batch_boundary_call;
    }
    const msg = try std.fmt.allocPrint(
        result.diagnostics.allocator,
        "TS11_PACED_CONTROL: require explicit batch boundary before state updates " ++
            "(external call=`{s}`, mutation call=`{s}`, boundary call=`{s}`)",
        .{
            evidence.external_event_call,
            evidence.direct_mutation_call,
            boundary,
        },
    );
    try append_diag(result, .warning, .TS11_PACED_CONTROL, file_path, msg);
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
    if (!is_self_analysis_source_file(file_path)) {
        try append_ts11_paced_control_diag(role_index, full.ast.then_expr, file_path, result);
    }
    if (is_literal_true(tree, full.ast.cond_expr)) {
        try diagnostics.append_pair(
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
    if (!is_self_analysis_source_file(file_path)) {
        try append_ts11_paced_control_diag(role_index, full.ast.then_expr, file_path, result);
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

    const segment = source[if_start..then_end];
    return std.mem.indexOfScalar(u8, segment, '\n') == null;
}

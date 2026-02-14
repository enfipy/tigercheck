const std = @import("std");
const assert = std.debug.assert;
const Ast = std.zig.Ast;
const ast_walk = @import("ast_walk.zig");
const Count = u32;

pub const FunctionMetric = struct {
    canonical_name: []const u8,
    file_path: []const u8,
    function_name: []const u8,
    statement_count: Count,
    logical_line_count: Count,
    cyclomatic_complexity: Count,
    comptime_max_nesting: Count,
    comptime_node_count: Count,
    total_node_count: Count,
};

const ComptimeStats = struct {
    max_nesting: Count,
    comptime_node_count: Count,
    total_node_count: Count,
};

pub const FileMetrics = struct {
    functions: std.array_list.Managed(FunctionMetric),
    lines_exceeding_limit: std.array_list.Managed(Count),
    line_lengths: std.array_list.Managed(Count),
    max_line_length: Count,

    pub fn init(allocator: std.mem.Allocator) FileMetrics {
        return .{
            .functions = std.array_list.Managed(FunctionMetric).init(allocator),
            .lines_exceeding_limit = std.array_list.Managed(Count).init(allocator),
            .line_lengths = std.array_list.Managed(Count).init(allocator),
            .max_line_length = 0,
        };
    }

    pub fn deinit(self: *FileMetrics) void {
        const allocator = self.functions.allocator;
        for (self.functions.items) |f| {
            allocator.free(f.canonical_name);
            allocator.free(f.function_name);
        }
        self.functions.deinit();
        self.lines_exceeding_limit.deinit();
        self.line_lengths.deinit();
    }
};

pub fn analyze_file(allocator: std.mem.Allocator, file_path: []const u8) !FileMetrics {
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

    return analyze_file_with_parsed(allocator, file_path, source, &tree);
}

pub fn analyze_file_with_parsed(
    allocator: std.mem.Allocator,
    file_path: []const u8,
    source: []const u8,
    tree: *const Ast,
) !FileMetrics {
    assert(file_path.len > 0);
    assert(std.mem.indexOfScalar(u8, source, 0) == null);
    if (file_path.len == 0) return error.InvalidInputPath;
    var out = FileMetrics.init(allocator);
    errdefer out.deinit();

    // TS26_LINE_LENGTH: Check line lengths
    try check_line_lengths(&out, source);

    for (tree.rootDecls()) |decl| {
        if (tree.nodes.items(.tag)[@intFromEnum(decl)] != .fn_decl) continue;

        var fn_buf: [1]Ast.Node.Index = undefined;
        const proto = tree.fullFnProto(&fn_buf, decl) orelse continue;
        const name_token = proto.name_token orelse continue;
        const function_name = try allocator.dupe(u8, tree.tokenSlice(name_token));

        const body_node = tree.nodeData(decl).node_and_node[1];
        if (body_node == .root) continue;

        var statement_count: Count = 0;
        try count_statements(allocator, tree, body_node, &statement_count);

        var cyclomatic_complexity: Count = 1;
        try count_complexity(allocator, tree, body_node, &cyclomatic_complexity);

        const logical_line_count = count_logical_lines(tree, source, body_node);

        const comptime_stats = try collect_comptime_stats(allocator, tree, body_node);

        const canonical_name =
            try std.fmt.allocPrint(allocator, "{s}::{s}", .{ file_path, function_name });
        try out.functions.append(.{
            .canonical_name = canonical_name,
            .file_path = file_path,
            .function_name = function_name,
            .statement_count = statement_count,
            .logical_line_count = logical_line_count,
            .cyclomatic_complexity = cyclomatic_complexity,
            .comptime_max_nesting = comptime_stats.max_nesting,
            .comptime_node_count = comptime_stats.comptime_node_count,
            .total_node_count = comptime_stats.total_node_count,
        });
    }

    return out;
}

fn count_statements(
    allocator: std.mem.Allocator,
    tree: *const Ast,
    node: Ast.Node.Index,
    statement_count: *Count,
) !void {
    var visited = ast_walk.NodeVisited.init(allocator);
    defer visited.deinit();

    var ctx = StatementVisitCtx{ .statement_count = statement_count };
    try ast_walk.walk_with_options(
        tree,
        node,
        &ctx,
        statement_visit_node,
        .{ .visited = &visited },
    );
}

const StatementVisitCtx = struct {
    statement_count: *Count,
};

fn statement_visit_node(
    tree: *const Ast,
    node: Ast.Node.Index,
    ctx_opaque: *anyopaque,
) anyerror!ast_walk.VisitDecision {
    const ctx: *StatementVisitCtx = @ptrCast(@alignCast(ctx_opaque));
    const tag = tree.nodes.items(.tag)[@intFromEnum(node)];
    if (is_logical_statement(tag)) {
        ctx.statement_count.* += 1;
    }
    return .visit_children;
}

fn count_complexity(
    allocator: std.mem.Allocator,
    tree: *const Ast,
    node: Ast.Node.Index,
    cyclomatic_complexity: *Count,
) !void {
    var visited = ast_walk.NodeVisited.init(allocator);
    defer visited.deinit();
    var ctx = ComplexityVisitCtx{ .cyclomatic_complexity = cyclomatic_complexity };
    try ast_walk.walk_with_options(
        tree,
        node,
        &ctx,
        complexity_visit_node,
        .{ .visited = &visited },
    );
}

const ComplexityVisitCtx = struct {
    cyclomatic_complexity: *Count,
};

fn complexity_visit_node(
    tree: *const Ast,
    node: Ast.Node.Index,
    ctx_opaque: *anyopaque,
) anyerror!ast_walk.VisitDecision {
    const ctx: *ComplexityVisitCtx = @ptrCast(@alignCast(ctx_opaque));
    const tag = tree.nodes.items(.tag)[@intFromEnum(node)];
    switch (tag) {
        .@"if",
        .if_simple,
        .@"while",
        .while_simple,
        .while_cont,
        .@"for",
        .for_simple,
        .@"catch",
        .@"orelse",
        .switch_case_one,
        .switch_case_inline_one,
        .switch_case,
        .switch_case_inline,
        => ctx.cyclomatic_complexity.* += 1,
        else => {},
    }
    return .visit_children;
}

fn count_logical_lines(tree: *const Ast, source: []const u8, node: Ast.Node.Index) Count {
    assert(source.len > 0);
    assert(node == .root or @intFromEnum(node) < tree.nodes.len);
    assert(std.mem.indexOfScalar(u8, source, 0) == null);
    if (source.len == 0) return 0;
    if (node == .root or @intFromEnum(node) >= tree.nodes.len) return 0;

    const first_token = tree.firstToken(node);
    const last_token = tree.lastToken(node);
    if (first_token >= tree.tokens.len or last_token >= tree.tokens.len) return 0;
    const token_starts = tree.tokens.items(.start);

    const start = token_starts[first_token];
    const end = token_starts[last_token] + tree.tokenSlice(last_token).len;
    if (end <= start or end > source.len) return 0;

    const body = source[start..end];
    return count_logical_lines_in_source(body);
}

fn count_logical_lines_in_source(source: []const u8) Count {
    assert(source.len <= std.math.maxInt(Count));
    assert(std.mem.indexOfScalar(u8, source, 0) == null);
    if (source.len == 0) return 0;
    var line_count: Count = 0;
    var line_start: usize = 0;
    var in_block_comment = false;

    var i: usize = 0;
    while (i < source.len) : (i += 1) {
        if (source[i] == '\n') {
            if (line_has_logic(source[line_start..i], &in_block_comment)) {
                line_count += 1;
            }
            line_start = i + 1;
        }
    }

    if (line_start < source.len and line_has_logic(source[line_start..], &in_block_comment)) {
        line_count += 1;
    }

    return line_count;
}

fn line_has_logic(line: []const u8, in_block_comment: *bool) bool {
    assert(line.len <= std.math.maxInt(Count));
    assert(std.mem.indexOfScalar(u8, line, 0) == null);
    if (line.len == 0) return false;
    var i: usize = 0;
    var has_content = false;
    var only_braces_or_semicolon = true;

    while (i < line.len) {
        if (in_block_comment.*) {
            if (slice_has_pair(line, @intCast(i), '*', '/')) {
                in_block_comment.* = false;
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }

        if (slice_has_pair(line, @intCast(i), '/', '*')) {
            in_block_comment.* = true;
            i += 2;
            continue;
        }

        if (slice_has_pair(line, @intCast(i), '/', '/')) {
            break;
        }

        const c = line[i];
        if (std.ascii.isWhitespace(c)) {
            i += 1;
            continue;
        }

        has_content = true;
        if (!line_char_is_brace_or_semicolon(c)) {
            only_braces_or_semicolon = false;
        }
        i += 1;
    }

    return has_content and !only_braces_or_semicolon;
}

fn slice_has_pair(line: []const u8, index_u32: u32, first: u8, second: u8) bool {
    assert(index_u32 <= line.len);
    const index: usize = @intCast(index_u32);
    if (index >= line.len) return false;
    if (index + 1 >= line.len) return false;
    if (line[index] != first) return false;
    return line[index + 1] == second;
}

fn line_char_is_brace_or_semicolon(c: u8) bool {
    if (c == '{') return true;
    if (c == '}') return true;
    return c == ';';
}

fn collect_comptime_stats(
    allocator: std.mem.Allocator,
    tree: *const Ast,
    body_node: Ast.Node.Index,
) !ComptimeStats {
    var visited = ast_walk.NodeVisited.init(allocator);
    defer visited.deinit();

    var stats = ComptimeStats{
        .max_nesting = 0,
        .comptime_node_count = 0,
        .total_node_count = 0,
    };

    var ctx = ComptimeVisitCtx{ .stats = &stats };
    try ast_walk.walk_with_hooks(
        tree,
        body_node,
        &ctx,
        .{
            .on_enter = comptime_enter_visit,
            .on_exit = comptime_exit_visit,
        },
        .{ .visited = &visited },
    );

    return stats;
}

const ComptimeVisitCtx = struct {
    stats: *ComptimeStats,
    active_boundary_depth: Count = 0,
};

fn comptime_enter_visit(
    tree: *const Ast,
    node: Ast.Node.Index,
    ctx_opaque: *anyopaque,
) anyerror!ast_walk.VisitDecision {
    const ctx: *ComptimeVisitCtx = @ptrCast(@alignCast(ctx_opaque));
    if (is_comptime_boundary(tree, node)) {
        ctx.active_boundary_depth += 1;
    }

    ctx.stats.total_node_count += 1;
    if (ctx.active_boundary_depth > 0) {
        ctx.stats.comptime_node_count += 1;
    }
    if (ctx.active_boundary_depth > ctx.stats.max_nesting) {
        ctx.stats.max_nesting = ctx.active_boundary_depth;
    }

    return .visit_children;
}

fn comptime_exit_visit(
    tree: *const Ast,
    node: Ast.Node.Index,
    ctx_opaque: *anyopaque,
) anyerror!void {
    const ctx: *ComptimeVisitCtx = @ptrCast(@alignCast(ctx_opaque));
    if (!is_comptime_boundary(tree, node)) return;
    if (ctx.active_boundary_depth > 0) {
        ctx.active_boundary_depth -= 1;
    }
}

fn is_comptime_boundary(tree: *const Ast, node: Ast.Node.Index) bool {
    if (node == .root or @intFromEnum(node) >= tree.nodes.len) return false;
    return switch (tree.nodes.items(.tag)[@intFromEnum(node)]) {
        .@"comptime" => true,
        .@"while", .while_simple, .while_cont => {
            const full = tree.fullWhile(node) orelse return false;
            return full.inline_token != null;
        },
        .@"for", .for_simple => {
            const full = tree.fullFor(node) orelse return false;
            return full.inline_token != null;
        },
        else => false,
    };
}

fn is_logical_statement(tag: Ast.Node.Tag) bool {
    return switch (tag) {
        .local_var_decl,
        .simple_var_decl,
        .aligned_var_decl,
        .assign,
        .assign_add,
        .assign_add_wrap,
        .assign_add_sat,
        .assign_sub,
        .assign_sub_wrap,
        .assign_sub_sat,
        .assign_mul,
        .assign_mul_wrap,
        .assign_mul_sat,
        .assign_div,
        .assign_mod,
        .assign_shl,
        .assign_shl_sat,
        .assign_shr,
        .assign_bit_and,
        .assign_bit_or,
        .assign_bit_xor,
        .call,
        .call_comma,
        .call_one,
        .call_one_comma,

        .@"if",
        .if_simple,
        .@"while",
        .while_simple,
        .while_cont,
        .@"for",
        .for_simple,
        .@"switch",
        .switch_comma,
        .@"return",
        .@"break",
        .@"continue",
        .@"defer",
        .@"errdefer",
        => true,
        else => false,
    };
}

fn check_line_lengths(out: *FileMetrics, source: []const u8) !void {
    assert(source.len <= std.math.maxInt(Count));
    assert(std.mem.indexOfScalar(u8, source, 0) == null);
    if (source.len == 0) return;
    const max_line_length: Count = 100;
    var line_number: Count = 1;
    var line_start: usize = 0;

    var i: usize = 0;
    while (i < source.len) : (i += 1) {
        if (source[i] == '\n') {
            const line_length: Count = @intCast(i - line_start);
            try out.line_lengths.append(line_length);
            if (line_length > out.max_line_length) {
                out.max_line_length = line_length;
            }
            if (line_length > max_line_length) {
                try out.lines_exceeding_limit.append(line_number);
            }
            line_number += 1;
            line_start = i + 1;
        }
    }

    // Check last line if no trailing newline
    if (line_start < source.len) {
        const line_length: Count = @intCast(source.len - line_start);
        try out.line_lengths.append(line_length);
        if (line_length > out.max_line_length) {
            out.max_line_length = line_length;
        }
        if (line_length > max_line_length) {
            try out.lines_exceeding_limit.append(line_number);
        }
    }
}

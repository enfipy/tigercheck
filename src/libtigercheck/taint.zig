const std = @import("std");
const assert = std.debug.assert;
const Ast = std.zig.Ast;
const graph = @import("graph.zig");
const ast_walk = @import("ast_walk.zig");

pub const FunctionFacts = struct {
    canonical_name: []const u8,
    file_path: []const u8,
    function_name: []const u8,
    is_method: bool,
    has_forbidden_alloc: bool,
    has_unbounded_loop: bool,
};

pub const FileFacts = struct {
    functions: std.array_list.Managed(FunctionFacts),

    pub fn init(allocator: std.mem.Allocator) FileFacts {
        return .{ .functions = std.array_list.Managed(FunctionFacts).init(allocator) };
    }

    pub fn deinit(self: *FileFacts) void {
        const allocator = self.functions.allocator;
        for (self.functions.items) |f| {
            allocator.free(f.canonical_name);
            allocator.free(f.function_name);
        }
        self.functions.deinit();
    }
};

const ContainerRange = struct {
    first: Ast.TokenIndex,
    last: Ast.TokenIndex,
};

const FunctionWalkState = struct {
    safe_consts: std.StringHashMap(void),
    bounded_iterators: std.StringHashMap(void),
    has_forbidden_alloc: bool,
    has_unbounded_loop: bool,
};

const CallPath = struct {
    parts: [8][]const u8 = undefined,
    len: usize = 0,

    fn append(self: *CallPath, value: []const u8) void {
        if (self.len < self.parts.len) {
            self.parts[self.len] = value;
            self.len += 1;
        }
    }

    fn last(self: *const CallPath) ?[]const u8 {
        if (self.len == 0) return null;
        return self.parts[self.len - 1];
    }
};

pub fn analyze_file(
    allocator: std.mem.Allocator,
    call_graph: *const graph.CallGraph,
    file_path: []const u8,
) !FileFacts {
    assert(file_path.len > 0);
    assert(call_graph.files.items.len <= call_graph.files.capacity);
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

    return analyze_file_with_parsed(allocator, call_graph, file_path, &tree);
}

pub fn analyze_file_with_parsed(
    allocator: std.mem.Allocator,
    call_graph: *const graph.CallGraph,
    file_path: []const u8,
    tree: *const Ast,
) !FileFacts {
    assert(file_path.len > 0);
    assert(call_graph.files.items.len <= call_graph.files.capacity);
    if (file_path.len == 0) return error.InvalidInputPath;

    var green_functions = std.StringHashMap(void).init(allocator);
    defer green_functions.deinit();
    try build_green_function_set(allocator, call_graph, &green_functions);

    return analyze_file_with_parsed_and_green_functions(
        allocator,
        file_path,
        tree,
        &green_functions,
    );
}

pub fn build_green_function_set(
    allocator: std.mem.Allocator,
    call_graph: *const graph.CallGraph,
    green_functions: *std.StringHashMap(void),
) !void {
    assert(call_graph.files.items.len <= call_graph.files.capacity);
    assert(green_functions.count() == 0);
    if (green_functions.count() != 0) return;
    try collect_green_functions(allocator, call_graph, green_functions);
}

pub fn analyze_file_with_parsed_and_green_functions(
    allocator: std.mem.Allocator,
    file_path: []const u8,
    tree: *const Ast,
    green_functions: *const std.StringHashMap(void),
) !FileFacts {
    assert(file_path.len > 0);
    assert(tree.nodes.len > 0);
    assert(tree.nodes.items(.main_token).len == tree.nodes.len);
    assert(green_functions.count() <= std.math.maxInt(u32));
    if (file_path.len == 0) return error.InvalidInputPath;
    if (tree.nodes.len == 0) return error.InvalidInputPath;
    if (tree.nodes.items(.main_token).len != tree.nodes.len) return error.InvalidInputPath;

    var containers = std.array_list.Managed(ContainerRange).init(allocator);
    defer containers.deinit();
    try collect_container_ranges(tree, &containers);

    var facts = FileFacts.init(allocator);
    errdefer facts.deinit();

    for (tree.rootDecls()) |decl| {
        if (tree.nodes.items(.tag)[@intFromEnum(decl)] != .fn_decl) {
            continue;
        }

        var fn_buf: [1]Ast.Node.Index = undefined;
        const proto = tree.fullFnProto(&fn_buf, decl).?;
        const name_token = proto.name_token orelse continue;
        const function_name = try allocator.dupe(u8, tree.tokenSlice(name_token));

        const body_node = tree.nodeData(decl).node_and_node[1];
        if (body_node == .root) {
            continue;
        }

        const fn_first = tree.firstToken(decl);
        const is_method = node_in_containers(fn_first, &containers);
        const canonical_name =
            try std.fmt.allocPrint(allocator, "{s}::{s}", .{ file_path, function_name });

        var state = FunctionWalkState{
            .safe_consts = std.StringHashMap(void).init(allocator),
            .bounded_iterators = std.StringHashMap(void).init(allocator),
            .has_forbidden_alloc = false,
            .has_unbounded_loop = false,
        };
        defer state.safe_consts.deinit();
        defer state.bounded_iterators.deinit();

        try walk_function_body(
            allocator,
            tree,
            body_node,
            file_path,
            green_functions,
            &state,
        );

        try facts.functions.append(.{
            .canonical_name = canonical_name,
            .file_path = file_path,
            .function_name = function_name,
            .is_method = is_method,
            .has_forbidden_alloc = state.has_forbidden_alloc,
            .has_unbounded_loop = state.has_unbounded_loop,
        });
    }

    return facts;
}

fn collect_container_ranges(
    tree: *const Ast,
    ranges: *std.array_list.Managed(ContainerRange),
) !void {
    for (0..tree.nodes.len) |raw| {
        const node: Ast.Node.Index = @enumFromInt(raw);
        switch (tree.nodes.items(.tag)[raw]) {
            .container_decl,
            .container_decl_trailing,
            .container_decl_two,
            .container_decl_two_trailing,
            .container_decl_arg,
            .container_decl_arg_trailing,
            => {
                try ranges.append(.{
                    .first = tree.firstToken(node),
                    .last = tree.lastToken(node),
                });
            },
            else => {},
        }
    }
}

fn node_in_containers(
    token: Ast.TokenIndex,
    ranges: *const std.array_list.Managed(ContainerRange),
) bool {
    for (ranges.items) |range| {
        if (token >= range.first and token <= range.last) {
            return true;
        }
    }
    return false;
}

fn walk_function_body(
    allocator: std.mem.Allocator,
    tree: *const Ast,
    body_node: Ast.Node.Index,
    file_path: []const u8,
    green_functions: *const std.StringHashMap(void),
    state: *FunctionWalkState,
) !void {
    assert(file_path.len > 0);
    assert(body_node == .root or @intFromEnum(body_node) < tree.nodes.len);
    if (file_path.len == 0) return;
    if (body_node == .root or @intFromEnum(body_node) >= tree.nodes.len) return;
    var visited = ast_walk.NodeVisited.init(allocator);
    defer visited.deinit();

    var ctx = WalkCtx{
        .tree = tree,
        .file_path = file_path,
        .green_functions = green_functions,
        .state = state,
    };
    try ast_walk.walk_with_options(
        tree,
        body_node,
        &ctx,
        analysis_visit_node,
        .{ .visited = &visited },
    );
}

const WalkCtx = struct {
    tree: *const Ast,
    file_path: []const u8,
    green_functions: *const std.StringHashMap(void),
    state: *FunctionWalkState,
};

fn analysis_visit_node(
    tree: *const Ast,
    node: Ast.Node.Index,
    ctx_opaque: *anyopaque,
) anyerror!ast_walk.VisitDecision {
    const ctx: *WalkCtx = @ptrCast(@alignCast(ctx_opaque));
    assert(node == .root or @intFromEnum(node) < tree.nodes.len);
    assert(ctx.file_path.len > 0);
    if (node == .root or @intFromEnum(node) >= tree.nodes.len) return .visit_children;

    const tag = tree.nodes.items(.tag)[@intFromEnum(node)];
    if (is_call_tag(tag)) {
        note_call(tree, node, ctx);
        return .visit_children;
    }
    if (is_while_tag(tag)) {
        note_while(tree, node, ctx);
        return .visit_children;
    }
    if (is_local_var_decl_tag(tag)) {
        try note_local_var_decl(tree, node, ctx);
        return .visit_children;
    }
    if (is_assignment_tag(tag)) {
        const pair = tree.nodeData(node).node_and_node;
        invalidate_assignment_lhs(tree, pair[0], ctx.state);
    }

    return .visit_children;
}

fn note_call(tree: *const Ast, node: Ast.Node.Index, ctx: *WalkCtx) void {
    var call_buf: [1]Ast.Node.Index = undefined;
    const call = tree.fullCall(&call_buf, node) orelse return;
    var path: CallPath = .{};
    collect_call_path(tree, call.ast.fn_expr, &path);
    if (is_forbidden_alloc_path(&path)) {
        ctx.state.has_forbidden_alloc = true;
    }
}

fn note_while(tree: *const Ast, node: Ast.Node.Index, ctx: *WalkCtx) void {
    const while_full = tree.fullWhile(node) orelse return;
    const is_safe = loop_condition_is_safe(
        tree,
        while_full.ast.cond_expr,
        ctx.file_path,
        ctx.green_functions,
        ctx.state,
    );
    if (!is_safe) {
        ctx.state.has_unbounded_loop = true;
    }
}

fn note_local_var_decl(tree: *const Ast, node: Ast.Node.Index, ctx: *WalkCtx) !void {
    assert(node == .root or @intFromEnum(node) < tree.nodes.len);
    assert(ctx.file_path.len > 0);
    const var_decl = tree.fullVarDecl(node) orelse return;
    const name_token = var_decl.ast.mut_token + 1;
    const name = tree.tokenSlice(name_token);
    const mut_tag = tree.tokens.items(.tag)[var_decl.ast.mut_token];
    if (mut_tag == .keyword_const) {
        const init_node = var_decl.ast.init_node.unwrap() orelse return;
        const safe_bound = expr_is_safe_bound(
            tree,
            init_node,
            ctx.file_path,
            ctx.green_functions,
            &ctx.state.safe_consts,
        );
        if (safe_bound) {
            try ctx.state.safe_consts.put(name, {});
        }
        return;
    }

    const init_node = var_decl.ast.init_node.unwrap() orelse return;
    if (init_expr_is_bounded_iterator(tree, init_node)) {
        try ctx.state.bounded_iterators.put(name, {});
    }
}

fn is_call_tag(tag: Ast.Node.Tag) bool {
    return tag == .call or
        tag == .call_comma or
        tag == .call_one or
        tag == .call_one_comma;
}

fn is_while_tag(tag: Ast.Node.Tag) bool {
    return tag == .while_simple or tag == .while_cont or tag == .@"while";
}

fn is_local_var_decl_tag(tag: Ast.Node.Tag) bool {
    return tag == .local_var_decl or tag == .simple_var_decl or tag == .aligned_var_decl;
}

fn loop_condition_is_safe(
    tree: *const Ast,
    cond_node: Ast.Node.Index,
    file_path: []const u8,
    green_functions: *const std.StringHashMap(void),
    state: *const FunctionWalkState,
) bool {
    assert(file_path.len > 0);
    assert(tree.nodes.len > 0);
    assert(tree.nodes.items(.main_token).len == tree.nodes.len);
    if (file_path.len == 0) return false;
    if (cond_node == .root or @intFromEnum(cond_node) >= tree.nodes.len) return false;
    var stack: [64]Ast.Node.Index = undefined;
    var stack_len: u8 = 0;
    stack[@as(usize, stack_len)] = cond_node;
    stack_len += 1;

    var saw_constraint = false;
    while (stack_len > 0) {
        stack_len -= 1;
        const current_raw = stack[@as(usize, stack_len)];
        const current = normalize_condition_node(tree, current_raw) orelse return false;

        if (condition_node_is_neutral_guard(tree, current)) {
            continue;
        }

        if (while_condition_is_bounded_iterator_next(tree, current, state)) {
            saw_constraint = true;
            continue;
        }

        const tag = tree.nodes.items(.tag)[@intFromEnum(current)];
        if (tag == .bool_and) {
            if (!push_loop_condition_children(tree, current, &stack, &stack_len)) return false;
            continue;
        }

        if (loop_condition_leaf_is_safe(
            tree,
            current,
            file_path,
            green_functions,
            state,
        )) {
            saw_constraint = true;
            continue;
        }
        return false;
    }

    return saw_constraint;
}

fn condition_node_is_neutral_guard(tree: *const Ast, node: Ast.Node.Index) bool {
    assert(tree.nodes.items(.tag).len == tree.nodes.len);
    assert(node == .root or @intFromEnum(node) < tree.nodes.len);
    if (node == .root or @intFromEnum(node) >= tree.nodes.len) return false;
    const tag = tree.nodes.items(.tag)[@intFromEnum(node)];
    if (tag == .identifier) {
        const token = tree.nodes.items(.main_token)[@intFromEnum(node)];
        return std.mem.eql(u8, tree.tokenSlice(token), "true");
    }
    if (tag == .bool_not) return true;
    if (tag == .bang_equal) return true;
    return tag == .equal_equal;
}

fn normalize_condition_node(tree: *const Ast, cond_node: Ast.Node.Index) ?Ast.Node.Index {
    assert(tree.nodes.items(.tag).len == tree.nodes.len);
    assert(cond_node == .root or @intFromEnum(cond_node) < tree.nodes.len);
    if (cond_node == .root or @intFromEnum(cond_node) >= tree.nodes.len) return null;
    var current = cond_node;
    while (current != .root and @intFromEnum(current) < tree.nodes.len) {
        const tag = tree.nodes.items(.tag)[@intFromEnum(current)];
        switch (tag) {
            .grouped_expression, .unwrap_optional => {
                current = tree.nodeData(current).node_and_token[0];
            },
            .@"try" => {
                current = tree.nodeData(current).node;
            },
            else => return current,
        }
    }
    return null;
}

fn loop_condition_leaf_is_safe(
    tree: *const Ast,
    node: Ast.Node.Index,
    file_path: []const u8,
    green_functions: *const std.StringHashMap(void),
    state: *const FunctionWalkState,
) bool {
    assert(file_path.len > 0);
    assert(node == .root or @intFromEnum(node) < tree.nodes.len);
    assert(tree.nodes.items(.main_token).len == tree.nodes.len);
    if (file_path.len == 0) return false;
    if (node == .root or @intFromEnum(node) >= tree.nodes.len) return false;
    const tag = tree.nodes.items(.tag)[@intFromEnum(node)];
    switch (tag) {
        .number_literal => return false,
        .bool_or => return false,
        .identifier => {
            const token = tree.nodes.items(.main_token)[@intFromEnum(node)];
            const ident = tree.tokenSlice(token);
            return state.safe_consts.contains(ident);
        },
        .less_than,
        .less_or_equal,
        .greater_than,
        .greater_or_equal,
        => {
            const rhs = tree.nodeData(node).node_and_node[1];
            return expr_is_safe_bound(tree, rhs, file_path, green_functions, &state.safe_consts);
        },
        else => return false,
    }
}

fn push_loop_condition_children(
    tree: *const Ast,
    node: Ast.Node.Index,
    stack: *[64]Ast.Node.Index,
    stack_len: *u8,
) bool {
    assert(node == .root or @intFromEnum(node) < tree.nodes.len);
    assert(stack_len.* <= stack.len);
    if (tree.nodes.items(.tag)[@intFromEnum(node)] != .bool_and) {
        return true;
    }

    const lhs, const rhs = tree.nodeData(node).node_and_node;
    return push_nodes_64(stack, stack_len, lhs, rhs);
}

fn push_nodes_64(
    stack: *[64]Ast.Node.Index,
    stack_len: *u8,
    first: Ast.Node.Index,
    second: Ast.Node.Index,
) bool {
    const used = @as(usize, stack_len.*);
    if (used + 2 > stack.len) return false;
    stack[used] = first;
    stack_len.* += 1;
    stack[@as(usize, stack_len.*)] = second;
    stack_len.* += 1;
    return true;
}

fn while_condition_is_bounded_iterator_next(
    tree: *const Ast,
    cond_node: Ast.Node.Index,
    state: *const FunctionWalkState,
) bool {
    if (cond_node == .root or @intFromEnum(cond_node) >= tree.nodes.len) return false;
    assert(@intFromEnum(cond_node) < tree.nodes.len);
    assert(tree.nodes.items(.main_token).len == tree.nodes.len);

    const call_node = while_condition_call_node(tree, cond_node) orelse return false;
    return call_is_bounded_iterator_next(tree, call_node, state);
}

fn while_condition_call_node(tree: *const Ast, cond_node: Ast.Node.Index) ?Ast.Node.Index {
    assert(cond_node == .root or @intFromEnum(cond_node) < tree.nodes.len);
    assert(tree.nodes.items(.tag).len == tree.nodes.len);
    if (cond_node == .root or @intFromEnum(cond_node) >= tree.nodes.len) return null;
    var current = cond_node;
    while (current != .root and @intFromEnum(current) < tree.nodes.len) {
        const tag = tree.nodes.items(.tag)[@intFromEnum(current)];
        switch (tag) {
            .grouped_expression, .unwrap_optional => {
                current = tree.nodeData(current).node_and_token[0];
            },
            .@"try" => {
                current = tree.nodeData(current).node;
            },
            .call,
            .call_comma,
            .call_one,
            .call_one_comma,
            => return current,
            else => return null,
        }
    }

    return null;
}

fn call_is_bounded_iterator_next(
    tree: *const Ast,
    call_node: Ast.Node.Index,
    state: *const FunctionWalkState,
) bool {
    assert(call_node == .root or @intFromEnum(call_node) < tree.nodes.len);
    assert(tree.nodes.items(.main_token).len == tree.nodes.len);
    if (call_node == .root or @intFromEnum(call_node) >= tree.nodes.len) return false;
    var call_buf: [1]Ast.Node.Index = undefined;
    const call = tree.fullCall(&call_buf, call_node) orelse return false;
    const method = method_call_parts(tree, call.ast.fn_expr) orelse return false;
    if (!is_iterator_next_method(method.method_name)) return false;
    const receiver_name = root_identifier_name(tree, method.receiver) orelse return false;
    return state.bounded_iterators.contains(receiver_name);
}

const MethodCallParts = struct {
    receiver: Ast.Node.Index,
    method_name: []const u8,
};

fn method_call_parts(tree: *const Ast, fn_expr: Ast.Node.Index) ?MethodCallParts {
    if (fn_expr == .root or @intFromEnum(fn_expr) >= tree.nodes.len) return null;
    if (tree.nodes.items(.tag)[@intFromEnum(fn_expr)] != .field_access) return null;

    const receiver, const method_token = tree.nodeData(fn_expr).node_and_token;
    return .{
        .receiver = receiver,
        .method_name = tree.tokenSlice(method_token),
    };
}

fn root_identifier_name(tree: *const Ast, expr_node: Ast.Node.Index) ?[]const u8 {
    if (expr_node == .root or @intFromEnum(expr_node) >= tree.nodes.len) return null;
    assert(@intFromEnum(expr_node) < tree.nodes.len);
    assert(tree.nodes.items(.main_token).len == tree.nodes.len);

    var current = expr_node;
    while (current != .root and @intFromEnum(current) < tree.nodes.len) {
        switch (tree.nodes.items(.tag)[@intFromEnum(current)]) {
            .identifier => {
                const token = tree.nodes.items(.main_token)[@intFromEnum(current)];
                return tree.tokenSlice(token);
            },
            .field_access => {
                current = tree.nodeData(current).node_and_token[0];
            },
            .grouped_expression => {
                current = tree.nodeData(current).node_and_token[0];
            },
            .@"try" => {
                current = tree.nodeData(current).node;
            },
            else => return null,
        }
    }

    return null;
}

fn is_iterator_next_method(method_name: []const u8) bool {
    assert(method_name.len > 0);
    if (method_name.len == 0) return false;
    return std.mem.eql(u8, method_name, "next") or std.mem.eql(u8, method_name, "nextBack");
}

fn is_iterator_constructor_method(method_name: []const u8) bool {
    assert(method_name.len > 0);
    if (method_name.len == 0) return false;
    return std.mem.eql(u8, method_name, "iterator") or
        std.mem.eql(u8, method_name, "keyIterator") or
        std.mem.eql(u8, method_name, "valueIterator") or
        std.mem.eql(u8, method_name, "iterate");
}

fn init_expr_is_bounded_iterator(
    tree: *const Ast,
    init_node: Ast.Node.Index,
) bool {
    if (init_node == .root or @intFromEnum(init_node) >= tree.nodes.len) return false;
    assert(@intFromEnum(init_node) < tree.nodes.len);
    assert(tree.nodes.items(.main_token).len == tree.nodes.len);

    var current = init_node;
    while (current != .root and @intFromEnum(current) < tree.nodes.len) {
        const tag = tree.nodes.items(.tag)[@intFromEnum(current)];
        switch (tag) {
            .grouped_expression => {
                current = tree.nodeData(current).node_and_token[0];
            },
            .@"try" => {
                current = tree.nodeData(current).node;
            },
            .call,
            .call_comma,
            .call_one,
            .call_one_comma,
            => {
                var call_buf: [1]Ast.Node.Index = undefined;
                const call = tree.fullCall(&call_buf, current) orelse return false;
                const method = method_call_parts(tree, call.ast.fn_expr) orelse return false;
                return is_iterator_constructor_method(method.method_name);
            },
            else => return false,
        }
    }

    return false;
}

fn is_assignment_tag(tag: Ast.Node.Tag) bool {
    return switch (tag) {
        .assign,
        .assign_add,
        .assign_sub,
        .assign_mul,
        .assign_div,
        .assign_mod,
        .assign_shl,
        .assign_shr,
        .assign_bit_and,
        .assign_bit_or,
        .assign_bit_xor,
        .assign_mul_wrap,
        .assign_add_wrap,
        .assign_sub_wrap,
        .assign_mul_sat,
        .assign_add_sat,
        .assign_sub_sat,
        .assign_shl_sat,
        => true,
        else => false,
    };
}

fn invalidate_assignment_lhs(
    tree: *const Ast,
    lhs_node: Ast.Node.Index,
    state: *FunctionWalkState,
) void {
    const ident = root_identifier_name(tree, lhs_node) orelse return;
    if (state.bounded_iterators.remove(ident)) {}
}

fn expr_is_safe_bound(
    tree: *const Ast,
    expr_node: Ast.Node.Index,
    file_path: []const u8,
    green_functions: *const std.StringHashMap(void),
    safe_consts: *const std.StringHashMap(void),
) bool {
    assert(file_path.len > 0);
    assert(tree.nodes.len > 0);
    assert(tree.nodes.items(.main_token).len == tree.nodes.len);
    if (file_path.len == 0) return false;
    if (expr_node == .root or @intFromEnum(expr_node) >= tree.nodes.len) return false;

    var stack: [128]Ast.Node.Index = undefined;
    var stack_len: u8 = 0;
    stack[@as(usize, stack_len)] = expr_node;
    stack_len += 1;

    while (stack_len > 0) {
        stack_len -= 1;
        const current = stack[@as(usize, stack_len)];
        if (current == .root or @intFromEnum(current) >= tree.nodes.len) return false;
        if (!bound_node_is_safe(
            tree,
            current,
            file_path,
            green_functions,
            safe_consts,
            &stack,
            &stack_len,
        )) {
            return false;
        }
    }

    return true;
}

fn bound_node_is_safe(
    tree: *const Ast,
    current: Ast.Node.Index,
    file_path: []const u8,
    green_functions: *const std.StringHashMap(void),
    safe_consts: *const std.StringHashMap(void),
    stack: *[128]Ast.Node.Index,
    stack_len: *u8,
) bool {
    assert(file_path.len > 0);
    assert(current == .root or @intFromEnum(current) < tree.nodes.len);
    if (file_path.len == 0) return false;
    if (current == .root) return false;
    if (@intFromEnum(current) >= tree.nodes.len) return false;
    if (bound_node_is_literal_or_const(tree, current, safe_consts)) return true;
    if (bound_node_is_len_access(tree, current)) return true;
    if (bound_node_is_ast_token_call(tree, current)) return true;
    if (try_push_wrapper_child_128(tree, current, stack, stack_len)) return true;
    if (try_push_safe_builtin_args_128(tree, current, stack, stack_len)) return true;
    return bound_node_is_green_call(tree, current, file_path, green_functions);
}

fn bound_node_is_literal_or_const(
    tree: *const Ast,
    node: Ast.Node.Index,
    safe_consts: *const std.StringHashMap(void),
) bool {
    switch (tree.nodes.items(.tag)[@intFromEnum(node)]) {
        .number_literal => return true,
        .identifier => {
            const token = tree.nodes.items(.main_token)[@intFromEnum(node)];
            return safe_consts.contains(tree.tokenSlice(token));
        },
        else => return false,
    }
}

fn bound_node_is_len_access(tree: *const Ast, node: Ast.Node.Index) bool {
    return tree.nodes.items(.tag)[@intFromEnum(node)] == .field_access and
        is_len_field_access(tree, node);
}

fn bound_node_is_ast_token_call(tree: *const Ast, node: Ast.Node.Index) bool {
    assert(tree.nodes.items(.tag).len == tree.nodes.len);
    assert(node == .root or @intFromEnum(node) < tree.nodes.len);
    if (node == .root or @intFromEnum(node) >= tree.nodes.len) return false;
    const tag = tree.nodes.items(.tag)[@intFromEnum(node)];
    switch (tag) {
        .call,
        .call_comma,
        .call_one,
        .call_one_comma,
        => {
            var call_buf: [1]Ast.Node.Index = undefined;
            const call = tree.fullCall(&call_buf, node) orelse return false;
            var path: CallPath = .{};
            collect_call_path(tree, call.ast.fn_expr, &path);
            const method_name = path.last() orelse return false;
            if (std.mem.eql(u8, method_name, "firstToken")) return true;
            return std.mem.eql(u8, method_name, "lastToken");
        },
        else => return false,
    }
}

fn try_push_wrapper_child_128(
    tree: *const Ast,
    node: Ast.Node.Index,
    stack: *[128]Ast.Node.Index,
    stack_len: *u8,
) bool {
    assert(node == .root or @intFromEnum(node) < tree.nodes.len);
    assert(stack_len.* <= stack.len);
    const child = switch (tree.nodes.items(.tag)[@intFromEnum(node)]) {
        .grouped_expression => tree.nodeData(node).node_and_token[0],
        .@"try", .@"comptime" => tree.nodeData(node).node,
        else => return false,
    };
    return push_node_128(stack, stack_len, child);
}

fn try_push_safe_builtin_args_128(
    tree: *const Ast,
    node: Ast.Node.Index,
    stack: *[128]Ast.Node.Index,
    stack_len: *u8,
) bool {
    assert(node == .root or @intFromEnum(node) < tree.nodes.len);
    assert(stack_len.* <= stack.len);
    const tag = tree.nodes.items(.tag)[@intFromEnum(node)];
    if (tag == .builtin_call or tag == .builtin_call_comma) {
        return try_push_safe_builtin_variadic_args_128(tree, node, stack, stack_len);
    }
    if (tag == .builtin_call_two or tag == .builtin_call_two_comma) {
        return try_push_safe_builtin_pair_args_128(tree, node, stack, stack_len);
    }
    return false;
}

fn try_push_safe_builtin_variadic_args_128(
    tree: *const Ast,
    node: Ast.Node.Index,
    stack: *[128]Ast.Node.Index,
    stack_len: *u8,
) bool {
    assert(node == .root or @intFromEnum(node) < tree.nodes.len);
    assert(stack_len.* <= stack.len);
    if (node == .root or @intFromEnum(node) >= tree.nodes.len) return false;
    if (!is_safe_bound_builtin(tree, node)) return false;
    const args = tree.extraDataSlice(tree.nodeData(node).extra_range, Ast.Node.Index);
    if (args.len == 0) return false;
    const used = @as(usize, stack_len.*);
    if (used + args.len > stack.len) return false;
    for (args) |arg| {
        stack[@as(usize, stack_len.*)] = arg;
        stack_len.* += 1;
    }
    return true;
}

fn try_push_safe_builtin_pair_args_128(
    tree: *const Ast,
    node: Ast.Node.Index,
    stack: *[128]Ast.Node.Index,
    stack_len: *u8,
) bool {
    if (!is_safe_bound_builtin(tree, node)) return false;
    const first, const second = tree.nodeData(node).opt_node_and_opt_node;
    const first_arg = first.unwrap() orelse return false;
    const second_arg = second.unwrap() orelse return false;
    return push_nodes_128(stack, stack_len, first_arg, second_arg);
}

fn bound_node_is_green_call(
    tree: *const Ast,
    node: Ast.Node.Index,
    file_path: []const u8,
    green_functions: *const std.StringHashMap(void),
) bool {
    assert(file_path.len > 0);
    if (file_path.len == 0) return false;
    assert(node == .root or @intFromEnum(node) < tree.nodes.len);
    assert(tree.nodes.items(.main_token).len == tree.nodes.len);
    switch (tree.nodes.items(.tag)[@intFromEnum(node)]) {
        .call, .call_comma, .call_one, .call_one_comma => {
            var call_buf: [1]Ast.Node.Index = undefined;
            const call = tree.fullCall(&call_buf, node) orelse return false;
            var path: CallPath = .{};
            collect_call_path(tree, call.ast.fn_expr, &path);
            return call_is_green_function(file_path, &path, green_functions);
        },
        else => return false,
    }
}

fn push_node_128(stack: *[128]Ast.Node.Index, stack_len: *u8, node: Ast.Node.Index) bool {
    const used = @as(usize, stack_len.*);
    if (used + 1 > stack.len) return false;
    stack[used] = node;
    stack_len.* += 1;
    return true;
}

fn push_nodes_128(
    stack: *[128]Ast.Node.Index,
    stack_len: *u8,
    first: Ast.Node.Index,
    second: Ast.Node.Index,
) bool {
    const used = @as(usize, stack_len.*);
    if (used + 2 > stack.len) return false;
    stack[used] = first;
    stack_len.* += 1;
    stack[@as(usize, stack_len.*)] = second;
    stack_len.* += 1;
    return true;
}

fn is_safe_bound_builtin(tree: *const Ast, node: Ast.Node.Index) bool {
    if (node == .root or @intFromEnum(node) >= tree.nodes.len) return false;
    const token = tree.nodes.items(.main_token)[@intFromEnum(node)];
    if (token >= tree.tokens.len) return false;
    const name = tree.tokenSlice(token);
    return std.mem.eql(u8, name, "@min") or std.mem.eql(u8, name, "@max");
}

fn is_len_field_access(tree: *const Ast, node: Ast.Node.Index) bool {
    assert(node == .root or @intFromEnum(node) < tree.nodes.len);
    if (node == .root or @intFromEnum(node) >= tree.nodes.len) return false;
    if (tree.nodes.items(.tag)[@intFromEnum(node)] != .field_access) return false;

    const lhs, const field_token = tree.nodeData(node).node_and_token;
    const field_name = tree.tokenSlice(field_token);
    if (!std.mem.eql(u8, field_name, "len")) return false;

    // .len on any identifier or field access is considered a length check
    // This handles: arr.len, items.len, self.items.len, etc.
    if (lhs == .root or @intFromEnum(lhs) >= tree.nodes.len) return true;
    const lhs_tag = tree.nodes.items(.tag)[@intFromEnum(lhs)];
    return lhs_tag == .identifier or lhs_tag == .field_access;
}

fn collect_green_functions(
    allocator: std.mem.Allocator,
    call_graph: *const graph.CallGraph,
    green: *std.StringHashMap(void),
) !void {
    assert(green.count() <= call_graph.nodes.count());
    var edges_by_caller = std.StringHashMap(std.array_list.Managed([]const u8)).init(allocator);
    defer {
        var it = edges_by_caller.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.deinit();
        }
        edges_by_caller.deinit();
    }

    try build_green_edges_by_caller(allocator, call_graph, &edges_by_caller);

    var queue = std.array_list.Managed([]const u8).init(allocator);
    defer queue.deinit();
    const max_green_queue: u32 = @intCast(call_graph.nodes.count());

    try seed_green_roots(call_graph, green, &queue, max_green_queue);
    try propagate_green_reachability(&edges_by_caller, green, &queue, max_green_queue);
}

fn build_green_edges_by_caller(
    allocator: std.mem.Allocator,
    call_graph: *const graph.CallGraph,
    edges_by_caller: *std.StringHashMap(std.array_list.Managed([]const u8)),
) !void {
    assert(edges_by_caller.count() <= call_graph.edges.count());
    assert(call_graph.edges.count() <= std.math.maxInt(usize));
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

fn seed_green_roots(
    call_graph: *const graph.CallGraph,
    green: *std.StringHashMap(void),
    queue: *std.array_list.Managed([]const u8),
    max_green_queue: u32,
) !void {
    var node_iter = call_graph.nodes.keyIterator();
    while (node_iter.next()) |node| {
        if (std.mem.endsWith(u8, node.*, "::main")) {
            try green.put(node.*, {});
            if (queue.items.len >= @as(usize, max_green_queue)) return error.QueueCapacityExceeded;
            try queue.append(node.*);
        }
    }
}

fn propagate_green_reachability(
    edges_by_caller: *const std.StringHashMap(std.array_list.Managed([]const u8)),
    green: *std.StringHashMap(void),
    queue: *std.array_list.Managed([]const u8),
    max_green_queue: u32,
) !void {
    assert(queue.items.len <= @as(usize, max_green_queue));
    assert(green.count() >= queue.items.len);
    var index: usize = 0;
    while (index < queue.items.len) : (index += 1) {
        const current = queue.items[index];
        if (edges_by_caller.get(current)) |callees| {
            for (callees.items) |callee| {
                if (!green.contains(callee)) {
                    try green.put(callee, {});
                    if (queue.items.len >= @as(usize, max_green_queue)) {
                        return error.QueueCapacityExceeded;
                    }
                    try queue.append(callee);
                }
            }
        }
    }
}

fn call_is_green_function(
    file_path: []const u8,
    path: *const CallPath,
    green_functions: *const std.StringHashMap(void),
) bool {
    assert(file_path.len > 0);
    assert(path.len <= path.parts.len);
    if (file_path.len == 0) return false;
    if (path.len != 1) return false;

    const function_name = path.parts[0];
    var it = green_functions.keyIterator();
    while (it.next()) |canonical| {
        if (!std.mem.startsWith(u8, canonical.*, file_path)) continue;
        if (canonical.*.len <= file_path.len + 2) continue;
        if (!std.mem.eql(u8, canonical.*[file_path.len .. file_path.len + 2], "::")) continue;
        if (std.mem.eql(u8, canonical.*[file_path.len + 2 ..], function_name)) {
            return true;
        }
    }
    return false;
}

fn collect_call_path(tree: *const Ast, expr_node: Ast.Node.Index, path: *CallPath) void {
    assert(tree.nodes.len > 0);
    assert(tree.nodes.items(.main_token).len == tree.nodes.len);
    if (expr_node == .root or @intFromEnum(expr_node) >= tree.nodes.len) return;

    var current = expr_node;
    var fields: [8][]const u8 = undefined;
    var fields_len: usize = 0;

    while (current != .root and @intFromEnum(current) < tree.nodes.len) {
        switch (tree.nodes.items(.tag)[@intFromEnum(current)]) {
            .identifier => {
                const token = tree.nodes.items(.main_token)[@intFromEnum(current)];
                path.append(tree.tokenSlice(token));
                break;
            },
            .field_access => {
                const lhs, const field_token = tree.nodeData(current).node_and_token;
                if (fields_len < fields.len) {
                    fields[fields_len] = tree.tokenSlice(field_token);
                    fields_len += 1;
                }
                current = lhs;
            },
            .grouped_expression => {
                current = tree.nodeData(current).node_and_token[0];
            },
            .@"try" => {
                current = tree.nodeData(current).node;
            },
            else => return,
        }
    }

    var i = fields_len;
    while (i > 0) {
        i -= 1;
        path.append(fields[i]);
    }
}

fn is_forbidden_alloc_path(path: *const CallPath) bool {
    assert(path.len <= path.parts.len);
    assert(path.parts.len > 0);
    const last = path.last() orelse return false;
    if (std.mem.eql(u8, last, "alloc")) {
        if (is_std_page_allocator_path(path)) return true;
        if (path.len >= 2) {
            return true;
        }
    }
    if (std.mem.eql(u8, last, "create") and path.len >= 2) {
        return true;
    }
    return false;
}

fn is_std_page_allocator_path(path: *const CallPath) bool {
    if (path.len != 4) return false;
    if (!std.mem.eql(u8, path.parts[0], "std")) return false;
    if (!std.mem.eql(u8, path.parts[1], "heap")) return false;
    return std.mem.eql(u8, path.parts[2], "page_allocator");
}

const std = @import("std");
const assert = std.debug.assert;
const ast_walk = @import("../ast_walk.zig");
const rules = @import("../rules.zig");
const diagnostics = @import("diagnostics.zig");
const error_discipline = @import("error_discipline.zig");
const implicit_walk = @import("implicit_walk.zig");

const ast_walk_nodes_max: usize = 4000;
const large_arg_array_threshold: u64 = 64;
const large_arg_value_threshold_bytes: u64 = 64;
const pointer_size_bytes: u64 = 8;
const slice_size_bytes: u64 = 16;
const declaration_locality_gap_statements: usize = 5;
const append_diag = diagnostics.append;
const Result = diagnostics.Result;

const LargeArgSymbolIndex = struct {
    const_expr_nodes: std.StringHashMap(std.zig.Ast.Node.Index),
    type_decl_nodes: std.StringHashMap(std.zig.Ast.Node.Index),

    fn init(allocator: std.mem.Allocator) LargeArgSymbolIndex {
        return .{
            .const_expr_nodes = std.StringHashMap(std.zig.Ast.Node.Index).init(allocator),
            .type_decl_nodes = std.StringHashMap(std.zig.Ast.Node.Index).init(allocator),
        };
    }

    fn deinit(self: *LargeArgSymbolIndex) void {
        self.const_expr_nodes.deinit();
        self.type_decl_nodes.deinit();
    }
};

const ConstVisitState = struct {
    names: [32][]const u8 = undefined,
    len: u8 = 0,
};

const TypeVisitState = struct {
    names: [32][]const u8 = undefined,
    len: u8 = 0,
};

fn detect_error_handling_in_function(
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
    try error_discipline.detect_error_handling_in_function(tree, body_node, file_path, result);
}

pub fn detect_with_parsed(
    allocator: std.mem.Allocator,
    tree: *const std.zig.Ast,
    source: []const u8,
    file_path: []const u8,
    result: *Result,
) !void {
    assert(source.len > 0);
    assert(file_path.len > 0);
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    if (source.len == 0) return;
    if (file_path.len == 0) return;

    var large_arg_symbols = try build_large_arg_symbol_index(allocator, tree);
    defer large_arg_symbols.deinit();

    for (tree.rootDecls()) |decl| {
        const tag = tree.nodes.items(.tag)[@intFromEnum(decl)];
        switch (tag) {
            .fn_decl => {
                try analyze_root_fn_decl(
                    allocator,
                    tree,
                    source,
                    file_path,
                    decl,
                    &large_arg_symbols,
                    result,
                );
            },
            .global_var_decl,
            .local_var_decl,
            .simple_var_decl,
            .aligned_var_decl,
            => {
                try analyze_root_var_decl(allocator, tree, file_path, decl, result);
            },
            else => {},
        }
    }
}

fn analyze_root_fn_decl(
    allocator: std.mem.Allocator,
    tree: *const std.zig.Ast,
    source: []const u8,
    file_path: []const u8,
    decl: std.zig.Ast.Node.Index,
    large_arg_symbols: *LargeArgSymbolIndex,
    result: *Result,
) !void {
    assert(source.len > 0);
    assert(file_path.len > 0);
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    assert(decl == .root or @intFromEnum(decl) < tree.nodes.len);
    if (source.len == 0) return;
    if (file_path.len == 0) return;
    if (decl == .root or @intFromEnum(decl) >= tree.nodes.len) return;
    var fn_buf: [1]std.zig.Ast.Node.Index = undefined;
    const proto = tree.fullFnProto(&fn_buf, decl) orelse return;
    const fn_name_tok = proto.name_token orelse return;
    const fn_name = tree.tokenSlice(fn_name_tok);

    const alias_overlap_risk = try analyze_fn_params_for_pointer_rules(
        allocator,
        tree,
        file_path,
        fn_name,
        proto,
        large_arg_symbols,
        result,
    );
    try analyze_fn_return_type_for_fixed_width(allocator, tree, file_path, fn_name, proto, result);
    try analyze_fn_return_type_for_in_place_init(
        allocator,
        tree,
        file_path,
        fn_name,
        proto,
        large_arg_symbols,
        result,
    );
    if (alias_overlap_risk) {
        const msg = try std.fmt.allocPrint(
            allocator,
            "Potential Aliasing in `{s}`. Ensure pointer params do not overlap.",
            .{fn_name},
        );
        try append_diag(result, .warning, .TB01_ALIASING, file_path, msg);
    }

    const body_node = tree.nodeData(decl).node_and_node[1];
    if (body_node == .root) return;

    try analyze_function_declaration_locality(
        allocator,
        tree,
        file_path,
        fn_name,
        body_node,
        result,
    );

    try detect_error_handling_in_function(tree, body_node, file_path, result);
    try detect_local_pointer_depth(tree, body_node, file_path, result);

    try implicit_walk.detect_implicit_alloc_and_switch_else(
        allocator,
        tree,
        source,
        body_node,
        file_path,
        result,
    );
}

fn analyze_fn_params_for_pointer_rules(
    allocator: std.mem.Allocator,
    tree: *const std.zig.Ast,
    file_path: []const u8,
    fn_name: []const u8,
    proto: std.zig.Ast.full.FnProto,
    large_arg_symbols: *LargeArgSymbolIndex,
    result: *Result,
) !bool {
    assert(file_path.len > 0);
    assert(fn_name.len > 0);
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    if (file_path.len == 0) return false;
    if (fn_name.len == 0) return false;
    var alias_keys: [16][]const u8 = undefined;
    var alias_key_len: u32 = 0;
    var alias_overlap_risk = false;

    var it = proto.iterate(tree);
    while (it.next()) |param| {
        const type_expr = param.type_expr orelse continue;
        var param_name: ?[]const u8 = null;
        if (param.name_token) |name_token| {
            param_name = tree.tokenSlice(name_token);
        }
        try analyze_pointer_depth_param(tree, type_expr, file_path, result);
        try analyze_function_pointer_param(
            allocator,
            tree,
            type_expr,
            file_path,
            fn_name,
            param_name,
            result,
        );
        update_alias_overlap(tree, type_expr, &alias_keys, &alias_key_len, &alias_overlap_risk);
        try analyze_fixed_width_param(allocator, tree, type_expr, file_path, fn_name, result);
        try analyze_large_arg_pointer_param(
            allocator,
            tree,
            type_expr,
            file_path,
            fn_name,
            param_name,
            large_arg_symbols,
            result,
        );
    }

    return alias_overlap_risk;
}

fn analyze_large_arg_pointer_param(
    allocator: std.mem.Allocator,
    tree: *const std.zig.Ast,
    type_expr: std.zig.Ast.Node.Index,
    file_path: []const u8,
    fn_name: []const u8,
    param_name: ?[]const u8,
    large_arg_symbols: *LargeArgSymbolIndex,
    result: *Result,
) !void {
    assert(file_path.len > 0);
    assert(fn_name.len > 0);
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    if (file_path.len == 0) return;
    if (fn_name.len == 0) return;
    if (pointer_depth(tree, type_expr) > 0) return;

    if (estimated_value_size_bytes(tree, type_expr, large_arg_symbols)) |size_bytes| {
        if (size_bytes < large_arg_value_threshold_bytes) return;
        var msg: []const u8 = undefined;
        if (param_name) |name| {
            msg = try std.fmt.allocPrint(
                allocator,
                "TS23_LARGE_ARG_POINTER: parameter `{s}` in `{s}` passes ~{d} bytes by " ++
                    "value; prefer pointer/slice",
                .{ name, fn_name, size_bytes },
            );
        } else {
            msg = try std.fmt.allocPrint(
                allocator,
                "TS23_LARGE_ARG_POINTER: function `{s}` passes ~{d} bytes by value; " ++
                    "prefer pointer/slice",
                .{ fn_name, size_bytes },
            );
        }
        try append_diag(result, .warning, .TS23_LARGE_ARG_POINTER, file_path, msg);
        return;
    }

    const array_len = fixed_array_length_value(tree, type_expr, large_arg_symbols) orelse return;
    if (array_len < large_arg_array_threshold) return;

    var msg: []const u8 = undefined;
    if (param_name) |name| {
        msg = try std.fmt.allocPrint(
            allocator,
            "TS23_LARGE_ARG_POINTER: parameter `{s}` in `{s}` passes [{d}] by value; " ++
                "prefer pointer/slice",
            .{ name, fn_name, array_len },
        );
    } else {
        msg = try std.fmt.allocPrint(
            allocator,
            "TS23_LARGE_ARG_POINTER: function `{s}` passes [{d}] by value; " ++
                "prefer pointer/slice",
            .{ fn_name, array_len },
        );
    }
    try append_diag(result, .warning, .TS23_LARGE_ARG_POINTER, file_path, msg);
}

fn build_large_arg_symbol_index(
    allocator: std.mem.Allocator,
    tree: *const std.zig.Ast,
) !LargeArgSymbolIndex {
    assert(tree.nodes.len > 0);
    assert(tree.nodes.items(.main_token).len == tree.nodes.len);
    var symbols = LargeArgSymbolIndex.init(allocator);
    errdefer symbols.deinit();

    for (tree.rootDecls()) |decl| {
        const var_decl = tree.fullVarDecl(decl) orelse continue;
        if (tree.tokens.items(.tag)[var_decl.ast.mut_token] != .keyword_const) {
            continue;
        }

        const init_node = var_decl.ast.init_node.unwrap() orelse continue;
        const name = tree.tokenSlice(var_decl.ast.mut_token + 1);
        try symbols.const_expr_nodes.put(name, init_node);

        var container_buf: [2]std.zig.Ast.Node.Index = undefined;
        if (tree.fullContainerDecl(&container_buf, init_node) != null) {
            try symbols.type_decl_nodes.put(name, init_node);
        }
    }

    return symbols;
}

fn fixed_array_length_value(
    tree: *const std.zig.Ast,
    type_node: std.zig.Ast.Node.Index,
    symbols: *LargeArgSymbolIndex,
) ?u64 {
    assert(tree.nodes.len > 0);

    const unwrapped_type = unwrap_optional_grouped_type(tree, type_node) orelse return null;
    const array_type = tree.fullArrayType(unwrapped_type) orelse return null;

    var const_state = ConstVisitState{};
    return eval_const_u64_expr(
        tree,
        array_type.ast.elem_count,
        symbols,
        &const_state,
    );
}

fn estimated_value_size_bytes(
    tree: *const std.zig.Ast,
    type_node: std.zig.Ast.Node.Index,
    symbols: *LargeArgSymbolIndex,
) ?u64 {
    var const_state = ConstVisitState{};
    var type_state = TypeVisitState{};
    return estimate_type_size_bytes(
        tree,
        type_node,
        symbols,
        &const_state,
        &type_state,
    );
}

fn estimate_type_size_bytes(
    tree: *const std.zig.Ast,
    type_node: std.zig.Ast.Node.Index,
    symbols: *LargeArgSymbolIndex,
    const_state: *ConstVisitState,
    type_state: *TypeVisitState,
) ?u64 {
    assert(tree.nodes.len > 0);
    assert(type_state.len <= type_state.names.len);

    const unwrapped_type = unwrap_optional_grouped_type(tree, type_node) orelse return null;

    if (tree.fullPtrType(unwrapped_type)) |ptr_type| {
        if (ptr_type.size == .slice) {
            return slice_size_bytes;
        }
        return pointer_size_bytes;
    }

    if (tree.fullArrayType(unwrapped_type)) |array_type| {
        const len = eval_const_u64_expr(
            tree,
            array_type.ast.elem_count,
            symbols,
            const_state,
        ) orelse return null;
        const elem_size = estimate_type_size_bytes(
            tree,
            array_type.ast.elem_type,
            symbols,
            const_state,
            type_state,
        ) orelse return null;
        return std.math.mul(u64, len, elem_size) catch null;
    }

    const tag = tree.nodes.items(.tag)[@intFromEnum(unwrapped_type)];
    if (tag == .identifier) {
        const type_token = tree.nodes.items(.main_token)[@intFromEnum(unwrapped_type)];
        const type_name = tree.tokenSlice(type_token);
        if (primitive_type_size_bytes(type_name)) |size| {
            return size;
        }
        return estimate_named_type_size_bytes(
            tree,
            type_name,
            symbols,
            const_state,
            type_state,
        );
    }

    var container_buf: [2]std.zig.Ast.Node.Index = undefined;
    if (tree.fullContainerDecl(&container_buf, unwrapped_type) != null) {
        return estimate_container_decl_size_bytes(
            tree,
            unwrapped_type,
            symbols,
            const_state,
            type_state,
        );
    }

    return null;
}

fn estimate_named_type_size_bytes(
    tree: *const std.zig.Ast,
    type_name: []const u8,
    symbols: *LargeArgSymbolIndex,
    const_state: *ConstVisitState,
    type_state: *TypeVisitState,
) ?u64 {
    assert(type_name.len > 0);
    if (type_name.len == 0) return null;

    const decl_node = symbols.type_decl_nodes.get(type_name) orelse return null;
    if (!push_type_visiting_name(type_state, type_name)) return null;
    defer pop_type_visiting_name(type_state);

    return estimate_container_decl_size_bytes(
        tree,
        decl_node,
        symbols,
        const_state,
        type_state,
    );
}

fn estimate_container_decl_size_bytes(
    tree: *const std.zig.Ast,
    container_node: std.zig.Ast.Node.Index,
    symbols: *LargeArgSymbolIndex,
    const_state: *ConstVisitState,
    type_state: *TypeVisitState,
) ?u64 {
    assert(type_state.len <= type_state.names.len);
    assert(container_node == .root or @intFromEnum(container_node) < tree.nodes.len);
    assert(tree.nodes.items(.main_token).len == tree.nodes.len);
    if (container_node == .root or @intFromEnum(container_node) >= tree.nodes.len) return null;

    var container_buf: [2]std.zig.Ast.Node.Index = undefined;
    const container = tree.fullContainerDecl(&container_buf, container_node) orelse return null;
    const size_kind = container_size_kind(tree, container.ast.main_token) orelse return null;
    return estimate_container_members_size(
        tree,
        container.ast.members,
        size_kind,
        symbols,
        const_state,
        type_state,
    );
}

const ContainerSizeKind = enum {
    union_kind,
    aggregate_kind,
};

fn container_size_kind(
    tree: *const std.zig.Ast,
    main_token: std.zig.Ast.TokenIndex,
) ?ContainerSizeKind {
    if (main_token >= tree.tokens.len) return null;
    const container_token = tree.tokens.items(.tag)[main_token];
    if (container_token == .keyword_enum) return null;
    if (container_token == .keyword_union) return .union_kind;
    return .aggregate_kind;
}

fn estimate_container_members_size(
    tree: *const std.zig.Ast,
    members: []const std.zig.Ast.Node.Index,
    size_kind: ContainerSizeKind,
    symbols: *LargeArgSymbolIndex,
    const_state: *ConstVisitState,
    type_state: *TypeVisitState,
) ?u64 {
    assert(members.len <= tree.nodes.len);
    assert(const_state.len <= const_state.names.len);
    assert(type_state.len <= type_state.names.len);
    if (members.len > tree.nodes.len) return null;
    if (const_state.len > const_state.names.len) return null;
    if (type_state.len > type_state.names.len) return null;
    var total_size: u64 = 0;
    var max_field_size: u64 = 0;
    for (members) |member| {
        const field = tree.fullContainerField(member) orelse continue;
        const field_type = field.ast.type_expr.unwrap() orelse return null;
        const field_size = estimate_type_size_bytes(
            tree,
            field_type,
            symbols,
            const_state,
            type_state,
        ) orelse return null;
        if (size_kind == .union_kind) {
            max_field_size = @max(max_field_size, field_size);
        } else {
            total_size = std.math.add(u64, total_size, field_size) catch return null;
        }
    }

    return switch (size_kind) {
        .union_kind => max_field_size,
        .aggregate_kind => total_size,
    };
}

fn primitive_type_size_bytes(type_name: []const u8) ?u64 {
    assert(type_name.len > 0);
    assert(type_name.len <= std.math.maxInt(u32));
    if (type_name.len == 0) return null;
    if (type_name.len > std.math.maxInt(u32)) return null;
    if (primitive_type_is_one_byte(type_name)) return 1;
    if (primitive_type_is_two_bytes(type_name)) return 2;
    if (primitive_type_is_four_bytes(type_name)) return 4;
    if (primitive_type_is_eight_bytes(type_name)) return 8;
    if (primitive_type_is_sixteen_bytes(type_name)) return 16;
    return null;
}

fn primitive_type_is_one_byte(type_name: []const u8) bool {
    assert(type_name.len > 0);
    if (type_name.len == 0) return false;
    if (std.mem.eql(u8, type_name, "bool")) return true;
    if (std.mem.eql(u8, type_name, "u8")) return true;
    return std.mem.eql(u8, type_name, "i8");
}

fn primitive_type_is_two_bytes(type_name: []const u8) bool {
    assert(type_name.len > 0);
    if (type_name.len == 0) return false;
    if (std.mem.eql(u8, type_name, "u16")) return true;
    if (std.mem.eql(u8, type_name, "i16")) return true;
    return std.mem.eql(u8, type_name, "f16");
}

fn primitive_type_is_four_bytes(type_name: []const u8) bool {
    assert(type_name.len > 0);
    if (type_name.len == 0) return false;
    if (std.mem.eql(u8, type_name, "u32")) return true;
    if (std.mem.eql(u8, type_name, "i32")) return true;
    return std.mem.eql(u8, type_name, "f32");
}

fn primitive_type_is_eight_bytes(type_name: []const u8) bool {
    assert(type_name.len > 0);
    assert(type_name.len <= std.math.maxInt(u32));
    if (type_name.len == 0) return false;
    if (type_name.len > std.math.maxInt(u32)) return false;
    if (std.mem.eql(u8, type_name, "u64")) return true;
    if (std.mem.eql(u8, type_name, "i64")) return true;
    if (std.mem.eql(u8, type_name, "f64")) return true;
    if (std.mem.eql(u8, type_name, "usize")) return true;
    return std.mem.eql(u8, type_name, "isize");
}

fn primitive_type_is_sixteen_bytes(type_name: []const u8) bool {
    assert(type_name.len > 0);
    if (type_name.len == 0) return false;
    if (std.mem.eql(u8, type_name, "u128")) return true;
    if (std.mem.eql(u8, type_name, "i128")) return true;
    return std.mem.eql(u8, type_name, "f128");
}

fn eval_const_u64_expr(
    tree: *const std.zig.Ast,
    node: std.zig.Ast.Node.Index,
    symbols: *LargeArgSymbolIndex,
    const_state: *ConstVisitState,
) ?u64 {
    assert(tree.nodes.items(.main_token).len == tree.nodes.len);
    assert(const_state.len <= const_state.names.len);
    if (node == .root or @intFromEnum(node) >= tree.nodes.len) return null;

    const tag = tree.nodes.items(.tag)[@intFromEnum(node)];
    switch (tag) {
        .number_literal => {
            const token = tree.nodes.items(.main_token)[@intFromEnum(node)];
            return parse_unsigned_integer_literal(tree.tokenSlice(token));
        },
        .identifier => {
            const token = tree.nodes.items(.main_token)[@intFromEnum(node)];
            return resolve_const_identifier_value(
                tree,
                tree.tokenSlice(token),
                symbols,
                const_state,
            );
        },
        .grouped_expression => {
            const child = tree.nodeData(node).node_and_token[0];
            return eval_const_u64_expr(tree, child, symbols, const_state);
        },
        .@"comptime" => {
            const child = tree.nodeData(node).node;
            return eval_const_u64_expr(tree, child, symbols, const_state);
        },
        .add,
        .sub,
        .mul,
        .div,
        .mod,
        .shl,
        .shr,
        .add_wrap,
        .sub_wrap,
        .mul_wrap,
        .add_sat,
        .sub_sat,
        .mul_sat,
        .shl_sat,
        => {
            return eval_const_binary_expr(tree, node, tag, symbols, const_state);
        },
        .builtin_call,
        .builtin_call_comma,
        .builtin_call_two,
        .builtin_call_two_comma,
        => return eval_const_builtin_expr(tree, node, symbols, const_state),
        else => return null,
    }
}

fn eval_const_binary_expr(
    tree: *const std.zig.Ast,
    node: std.zig.Ast.Node.Index,
    tag: std.zig.Ast.Node.Tag,
    symbols: *LargeArgSymbolIndex,
    const_state: *ConstVisitState,
) ?u64 {
    const lhs_node, const rhs_node = tree.nodeData(node).node_and_node;
    const lhs = eval_const_u64_expr(tree, lhs_node, symbols, const_state) orelse
        return null;
    const rhs = eval_const_u64_expr(tree, rhs_node, symbols, const_state) orelse
        return null;

    return switch (tag) {
        .add, .add_wrap, .add_sat => std.math.add(u64, lhs, rhs) catch null,
        .sub, .sub_wrap, .sub_sat => std.math.sub(u64, lhs, rhs) catch null,
        .mul, .mul_wrap, .mul_sat => std.math.mul(u64, lhs, rhs) catch null,
        .div => eval_div_u64(lhs, rhs),
        .mod => eval_mod_u64(lhs, rhs),
        .shl, .shl_sat => eval_shift_left_u64(lhs, rhs),
        .shr => eval_shift_right_u64(lhs, rhs),
        else => null,
    };
}

fn eval_div_u64(lhs: u64, rhs: u64) ?u64 {
    if (rhs == 0) return null;
    return lhs / rhs;
}

fn eval_mod_u64(lhs: u64, rhs: u64) ?u64 {
    if (rhs == 0) return null;
    return lhs % rhs;
}

fn eval_shift_left_u64(lhs: u64, rhs: u64) ?u64 {
    if (rhs >= 64) return null;
    return lhs << @as(u6, @intCast(rhs));
}

fn eval_shift_right_u64(lhs: u64, rhs: u64) ?u64 {
    if (rhs >= 64) return null;
    return lhs >> @as(u6, @intCast(rhs));
}

fn eval_const_builtin_expr(
    tree: *const std.zig.Ast,
    node: std.zig.Ast.Node.Index,
    symbols: *LargeArgSymbolIndex,
    const_state: *ConstVisitState,
) ?u64 {
    assert(tree.nodes.items(.main_token).len == tree.nodes.len);
    assert(const_state.len <= const_state.names.len);
    const token = tree.nodes.items(.main_token)[@intFromEnum(node)];
    if (token >= tree.tokens.len) return null;
    const builtin_name = tree.tokenSlice(token);

    var arg_nodes: [2]std.zig.Ast.Node.Index = undefined;
    var arg_len: u8 = 0;
    if (!collect_builtin_arg_nodes(tree, node, &arg_nodes, &arg_len)) return null;

    if (std.mem.eql(u8, builtin_name, "@as")) {
        return eval_builtin_as(tree, symbols, const_state, &arg_nodes, arg_len);
    }
    if (std.mem.eql(u8, builtin_name, "@intCast")) {
        return eval_builtin_int_cast(tree, symbols, const_state, &arg_nodes, arg_len);
    }
    if (std.mem.eql(u8, builtin_name, "@max")) {
        return eval_builtin_extrema(tree, symbols, const_state, &arg_nodes, arg_len, true);
    }
    if (std.mem.eql(u8, builtin_name, "@min")) {
        return eval_builtin_extrema(tree, symbols, const_state, &arg_nodes, arg_len, false);
    }

    return null;
}

fn collect_builtin_arg_nodes(
    tree: *const std.zig.Ast,
    node: std.zig.Ast.Node.Index,
    arg_nodes: *[2]std.zig.Ast.Node.Index,
    arg_len: *u8,
) bool {
    assert(arg_len.* <= arg_nodes.len);
    assert(node == .root or @intFromEnum(node) < tree.nodes.len);
    switch (tree.nodes.items(.tag)[@intFromEnum(node)]) {
        .builtin_call,
        .builtin_call_comma,
        => {
            const args = tree.extraDataSlice(
                tree.nodeData(node).extra_range,
                std.zig.Ast.Node.Index,
            );
            if (args.len > arg_nodes.len) return false;
            for (args) |arg| {
                arg_nodes[@as(usize, arg_len.*)] = arg;
                arg_len.* += 1;
            }
            return true;
        },
        .builtin_call_two,
        .builtin_call_two_comma,
        => {
            const first, const second = tree.nodeData(node).opt_node_and_opt_node;
            if (first.unwrap()) |first_arg| {
                arg_nodes[@as(usize, arg_len.*)] = first_arg;
                arg_len.* += 1;
            }
            if (second.unwrap()) |second_arg| {
                arg_nodes[@as(usize, arg_len.*)] = second_arg;
                arg_len.* += 1;
            }
            return true;
        },
        else => return false,
    }
}

fn eval_builtin_as(
    tree: *const std.zig.Ast,
    symbols: *LargeArgSymbolIndex,
    const_state: *ConstVisitState,
    arg_nodes: *const [2]std.zig.Ast.Node.Index,
    arg_len: u8,
) ?u64 {
    if (arg_len != 2) return null;
    return eval_const_u64_expr(tree, arg_nodes[1], symbols, const_state);
}

fn eval_builtin_int_cast(
    tree: *const std.zig.Ast,
    symbols: *LargeArgSymbolIndex,
    const_state: *ConstVisitState,
    arg_nodes: *const [2]std.zig.Ast.Node.Index,
    arg_len: u8,
) ?u64 {
    if (arg_len == 0) return null;
    return eval_const_u64_expr(tree, arg_nodes[arg_len - 1], symbols, const_state);
}

fn eval_builtin_extrema(
    tree: *const std.zig.Ast,
    symbols: *LargeArgSymbolIndex,
    const_state: *ConstVisitState,
    arg_nodes: *const [2]std.zig.Ast.Node.Index,
    arg_len: u8,
    is_max: bool,
) ?u64 {
    assert(arg_len <= arg_nodes.len);
    assert(const_state.len <= const_state.names.len);
    if (arg_len > arg_nodes.len) return null;
    if (const_state.len > const_state.names.len) return null;
    if (arg_len != 2) return null;
    const lhs = eval_const_u64_expr(tree, arg_nodes[0], symbols, const_state) orelse return null;
    const rhs = eval_const_u64_expr(tree, arg_nodes[1], symbols, const_state) orelse return null;
    if (is_max) {
        return @max(lhs, rhs);
    }
    return @min(lhs, rhs);
}

fn resolve_const_identifier_value(
    tree: *const std.zig.Ast,
    name: []const u8,
    symbols: *LargeArgSymbolIndex,
    const_state: *ConstVisitState,
) ?u64 {
    assert(name.len > 0);
    assert(const_state.len <= const_state.names.len);
    if (name.len == 0) return null;
    if (const_state.len > const_state.names.len) return null;
    if (!push_const_visiting_name(const_state, name)) return null;
    defer pop_const_visiting_name(const_state);

    const expr_node = symbols.const_expr_nodes.get(name) orelse return null;
    return eval_const_u64_expr(tree, expr_node, symbols, const_state);
}

fn parse_unsigned_integer_literal(text_input: []const u8) ?u64 {
    assert(text_input.len > 0);
    assert(text_input.len <= 4096);
    if (text_input.len == 0) return null;
    const text = std.mem.trim(u8, text_input, " \t\r\n");
    if (text.len == 0) return null;

    var compact: [128]u8 = undefined;
    var compact_len: usize = 0;
    for (text) |c| {
        if (c == '_') continue;
        if (compact_len >= compact.len) return null;
        compact[compact_len] = c;
        compact_len += 1;
    }
    if (compact_len == 0) return null;

    var digits = compact[0..compact_len];
    const base_info = integer_literal_base_info(digits);
    const base = base_info.base;
    digits = digits[base_info.prefix_len..];
    if (digits.len == 0) return null;

    return std.fmt.parseInt(u64, digits, base) catch null;
}

const IntegerLiteralBaseInfo = struct {
    base: u8,
    prefix_len: usize,
};

fn integer_literal_base_info(digits: []const u8) IntegerLiteralBaseInfo {
    assert(digits.len > 0);
    if (digits.len == 0) {
        return .{ .base = 10, .prefix_len = 0 };
    }
    if (digits.len <= 2 or digits[0] != '0') {
        return .{ .base = 10, .prefix_len = 0 };
    }

    const prefix = std.ascii.toLower(digits[1]);
    return switch (prefix) {
        'x' => .{ .base = 16, .prefix_len = 2 },
        'o' => .{ .base = 8, .prefix_len = 2 },
        'b' => .{ .base = 2, .prefix_len = 2 },
        else => .{ .base = 10, .prefix_len = 0 },
    };
}

fn push_const_visiting_name(state: *ConstVisitState, name: []const u8) bool {
    assert(name.len > 0);
    assert(state.len <= state.names.len);
    if (name.len == 0) return false;
    if (state.len > state.names.len) return false;
    if (has_const_visiting_name(state, name)) return false;
    if (state.len >= state.names.len) return false;
    state.names[@as(usize, state.len)] = name;
    state.len += 1;
    return true;
}

fn pop_const_visiting_name(state: *ConstVisitState) void {
    if (state.len == 0) return;
    state.len -= 1;
}

fn has_const_visiting_name(state: *const ConstVisitState, name: []const u8) bool {
    assert(name.len > 0);
    if (name.len == 0) return false;
    for (state.names[0..@as(usize, state.len)]) |entry| {
        if (std.mem.eql(u8, entry, name)) {
            return true;
        }
    }
    return false;
}

fn push_type_visiting_name(state: *TypeVisitState, name: []const u8) bool {
    assert(name.len > 0);
    assert(state.len <= state.names.len);
    if (name.len == 0) return false;
    if (state.len > state.names.len) return false;
    if (has_type_visiting_name(state, name)) return false;
    if (state.len >= state.names.len) return false;
    state.names[@as(usize, state.len)] = name;
    state.len += 1;
    return true;
}

fn pop_type_visiting_name(state: *TypeVisitState) void {
    if (state.len == 0) return;
    state.len -= 1;
}

fn has_type_visiting_name(state: *const TypeVisitState, name: []const u8) bool {
    assert(name.len > 0);
    if (name.len == 0) return false;
    for (state.names[0..@as(usize, state.len)]) |entry| {
        if (std.mem.eql(u8, entry, name)) {
            return true;
        }
    }
    return false;
}

fn unwrap_optional_grouped_type(
    tree: *const std.zig.Ast,
    type_node: std.zig.Ast.Node.Index,
) ?std.zig.Ast.Node.Index {
    assert(tree.nodes.len > 0);
    if (type_node == .root or @intFromEnum(type_node) >= tree.nodes.len) return null;

    var current = type_node;
    while (current != .root and @intFromEnum(current) < tree.nodes.len) {
        const tag = tree.nodes.items(.tag)[@intFromEnum(current)];
        if (tag == .optional_type) {
            current = tree.nodeData(current).node;
            continue;
        }
        if (tag == .grouped_expression) {
            current = tree.nodeData(current).node_and_token[0];
            continue;
        }
        return current;
    }
    return null;
}

fn analyze_pointer_depth_param(
    tree: *const std.zig.Ast,
    type_expr: std.zig.Ast.Node.Index,
    file_path: []const u8,
    result: *Result,
) !void {
    assert(file_path.len > 0);
    assert(type_expr == .root or @intFromEnum(type_expr) < tree.nodes.len);
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    if (file_path.len == 0) return;
    if (type_expr == .root or @intFromEnum(type_expr) >= tree.nodes.len) return;
    const depth = pointer_depth(tree, type_expr);
    if (depth >= 2) {
        try append_diag(
            result,
            .critical,
            .N09_POINTER_DISCIPLINE,
            file_path,
            "multi-level pointer is forbidden (`**T` or deeper)",
        );
    }
}

fn analyze_function_pointer_param(
    allocator: std.mem.Allocator,
    tree: *const std.zig.Ast,
    type_expr: std.zig.Ast.Node.Index,
    file_path: []const u8,
    fn_name: []const u8,
    param_name: ?[]const u8,
    result: *Result,
) !void {
    assert(file_path.len > 0);
    assert(fn_name.len > 0);
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    if (file_path.len == 0) return;
    if (fn_name.len == 0) return;
    if (!is_function_pointer_type(tree, type_expr)) return;

    var msg: []const u8 = undefined;
    if (param_name) |name| {
        msg = try std.fmt.allocPrint(
            allocator,
            "N09_POINTER_DISCIPLINE: parameter `{s}` in `{s}` uses function pointer; " ++
                "prefer explicit enum/tag dispatch",
            .{ name, fn_name },
        );
    } else {
        msg = try std.fmt.allocPrint(
            allocator,
            "N09_POINTER_DISCIPLINE: function `{s}` uses function-pointer parameter; " ++
                "prefer explicit enum/tag dispatch",
            .{fn_name},
        );
    }
    try append_diag(result, .critical, .N09_POINTER_DISCIPLINE, file_path, msg);
}

fn is_function_pointer_type(tree: *const std.zig.Ast, type_node: std.zig.Ast.Node.Index) bool {
    assert(type_node == .root or @intFromEnum(type_node) < tree.nodes.len);
    assert(tree.nodes.items(.main_token).len == tree.nodes.len);
    if (type_node == .root or @intFromEnum(type_node) >= tree.nodes.len) return false;
    const tag = tree.nodes.items(.tag)[@intFromEnum(type_node)];

    if (tag == .optional_type) {
        return is_function_pointer_type(tree, tree.nodeData(type_node).node);
    }
    if (tag == .grouped_expression) {
        return is_function_pointer_type(tree, tree.nodeData(type_node).node_and_token[0]);
    }

    if (tree.fullPtrType(type_node)) |ptr| {
        if (is_function_type_node(tree, ptr.ast.child_type)) return true;
        return is_function_pointer_type(tree, ptr.ast.child_type);
    }

    return false;
}

fn is_function_type_node(tree: *const std.zig.Ast, node: std.zig.Ast.Node.Index) bool {
    if (node == .root or @intFromEnum(node) >= tree.nodes.len) return false;
    const tag = tree.nodes.items(.tag)[@intFromEnum(node)];
    return tag == .fn_proto or
        tag == .fn_proto_simple or
        tag == .fn_proto_multi or
        tag == .fn_proto_one;
}

fn update_alias_overlap(
    tree: *const std.zig.Ast,
    type_expr: std.zig.Ast.Node.Index,
    alias_keys: *[16][]const u8,
    alias_key_len: *u32,
    alias_overlap_risk: *bool,
) void {
    assert(type_expr == .root or @intFromEnum(type_expr) < tree.nodes.len);
    assert(@as(usize, alias_key_len.*) <= alias_keys.len);
    if (alias_risk_pointer_key(tree, type_expr)) |key| {
        var seen = false;
        for (alias_keys[0..@as(usize, alias_key_len.*)]) |existing_key| {
            if (std.mem.eql(u8, existing_key, key)) {
                alias_overlap_risk.* = true;
                seen = true;
                break;
            }
        }

        if (!seen and @as(usize, alias_key_len.*) < alias_keys.len) {
            alias_keys[@as(usize, alias_key_len.*)] = key;
            alias_key_len.* += 1;
        }
    }
}

fn analyze_fixed_width_param(
    allocator: std.mem.Allocator,
    tree: *const std.zig.Ast,
    type_expr: std.zig.Ast.Node.Index,
    file_path: []const u8,
    fn_name: []const u8,
    result: *Result,
) !void {
    assert(file_path.len > 0);
    assert(fn_name.len > 0);
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    if (file_path.len == 0) return;
    if (fn_name.len == 0) return;
    if (type_expr == .root or @intFromEnum(type_expr) >= tree.nodes.len) return;
    if (!is_arch_sized_type(tree, type_expr)) return;

    const msg = try std.fmt.allocPrint(
        allocator,
        "TS03_FIXED_WIDTH_TYPES: Parameter uses usize/isize in `{s}`. " ++
            "Use explicitly-sized types (u32, u64, etc.) for " ++
            "protocol/persistence boundaries.",
        .{fn_name},
    );
    try append_diag(result, .warning, .TS03_FIXED_WIDTH_TYPES, file_path, msg);
}

fn analyze_fn_return_type_for_fixed_width(
    allocator: std.mem.Allocator,
    tree: *const std.zig.Ast,
    file_path: []const u8,
    fn_name: []const u8,
    proto: std.zig.Ast.full.FnProto,
    result: *Result,
) !void {
    assert(file_path.len > 0);
    assert(fn_name.len > 0);
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    if (file_path.len == 0) return;
    if (fn_name.len == 0) return;
    const return_type = proto.ast.return_type.unwrap() orelse return;
    if (!is_arch_sized_type(tree, return_type)) return;

    const msg = try std.fmt.allocPrint(
        allocator,
        "TS03_FIXED_WIDTH_TYPES: Return type uses usize/isize in `{s}`. " ++
            "Use explicitly-sized types (u32, u64, etc.) for " ++
            "protocol/persistence boundaries.",
        .{fn_name},
    );
    try append_diag(result, .warning, .TS03_FIXED_WIDTH_TYPES, file_path, msg);
}

fn analyze_fn_return_type_for_in_place_init(
    allocator: std.mem.Allocator,
    tree: *const std.zig.Ast,
    file_path: []const u8,
    fn_name: []const u8,
    proto: std.zig.Ast.full.FnProto,
    large_arg_symbols: *LargeArgSymbolIndex,
    result: *Result,
) !void {
    assert(file_path.len > 0);
    assert(fn_name.len > 0);
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    if (file_path.len == 0) return;
    if (fn_name.len == 0) return;

    const return_type = proto.ast.return_type.unwrap() orelse return;
    if (!is_struct_return_type(tree, return_type, large_arg_symbols)) return;
    const size_bytes = estimated_value_size_bytes(
        tree,
        return_type,
        large_arg_symbols,
    ) orelse return;
    if (size_bytes < large_arg_value_threshold_bytes) return;

    const msg = try std.fmt.allocPrint(
        allocator,
        "TS24_IN_PLACE_INIT: function `{s}` returns ~{d} bytes by value; " ++
            "prefer `out: *T` in-place initialization",
        .{ fn_name, size_bytes },
    );
    try append_diag(result, .warning, .TS24_IN_PLACE_INIT, file_path, msg);
}

fn is_struct_return_type(
    tree: *const std.zig.Ast,
    type_node: std.zig.Ast.Node.Index,
    symbols: *const LargeArgSymbolIndex,
) bool {
    assert(tree.nodes.len > 0);
    const unwrapped_type = unwrap_optional_grouped_type(tree, type_node) orelse return false;

    var container_buf: [2]std.zig.Ast.Node.Index = undefined;
    if (tree.fullContainerDecl(&container_buf, unwrapped_type) != null) {
        return node_is_struct_container_decl(tree, unwrapped_type);
    }

    if (tree.nodes.items(.tag)[@intFromEnum(unwrapped_type)] != .identifier) return false;
    const type_token = tree.nodes.items(.main_token)[@intFromEnum(unwrapped_type)];
    const type_name = tree.tokenSlice(type_token);
    const decl_node = symbols.type_decl_nodes.get(type_name) orelse return false;
    return node_is_struct_container_decl(tree, decl_node);
}

fn node_is_struct_container_decl(
    tree: *const std.zig.Ast,
    node: std.zig.Ast.Node.Index,
) bool {
    var container_buf: [2]std.zig.Ast.Node.Index = undefined;
    const container = tree.fullContainerDecl(&container_buf, node) orelse return false;
    return tree.tokens.items(.tag)[container.ast.main_token] == .keyword_struct;
}

fn analyze_root_var_decl(
    allocator: std.mem.Allocator,
    tree: *const std.zig.Ast,
    file_path: []const u8,
    decl: std.zig.Ast.Node.Index,
    result: *Result,
) !void {
    assert(file_path.len > 0);
    assert(decl == .root or @intFromEnum(decl) < tree.nodes.len);
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    if (file_path.len == 0) return;
    if (decl == .root or @intFromEnum(decl) >= tree.nodes.len) return;
    const var_decl = tree.fullVarDecl(decl) orelse return;
    const mut_tag = tree.tokens.items(.tag)[var_decl.ast.mut_token];

    if (var_decl.ast.type_node.unwrap()) |type_node| {
        try analyze_root_function_pointer_var_decl(
            allocator,
            tree,
            file_path,
            var_decl,
            type_node,
            result,
        );
    }

    if (mut_tag == .keyword_var and var_decl.threadlocal_token == null) {
        try append_diag(
            result,
            .critical,
            .N06_SCOPE_MINIMIZATION,
            file_path,
            "mutable global state is forbidden (Rule 6)",
        );
        try append_diag(
            result,
            .warning,
            .TS08_SCOPE,
            file_path,
            "mutable global state widens scope; keep state local",
        );
    }

    if (mut_tag == .keyword_const and try const_global_is_risky(allocator, tree, var_decl)) {
        try append_diag(
            result,
            .warning,
            .N06_SCOPE_MINIMIZATION,
            file_path,
            "const global contains pointer/allocator; manual audit required",
        );
        try append_diag(
            result,
            .warning,
            .TS08_SCOPE,
            file_path,
            "prefer narrower declaration scope over global pointer state",
        );
    }
}

fn analyze_root_function_pointer_var_decl(
    allocator: std.mem.Allocator,
    tree: *const std.zig.Ast,
    file_path: []const u8,
    var_decl: std.zig.Ast.full.VarDecl,
    type_node: std.zig.Ast.Node.Index,
    result: *Result,
) !void {
    assert(file_path.len > 0);
    assert(type_node == .root or @intFromEnum(type_node) < tree.nodes.len);
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    if (file_path.len == 0) return;
    if (type_node == .root or @intFromEnum(type_node) >= tree.nodes.len) return;
    if (!is_function_pointer_type(tree, type_node)) return;

    const name_token = var_decl.ast.mut_token + 1;
    if (name_token >= tree.tokens.len or tree.tokens.items(.tag)[name_token] != .identifier) {
        return;
    }
    const var_name = tree.tokenSlice(name_token);
    const msg = try std.fmt.allocPrint(
        allocator,
        "N09_POINTER_DISCIPLINE: global `{s}` uses function pointer type; " ++
            "prefer explicit enum/tag dispatch",
        .{var_name},
    );
    try append_diag(result, .critical, .N09_POINTER_DISCIPLINE, file_path, msg);
}

fn analyze_function_declaration_locality(
    allocator: std.mem.Allocator,
    tree: *const std.zig.Ast,
    file_path: []const u8,
    fn_name: []const u8,
    body_node: std.zig.Ast.Node.Index,
    result: *Result,
) !void {
    assert(file_path.len > 0);
    assert(fn_name.len > 0);
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    if (file_path.len == 0) return;
    if (fn_name.len == 0) return;

    var statements = std.array_list.Managed(std.zig.Ast.Node.Index).init(allocator);
    defer statements.deinit();
    try collect_function_top_level_statements(tree, body_node, &statements);

    for (statements.items, 0..) |stmt, stmt_index| {
        if (stmt_index > std.math.maxInt(u32)) continue;
        const statement_index: u32 = @intCast(stmt_index);
        const candidate = locality_decl_candidate(tree, stmt, statement_index) orelse continue;
        try emit_locality_gap_diag(
            allocator,
            tree,
            statements.items,
            file_path,
            fn_name,
            candidate,
            result,
        );
    }
}

const LocalityDeclCandidate = struct {
    name: []const u8,
    declaration_index: u32,
    search_start_index: u32,
};

fn locality_decl_candidate(
    tree: *const std.zig.Ast,
    statement: std.zig.Ast.Node.Index,
    statement_index: u32,
) ?LocalityDeclCandidate {
    assert(statement == .root or @intFromEnum(statement) < tree.nodes.len);
    assert(statement_index <= std.math.maxInt(u32));
    if (statement == .root or @intFromEnum(statement) >= tree.nodes.len) return null;
    const tag = tree.nodes.items(.tag)[@intFromEnum(statement)];
    if (!is_local_var_decl_tag(tag)) return null;

    const var_decl = tree.fullVarDecl(statement) orelse return null;
    const name_token = var_decl.ast.mut_token + 1;
    if (name_token >= tree.tokens.len) return null;
    if (tree.tokens.items(.tag)[name_token] != .identifier) return null;

    const var_name = tree.tokenSlice(name_token);
    if (var_name.len == 0 or std.mem.eql(u8, var_name, "_")) return null;
    if (statement_index == std.math.maxInt(u32)) return null;

    return .{
        .name = var_name,
        .declaration_index = statement_index,
        .search_start_index = statement_index + 1,
    };
}

fn emit_locality_gap_diag(
    allocator: std.mem.Allocator,
    tree: *const std.zig.Ast,
    statements: []const std.zig.Ast.Node.Index,
    file_path: []const u8,
    fn_name: []const u8,
    candidate: LocalityDeclCandidate,
    result: *Result,
) !void {
    assert(file_path.len > 0);
    assert(fn_name.len > 0);
    assert(candidate.name.len > 0);
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    if (file_path.len == 0) return;
    if (fn_name.len == 0) return;
    if (candidate.name.len == 0) return;
    const first_use_index = first_statement_using_identifier(
        tree,
        statements,
        candidate.search_start_index,
        candidate.name,
    ) orelse return;

    const gap = @as(usize, first_use_index - candidate.declaration_index);
    if (gap < declaration_locality_gap_statements) return;

    const msg = try std.fmt.allocPrint(
        allocator,
        "`{s}` in `{s}` is declared {d} statements " ++
            "before first use; narrow declaration scope",
        .{ candidate.name, fn_name, gap },
    );
    try diagnostics.append_pair(
        result,
        .warning,
        .N06_SCOPE_MINIMIZATION,
        .TS08_SCOPE,
        file_path,
        msg,
    );
}

fn collect_function_top_level_statements(
    tree: *const std.zig.Ast,
    body_node: std.zig.Ast.Node.Index,
    out: *std.array_list.Managed(std.zig.Ast.Node.Index),
) !void {
    assert(tree.nodes.items(.tag).len == tree.nodes.len);
    assert(body_node == .root or @intFromEnum(body_node) < tree.nodes.len);
    if (body_node == .root or @intFromEnum(body_node) >= tree.nodes.len) return;
    const tag = tree.nodes.items(.tag)[@intFromEnum(body_node)];

    switch (tag) {
        .block,
        .block_semicolon,
        => {
            const stmts = tree.extraDataSlice(
                tree.nodeData(body_node).extra_range,
                std.zig.Ast.Node.Index,
            );
            for (stmts) |stmt| {
                try out.append(stmt);
            }
        },
        .block_two,
        .block_two_semicolon,
        => {
            const first, const second = tree.nodeData(body_node).opt_node_and_opt_node;
            if (first.unwrap()) |first_stmt| {
                try out.append(first_stmt);
            }
            if (second.unwrap()) |second_stmt| {
                try out.append(second_stmt);
            }
        },
        else => {
            try out.append(body_node);
        },
    }
}

fn is_local_var_decl_tag(tag: std.zig.Ast.Node.Tag) bool {
    return tag == .local_var_decl or tag == .simple_var_decl or tag == .aligned_var_decl;
}

fn first_statement_using_identifier(
    tree: *const std.zig.Ast,
    statements: []const std.zig.Ast.Node.Index,
    start_index: u32,
    identifier: []const u8,
) ?u32 {
    assert(identifier.len > 0);
    if (identifier.len == 0) return null;
    var index = start_index;
    while (@as(usize, index) < statements.len) : (index += 1) {
        if (node_contains_identifier_token(tree, statements[@as(usize, index)], identifier)) {
            return index;
        }
    }
    return null;
}

fn node_contains_identifier_token(
    tree: *const std.zig.Ast,
    node: std.zig.Ast.Node.Index,
    identifier: []const u8,
) bool {
    assert(identifier.len > 0);
    assert(node == .root or @intFromEnum(node) < tree.nodes.len);
    if (identifier.len == 0) return false;
    if (node == .root or @intFromEnum(node) >= tree.nodes.len) return false;
    const first = tree.firstToken(node);
    const last = tree.lastToken(node);
    if (first >= tree.tokens.len) return false;
    if (last >= tree.tokens.len) return false;
    if (first > last) return false;

    const end = @as(usize, last) + 1;
    for (@as(usize, first)..end) |token_index| {
        const token: std.zig.Ast.TokenIndex = @intCast(token_index);
        if (tree.tokens.items(.tag)[token] != .identifier) continue;
        if (std.mem.eql(u8, tree.tokenSlice(token), identifier)) {
            return true;
        }
    }
    return false;
}

fn const_global_is_risky(
    allocator: std.mem.Allocator,
    tree: *const std.zig.Ast,
    var_decl: std.zig.Ast.full.VarDecl,
) !bool {
    assert(tree.nodes.len > 0);
    assert(tree.tokens.len > 0);
    if (tree.nodes.len == 0) return false;
    if (tree.tokens.len == 0) return false;
    var type_risky = false;
    if (var_decl.ast.type_node.unwrap()) |type_node| {
        type_risky = type_has_pointer_or_optional(tree, type_node);
    }
    var init_visited = std.AutoHashMap(std.zig.Ast.Node.Index, void).init(allocator);
    defer init_visited.deinit();
    var init_risky = false;
    if (var_decl.ast.init_node.unwrap()) |init_node| {
        init_risky = expr_contains_allocator(tree, init_node, &init_visited);
    }
    return type_risky or init_risky;
}

fn detect_local_pointer_depth(
    tree: *const std.zig.Ast,
    node: std.zig.Ast.Node.Index,
    file_path: []const u8,
    result: *Result,
) anyerror!void {
    assert(file_path.len > 0);
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    if (file_path.len == 0) return;
    if (node == .root or @intFromEnum(node) >= tree.nodes.len) return;

    var ctx = PointerDepthVisitCtx{
        .file_path = file_path,
        .result = result,
    };
    try ast_walk.walk(tree, node, &ctx, pointer_depth_visit_node);
}

const PointerDepthVisitCtx = struct {
    file_path: []const u8,
    result: *Result,
};

fn pointer_depth_visit_node(
    tree: *const std.zig.Ast,
    node: std.zig.Ast.Node.Index,
    ctx_opaque: *anyopaque,
) anyerror!void {
    const ctx: *PointerDepthVisitCtx = @ptrCast(@alignCast(ctx_opaque));
    try detect_pointer_depth_here(tree, node, ctx.file_path, ctx.result);
}

fn detect_pointer_depth_here(
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
        .local_var_decl,
        .simple_var_decl,
        .aligned_var_decl,
        => {
            if (tree.fullVarDecl(node)) |var_decl| {
                if (var_decl.ast.type_node.unwrap()) |type_node| {
                    if (pointer_depth(tree, type_node) >= 2) {
                        try append_diag(
                            result,
                            .critical,
                            .N09_POINTER_DISCIPLINE,
                            file_path,
                            "multi-level pointer is forbidden (`**T` or deeper)",
                        );
                    }
                    if (is_function_pointer_type(tree, type_node)) {
                        const name_token = var_decl.ast.mut_token + 1;
                        if (name_token < tree.tokens.len and
                            tree.tokens.items(.tag)[name_token] == .identifier)
                        {
                            const name = tree.tokenSlice(name_token);
                            const msg = try std.fmt.allocPrint(
                                result.diagnostics.allocator,
                                "N09_POINTER_DISCIPLINE: local `{s}` uses " ++
                                    "function pointer type; " ++
                                    "prefer explicit enum/tag dispatch",
                                .{name},
                            );
                            try append_diag(
                                result,
                                .critical,
                                .N09_POINTER_DISCIPLINE,
                                file_path,
                                msg,
                            );
                        }
                    }
                }
            }
        },
        else => {},
    }
}

fn pointer_depth(tree: *const std.zig.Ast, type_node: std.zig.Ast.Node.Index) u8 {
    assert(tree.nodes.len > 0);
    if (type_node == .root or @intFromEnum(type_node) >= tree.nodes.len) return 0;

    const tag = tree.nodes.items(.tag)[@intFromEnum(type_node)];
    if (tag == .optional_type) {
        const child = tree.nodeData(type_node).node;
        return pointer_depth(tree, child);
    }
    if (tree.fullPtrType(type_node)) |ptr| {
        return 1 + pointer_depth(tree, ptr.ast.child_type);
    }
    if (tag == .grouped_expression) {
        return pointer_depth(tree, tree.nodeData(type_node).node_and_token[0]);
    }
    return 0;
}

fn type_has_pointer_or_optional(tree: *const std.zig.Ast, type_node: std.zig.Ast.Node.Index) bool {
    if (type_node == .root or @intFromEnum(type_node) >= tree.nodes.len) return false;
    const tag = tree.nodes.items(.tag)[@intFromEnum(type_node)];
    if (tag == .optional_type) return true;
    if (tree.fullPtrType(type_node)) |_| return true;
    return false;
}

fn alias_risk_pointer_key(tree: *const std.zig.Ast, type_node: std.zig.Ast.Node.Index) ?[]const u8 {
    if (type_node == .root or @intFromEnum(type_node) >= tree.nodes.len) return null;
    if (tree.nodes.items(.tag)[@intFromEnum(type_node)] == .optional_type) {
        return alias_risk_pointer_key(tree, tree.nodeData(type_node).node);
    }
    if (tree.fullPtrType(type_node)) |ptr| {
        if (ptr.size == .slice or ptr.const_token != null) return null;
        return type_alias_key(tree, ptr.ast.child_type);
    }
    return null;
}

fn type_alias_key(tree: *const std.zig.Ast, type_node: std.zig.Ast.Node.Index) []const u8 {
    if (type_node == .root or @intFromEnum(type_node) >= tree.nodes.len) return "<unknown>";

    const tag = tree.nodes.items(.tag)[@intFromEnum(type_node)];
    return switch (tag) {
        .grouped_expression => type_alias_key(tree, tree.nodeData(type_node).node_and_token[0]),
        .optional_type => type_alias_key(tree, tree.nodeData(type_node).node),
        .identifier => tree.tokenSlice(tree.nodes.items(.main_token)[@intFromEnum(type_node)]),
        .field_access => tree.tokenSlice(tree.nodeData(type_node).node_and_token[1]),
        .call,
        .call_comma,
        .call_one,
        .call_one_comma,
        => blk: {
            var call_buf: [1]std.zig.Ast.Node.Index = undefined;
            const call = tree.fullCall(&call_buf, type_node) orelse break :blk "<call-type>";
            break :blk type_alias_key(tree, call.ast.fn_expr);
        },
        else => tree.tokenSlice(tree.nodes.items(.main_token)[@intFromEnum(type_node)]),
    };
}

fn expr_contains_allocator(
    tree: *const std.zig.Ast,
    expr_node: std.zig.Ast.Node.Index,
    visited: *std.AutoHashMap(std.zig.Ast.Node.Index, void),
) bool {
    assert(tree.nodes.len > 0);
    assert(tree.nodes.items(.main_token).len == tree.nodes.len);
    if (expr_node == .root or @intFromEnum(expr_node) >= tree.nodes.len) return false;
    if (visited.count() > ast_walk_nodes_max) return false;
    if (visited.contains(expr_node)) return false;
    visited.put(expr_node, {}) catch return false;

    const tag = tree.nodes.items(.tag)[@intFromEnum(expr_node)];
    if (expr_is_allocator_symbol(tree, expr_node, tag)) return true;
    return expr_children_contain_allocator(tree, expr_node, tag, visited);
}

fn expr_is_allocator_symbol(
    tree: *const std.zig.Ast,
    expr_node: std.zig.Ast.Node.Index,
    tag: std.zig.Ast.Node.Tag,
) bool {
    assert(expr_node == .root or @intFromEnum(expr_node) < tree.nodes.len);
    assert(tree.nodes.items(.main_token).len == tree.nodes.len);
    if (expr_node == .root or @intFromEnum(expr_node) >= tree.nodes.len) return false;
    if (tag == .identifier) {
        const token = tree.nodes.items(.main_token)[@intFromEnum(expr_node)];
        const ident = tree.tokenSlice(token);
        return std.mem.eql(u8, ident, "allocator") or
            std.mem.eql(u8, ident, "page_allocator");
    }
    if (tag == .field_access) {
        const data = tree.nodeData(expr_node).node_and_token;
        const field_name = tree.tokenSlice(data[1]);
        return std.mem.eql(u8, field_name, "allocator") or
            std.mem.eql(u8, field_name, "page_allocator") or
            std.mem.eql(u8, field_name, "alloc") or
            std.mem.eql(u8, field_name, "create");
    }
    return false;
}

fn expr_children_contain_allocator(
    tree: *const std.zig.Ast,
    expr_node: std.zig.Ast.Node.Index,
    tag: std.zig.Ast.Node.Tag,
    visited: *std.AutoHashMap(std.zig.Ast.Node.Index, void),
) bool {
    assert(expr_node == .root or @intFromEnum(expr_node) < tree.nodes.len);
    assert(visited.count() <= ast_walk_nodes_max + 1);
    if (expr_node == .root or @intFromEnum(expr_node) >= tree.nodes.len) return false;
    switch (tag) {
        .field_access,
        .unwrap_optional,
        .grouped_expression,
        => {
            const child = tree.nodeData(expr_node).node_and_token[0];
            return expr_contains_allocator(tree, child, visited);
        },
        .@"try" => {
            const child = tree.nodeData(expr_node).node;
            return expr_contains_allocator(tree, child, visited);
        },
        .bool_and,
        .bool_or,
        .@"catch",
        .@"orelse",
        .assign,
        => {
            const pair = tree.nodeData(expr_node).node_and_node;
            return expr_contains_allocator(tree, pair[0], visited) or
                expr_contains_allocator(tree, pair[1], visited);
        },
        .call,
        .call_comma,
        .call_one,
        .call_one_comma,
        => return call_expr_contains_allocator(tree, expr_node, visited),
        else => return false,
    }
}

fn call_expr_contains_allocator(
    tree: *const std.zig.Ast,
    expr_node: std.zig.Ast.Node.Index,
    visited: *std.AutoHashMap(std.zig.Ast.Node.Index, void),
) bool {
    assert(expr_node == .root or @intFromEnum(expr_node) < tree.nodes.len);
    assert(visited.count() <= ast_walk_nodes_max + 1);
    if (expr_node == .root or @intFromEnum(expr_node) >= tree.nodes.len) return false;
    var call_buf: [1]std.zig.Ast.Node.Index = undefined;
    const call = tree.fullCall(&call_buf, expr_node) orelse return false;
    if (expr_contains_allocator(tree, call.ast.fn_expr, visited)) return true;
    for (call.ast.params) |param| {
        if (expr_contains_allocator(tree, param, visited)) return true;
    }
    return false;
}


fn is_arch_sized_type(tree: *const std.zig.Ast, type_node: std.zig.Ast.Node.Index) bool {
    assert(tree.nodes.len > 0);
    assert(tree.nodes.items(.main_token).len == tree.nodes.len);
    if (type_node == .root or @intFromEnum(type_node) >= tree.nodes.len) return false;

    const tag = tree.nodes.items(.tag)[@intFromEnum(type_node)];

    // Handle optional types (e.g., ?usize)
    if (tag == .optional_type) {
        const child = tree.nodeData(type_node).node;
        return is_arch_sized_type(tree, child);
    }

    // Handle pointer types (e.g., *usize, []usize)
    if (tree.fullPtrType(type_node)) |ptr| {
        return is_arch_sized_type(tree, ptr.ast.child_type);
    }

    // Handle grouped expressions
    if (tag == .grouped_expression) {
        const child = tree.nodeData(type_node).node_and_token[0];
        return is_arch_sized_type(tree, child);
    }

    // Check if it's a usize or isize identifier
    if (tag == .identifier) {
        const token = tree.nodes.items(.main_token)[@intFromEnum(type_node)];
        const name = tree.tokenSlice(token);
        return std.mem.eql(u8, name, "usize") or std.mem.eql(u8, name, "isize");
    }

    return false;
}


const std = @import("std");
const ast_walk = @import("../ast_walk.zig");
const assert = std.debug.assert;

const Ast = std.zig.Ast;
const lookup_walk_nodes_max: usize = 4000;

pub const SymbolRoleMask = u8;
pub const role_queue: SymbolRoleMask = 1 << 0;
pub const role_event_source: SymbolRoleMask = 1 << 1;
pub const role_control_plane: SymbolRoleMask = 1 << 2;
pub const role_data_plane: SymbolRoleMask = 1 << 3;
pub const role_boundary: SymbolRoleMask = 1 << 4;

pub const FunctionRoleFacts = struct {
    role_mask: SymbolRoleMask = 0,
    has_mutable_self_param: bool = false,
};

pub const SemanticIndex = struct {
    allocator: std.mem.Allocator,
    tree: *const Ast,
    role_cache: std.StringHashMap(SymbolRoleMask),
    fn_cache: std.StringHashMap(FunctionRoleFacts),

    pub fn init(allocator: std.mem.Allocator, tree: *const Ast) SemanticIndex {
        return .{
            .allocator = allocator,
            .tree = tree,
            .role_cache = std.StringHashMap(SymbolRoleMask).init(allocator),
            .fn_cache = std.StringHashMap(FunctionRoleFacts).init(allocator),
        };
    }

    pub fn deinit(self: *SemanticIndex) void {
        self.role_cache.deinit();
        self.fn_cache.deinit();
    }

    pub fn symbol_role_mask_for_identifier_cached(
        self: *SemanticIndex,
        identifier: []const u8,
    ) SymbolRoleMask {
        if (identifier.len == 0) return 0;
        if (self.role_cache.get(identifier)) |cached| {
            return cached;
        }

        const computed = symbol_role_mask_for_identifier(self.tree, identifier);
        self.role_cache.put(identifier, computed) catch |err| cache_put_failed(err);
        return computed;
    }

    pub fn function_role_facts_by_name_cached(
        self: *SemanticIndex,
        fn_name: []const u8,
    ) FunctionRoleFacts {
        if (fn_name.len == 0) return .{};
        if (self.fn_cache.get(fn_name)) |cached| {
            return cached;
        }

        const computed = function_role_facts_by_name(self.tree, fn_name);
        self.fn_cache.put(fn_name, computed) catch |err| cache_put_failed(err);
        return computed;
    }
};

fn cache_put_failed(err: anyerror) noreturn {
    std.debug.panic("semantic cache put failed: {}", .{err});
}

const SymbolLookupCtx = struct {
    identifier: []const u8,
    mask: *SymbolRoleMask,
};

const FunctionRoleFactsLookupCtx = struct {
    fn_name: []const u8,
    facts: *FunctionRoleFacts,
    found: bool = false,
};

pub fn has_role(mask: SymbolRoleMask, role: SymbolRoleMask) bool {
    return (mask & role) != 0;
}

pub fn token_has_queue_role_hint(token: []const u8) bool {
    assert(token.len > 0);
    if (token.len == 0) return false;
    return contains_ascii_case_insensitive(token, "queue") or
        contains_ascii_case_insensitive(token, "fifo") or
        contains_ascii_case_insensitive(token, "ring") or
        contains_ascii_case_insensitive(token, "channel") or
        contains_ascii_case_insensitive(token, "mailbox");
}

pub fn token_has_event_role_hint(token: []const u8) bool {
    assert(token.len > 0);
    if (token.len == 0) return false;
    return contains_ascii_case_insensitive(token, "event") or
        contains_ascii_case_insensitive(token, "socket") or
        contains_ascii_case_insensitive(token, "stream") or
        contains_ascii_case_insensitive(token, "listener") or
        contains_ascii_case_insensitive(token, "receiver") or
        contains_ascii_case_insensitive(token, "source");
}

pub fn token_has_control_role_hint(token: []const u8) bool {
    assert(token.len > 0);
    if (token.len == 0) return false;
    return contains_ascii_case_insensitive(token, "control") or
        contains_ascii_case_insensitive(token, "config") or
        contains_ascii_case_insensitive(token, "admin") or
        contains_ascii_case_insensitive(token, "policy") or
        contains_ascii_case_insensitive(token, "metadata");
}

pub fn token_has_data_role_hint(token: []const u8) bool {
    assert(token.len > 0);
    if (token.len == 0) return false;
    return contains_ascii_case_insensitive(token, "data") or
        contains_ascii_case_insensitive(token, "request") or
        contains_ascii_case_insensitive(token, "packet") or
        contains_ascii_case_insensitive(token, "storage") or
        contains_ascii_case_insensitive(token, "replica") or
        contains_ascii_case_insensitive(token, "batch") or
        contains_ascii_case_insensitive(token, "log");
}

pub fn token_has_boundary_role_hint(token: []const u8) bool {
    assert(token.len > 0);
    if (token.len == 0) return false;
    return contains_ascii_case_insensitive(token, "boundary") or
        contains_ascii_case_insensitive(token, "handoff") or
        contains_ascii_case_insensitive(token, "dispatch") or
        contains_ascii_case_insensitive(token, "route") or
        contains_ascii_case_insensitive(token, "bridge");
}

pub fn contains_ascii_case_insensitive(haystack: []const u8, needle: []const u8) bool {
    assert(haystack.len <= std.math.maxInt(u32));
    assert(needle.len <= std.math.maxInt(u32));
    if (needle.len == 0) return true;
    if (haystack.len < needle.len) return false;

    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        var match = true;
        var j: usize = 0;
        while (j < needle.len) : (j += 1) {
            if (std.ascii.toLower(haystack[i + j]) != std.ascii.toLower(needle[j])) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

fn symbol_lookup_visit_node(
    tree: *const Ast,
    node: Ast.Node.Index,
    ctx_opaque: *anyopaque,
) anyerror!void {
    const ctx: *SymbolLookupCtx = @ptrCast(@alignCast(ctx_opaque));
    const tag = tree.nodes.items(.tag)[@intFromEnum(node)];
    if (is_var_decl_tag(tag)) {
        collect_symbol_role_from_var_decl(tree, node, ctx.identifier, ctx.mask);
    }
}

fn is_var_decl_tag(tag: Ast.Node.Tag) bool {
    return tag == .global_var_decl or
        tag == .local_var_decl or
        tag == .simple_var_decl or
        tag == .aligned_var_decl;
}

pub fn symbol_role_mask_for_identifier(tree: *const Ast, identifier: []const u8) SymbolRoleMask {
    assert(identifier.len > 0);
    assert(tree.nodes.len > 0);
    if (identifier.len == 0) return 0;
    var out: SymbolRoleMask = 0;

    for (tree.rootDecls()) |decl| {
        const tag = tree.nodes.items(.tag)[@intFromEnum(decl)];
        switch (tag) {
            .fn_decl => scan_symbol_role_from_fn_decl(tree, decl, identifier, &out),
            .global_var_decl,
            .local_var_decl,
            .simple_var_decl,
            .aligned_var_decl,
            => collect_symbol_role_from_var_decl(tree, decl, identifier, &out),
            else => {},
        }
    }

    return out;
}

fn scan_symbol_role_from_fn_decl(
    tree: *const Ast,
    decl: Ast.Node.Index,
    identifier: []const u8,
    out: *SymbolRoleMask,
) void {
    assert(identifier.len > 0);
    assert(decl == .root or @intFromEnum(decl) < tree.nodes.len);
    if (identifier.len == 0) return;
    var fn_buf: [1]Ast.Node.Index = undefined;
    const proto = tree.fullFnProto(&fn_buf, decl) orelse return;

    var it = proto.iterate(tree);
    while (it.next()) |param| {
        const name_token = param.name_token orelse continue;
        if (!std.mem.eql(u8, tree.tokenSlice(name_token), identifier)) continue;
        if (param.type_expr) |type_expr| {
            out.* |= role_mask_from_type_or_init_node(tree, type_expr);
        }
    }

    const body_node = tree.nodeData(decl).node_and_node[1];
    if (body_node == .root or @intFromEnum(body_node) >= tree.nodes.len) return;
    var ctx = SymbolLookupCtx{ .identifier = identifier, .mask = out };
    ast_walk.walk(
        tree,
        body_node,
        &ctx,
        symbol_lookup_visit_node,
    ) catch |err| walk_failed(err);
}

pub fn function_role_facts_by_name(tree: *const Ast, fn_name: []const u8) FunctionRoleFacts {
    assert(fn_name.len > 0);
    if (fn_name.len == 0) return .{};

    var facts = FunctionRoleFacts{};
    var ctx = FunctionRoleFactsLookupCtx{
        .fn_name = fn_name,
        .facts = &facts,
    };

    for (tree.rootDecls()) |decl| {
        ast_walk.walk_with_options(
            tree,
            decl,
            &ctx,
            function_role_facts_visit_node,
            .{ .max_nodes = lookup_walk_nodes_max },
        ) catch |err| walk_failed(err);
        if (ctx.found) break;
    }

    return facts;
}

fn collect_symbol_role_from_var_decl(
    tree: *const Ast,
    decl_node: Ast.Node.Index,
    identifier: []const u8,
    mask: *SymbolRoleMask,
) void {
    assert(identifier.len > 0);
    assert(decl_node == .root or @intFromEnum(decl_node) < tree.nodes.len);
    if (identifier.len == 0) return;
    if (decl_node == .root or @intFromEnum(decl_node) >= tree.nodes.len) return;
    const var_decl = tree.fullVarDecl(decl_node) orelse return;
    const name_token = var_decl.ast.mut_token + 1;
    if (name_token >= tree.tokens.len) return;
    if (tree.tokens.items(.tag)[name_token] != .identifier) return;
    if (!std.mem.eql(u8, tree.tokenSlice(name_token), identifier)) return;

    if (var_decl.ast.type_node.unwrap()) |type_node| {
        mask.* |= role_mask_from_type_or_init_node(tree, type_node);
    }
    if (var_decl.ast.init_node.unwrap()) |init_node| {
        mask.* |= role_mask_from_type_or_init_node(tree, init_node);
    }
}

fn role_mask_from_type_or_init_node(tree: *const Ast, node: Ast.Node.Index) SymbolRoleMask {
    assert(tree.tokens.items(.tag).len == tree.tokens.len);
    assert(tree.nodes.items(.tag).len == tree.nodes.len);
    if (node == .root or @intFromEnum(node) >= tree.nodes.len) return 0;
    const first = tree.firstToken(node);
    const last = tree.lastToken(node);
    if (first >= tree.tokens.len) return 0;
    if (last >= tree.tokens.len) return 0;
    if (first > last) return 0;

    var out: SymbolRoleMask = 0;
    const end = @as(usize, last) + 1;
    for (@as(usize, first)..end) |token_index| {
        const token: Ast.TokenIndex = @intCast(token_index);
        if (tree.tokens.items(.tag)[token] != .identifier) continue;
        note_role_hits_for_identifier(tree.tokenSlice(token), &out);
    }
    return out;
}

fn note_role_hits_for_identifier(ident: []const u8, out: *SymbolRoleMask) void {
    assert(ident.len > 0);
    assert(out.* <= std.math.maxInt(SymbolRoleMask));
    if (ident.len == 0) return;
    if (token_has_queue_role_hint(ident)) out.* |= role_queue;
    if (token_has_event_role_hint(ident)) out.* |= role_event_source;
    if (token_has_control_role_hint(ident)) out.* |= role_control_plane;
    if (token_has_data_role_hint(ident)) out.* |= role_data_plane;
    if (token_has_boundary_role_hint(ident)) out.* |= role_boundary;
}

fn function_role_facts_visit_node(
    tree: *const Ast,
    node: Ast.Node.Index,
    ctx_opaque: *anyopaque,
) anyerror!ast_walk.VisitDecision {
    assert(node == .root or @intFromEnum(node) < tree.nodes.len);
    const tag = tree.nodes.items(.tag)[@intFromEnum(node)];
    if (tag != .fn_decl) return .visit_children;

    var fn_buf: [1]Ast.Node.Index = undefined;
    const proto = tree.fullFnProto(&fn_buf, node) orelse return .skip_children;
    const name_token = proto.name_token orelse return .skip_children;
    const ctx: *FunctionRoleFactsLookupCtx = @ptrCast(@alignCast(ctx_opaque));
    assert(ctx.fn_name.len > 0);
    if (!std.mem.eql(u8, tree.tokenSlice(name_token), ctx.fn_name)) return .skip_children;

    var param_index: u8 = 0;
    var params = proto.iterate(tree);
    while (params.next()) |param| {
        const type_expr = param.type_expr orelse continue;
        ctx.facts.role_mask |= role_mask_from_type_or_init_node(tree, type_expr);
        if (param_index == 0 and param_type_is_mutable_pointer(tree, type_expr)) {
            ctx.facts.has_mutable_self_param = true;
        }
        if (param_index < std.math.maxInt(u8)) {
            param_index += 1;
        }
    }

    ctx.found = true;
    return .stop;
}

fn param_type_is_mutable_pointer(tree: *const Ast, type_expr: Ast.Node.Index) bool {
    assert(tree.nodes.items(.main_token).len == tree.nodes.len);
    assert(type_expr == .root or @intFromEnum(type_expr) < tree.nodes.len);
    if (type_expr == .root or @intFromEnum(type_expr) >= tree.nodes.len) return false;
    var node = type_expr;
    while (node != .root and @intFromEnum(node) < tree.nodes.len) {
        const tag = tree.nodes.items(.tag)[@intFromEnum(node)];
        if (tag == .optional_type) {
            node = tree.nodeData(node).node;
            continue;
        }
        if (tag == .grouped_expression) {
            node = tree.nodeData(node).node_and_token[0];
            continue;
        }
        break;
    }

    if (tree.fullPtrType(node)) |ptr| {
        return ptr.const_token == null;
    }
    return false;
}

fn walk_failed(err: anyerror) noreturn {
    std.debug.panic("semantic walk failed: {}", .{err});
}

const std = @import("std");
const assert = std.debug.assert;
const Ast = std.zig.Ast;
const ast_walk = @import("ast_walk.zig");

const FunctionRecord = struct {
    canonical_name: []const u8,
    file_path: []const u8,
    name: []const u8,
    owner_type: ?[]const u8,
    body_node: ?Ast.Node.Index,
    ast_index: u32,
};

const RootDeclIndexes = struct {
    functions: *std.array_list.Managed(FunctionRecord),
    fn_by_file_name: *std.StringHashMap([]const u8),
    fn_by_file_owner_name: *std.StringHashMap([]const u8),
};

const ModuleRecord = struct {
    path: []const u8,
    source: [:0]const u8,
    ast: Ast,
    imports: std.StringHashMapUnmanaged([]const u8),
};

const BuildCollectCtx = struct {
    graph: *CallGraph,
    zig_files: *std.array_list.Managed([]const u8),
    seen_files: *std.StringHashMap(void),
    modules: *std.array_list.Managed(ModuleRecord),
    functions: *std.array_list.Managed(FunctionRecord),
    fn_by_file_name: *std.StringHashMap([]const u8),
    fn_by_file_owner_name: *std.StringHashMap([]const u8),
};

pub const CallGraph = struct {
    arena: std.heap.ArenaAllocator,
    nodes: std.StringHashMapUnmanaged(void),
    edges: std.StringHashMapUnmanaged(void),
    files: std.ArrayListUnmanaged([]const u8),

    pub fn init(backing_allocator: std.mem.Allocator) CallGraph {
        return .{
            .arena = std.heap.ArenaAllocator.init(backing_allocator),
            .nodes = .{},
            .edges = .{},
            .files = .{},
        };
    }

    pub fn deinit(self: *CallGraph) void {
        const allocator = self.arena.allocator();
        self.nodes.deinit(allocator);
        self.edges.deinit(allocator);
        self.files.deinit(allocator);
        self.arena.deinit();
    }

    fn add_node(self: *CallGraph, node_name: []const u8) !void {
        const allocator = self.arena.allocator();
        const key = try allocator.dupe(u8, node_name);
        try self.nodes.put(allocator, key, {});
    }

    fn add_edge(self: *CallGraph, caller: []const u8, callee: []const u8) !void {
        const allocator = self.arena.allocator();
        try self.add_node(caller);
        try self.add_node(callee);
        if (std.mem.eql(u8, caller, callee)) {
            return;
        }
        const key = try std.fmt.allocPrint(allocator, "{s}->{s}", .{ caller, callee });
        try self.edges.put(allocator, key, {});
    }

    pub fn dump_dot(self: *const CallGraph, writer: anytype) !void {
        try writer.writeAll("digraph call_graph {\n");

        var node_iter = self.nodes.keyIterator();
        while (node_iter.next()) |node_name| {
            try writer.print("    \"{s}\";\n", .{node_name.*});
        }

        var edge_iter = self.edges.keyIterator();
        while (edge_iter.next()) |edge| {
            const sep = std.mem.indexOf(u8, edge.*, "->") orelse continue;
            const caller = edge.*[0..sep];
            const callee = edge.*[sep + 2 ..];
            try writer.print("    \"{s}\" -> \"{s}\";\n", .{ caller, callee });
        }

        try writer.writeAll("}\n");
    }
};

pub fn build_from_path(allocator: std.mem.Allocator, input_path: []const u8) !CallGraph {
    assert(input_path.len > 0);
    assert(std.mem.indexOfScalar(u8, input_path, 0) == null);
    if (input_path.len == 0) return error.InvalidInputPath;
    var graph = CallGraph.init(allocator);
    errdefer graph.deinit();

    const arena = graph.arena.allocator();
    const root_path = try std.fs.path.resolve(arena, &.{input_path});
    var zig_files = std.array_list.Managed([]const u8).init(arena);
    var seen_files = std.StringHashMap(void).init(arena);
    try collect_zig_files(arena, root_path, &zig_files);
    for (zig_files.items) |file_path| {
        try seen_files.put(file_path, {});
    }

    var modules = std.array_list.Managed(ModuleRecord).init(arena);
    assert(modules.items.len == 0);
    var functions = std.array_list.Managed(FunctionRecord).init(arena);
    assert(functions.items.len == 0);

    var fn_by_file_name = std.StringHashMap([]const u8).init(arena);
    var fn_by_file_owner_name = std.StringHashMap([]const u8).init(arena);

    var file_index: usize = 0;
    const zig_file_queue_bound_limit: usize = 16384;
    var collect_ctx = BuildCollectCtx{
        .graph = &graph,
        .zig_files = &zig_files,
        .seen_files = &seen_files,
        .modules = &modules,
        .functions = &functions,
        .fn_by_file_name = &fn_by_file_name,
        .fn_by_file_owner_name = &fn_by_file_owner_name,
    };
    while (file_index < zig_files.items.len) : (file_index += 1) {
        const file_path = zig_files.items[file_index];
        try process_file_and_collect(
            arena,
            file_path,
            @intCast(zig_file_queue_bound_limit),
            &collect_ctx,
        );
    }

    for (functions.items) |function| {
        try graph.add_node(function.canonical_name);
    }

    for (functions.items) |function| {
        const module = modules.items[@as(usize, function.ast_index)];
        try walk_body(
            arena,
            &graph,
            function,
            &module,
            &fn_by_file_name,
            &fn_by_file_owner_name,
        );
    }

    return graph;
}

fn process_file_and_collect(
    arena: std.mem.Allocator,
    file_path: []const u8,
    zig_file_queue_bound_limit: u32,
    ctx: *BuildCollectCtx,
) !void {
    assert(file_path.len > 0);
    assert(zig_file_queue_bound_limit > 0);
    if (file_path.len == 0) return;
    const source = std.Io.Dir.cwd().readFileAllocOptions(
        std.Options.debug_io,
        file_path,
        arena,
        std.Io.Limit.limited(16 * 1024 * 1024),
        .of(u8),
        0,
    ) catch |err| {
        if (err == error.FileNotFound) return;
        return err;
    };

    try ctx.graph.files.append(arena, file_path);
    const ast = try Ast.parse(arena, source, .zig);

    var module = ModuleRecord{
        .path = file_path,
        .source = source,
        .ast = ast,
        .imports = .{},
    };

    const ast_index: u32 = @intCast(ctx.modules.items.len);
    const indexes = RootDeclIndexes{
        .functions = ctx.functions,
        .fn_by_file_name = ctx.fn_by_file_name,
        .fn_by_file_owner_name = ctx.fn_by_file_owner_name,
    };
    try scan_root_decls(arena, &module, ast_index, &indexes);

    var import_iter = module.imports.valueIterator();
    while (import_iter.next()) |imported_path| {
        if (!ctx.seen_files.contains(imported_path.*)) {
            try ctx.seen_files.put(imported_path.*, {});
            if (ctx.zig_files.items.len >= @as(usize, zig_file_queue_bound_limit)) {
                return error.FileQueueBoundExceeded;
            }
            try commit(ctx.zig_files, imported_path.*);
        }
    }
    try ctx.modules.append(module);
}

fn scan_root_decls(
    arena: std.mem.Allocator,
    module: *ModuleRecord,
    ast_index: u32,
    indexes: *const RootDeclIndexes,
) !void {
    assert(module.path.len > 0);
    assert(module.ast.nodes.len > 0);
    for (module.ast.rootDecls()) |decl| {
        switch (module.ast.nodes.items(.tag)[@intFromEnum(decl)]) {
            .fn_decl => {
                var fn_buf: [1]Ast.Node.Index = undefined;
                const proto = module.ast.fullFnProto(&fn_buf, decl).?;
                const name_token = proto.name_token orelse continue;
                const name = module.ast.tokenSlice(name_token);
                const canonical = try std.fmt.allocPrint(arena, "{s}::{s}", .{ module.path, name });
                const key = try std.fmt.allocPrint(arena, "{s}::{s}", .{ module.path, name });

                try indexes.functions.append(.{
                    .canonical_name = canonical,
                    .file_path = module.path,
                    .name = name,
                    .owner_type = null,
                    .body_node = module.ast.nodeData(decl).node_and_node[1],
                    .ast_index = ast_index,
                });

                try indexes.fn_by_file_name.put(key, canonical);
            },
            .global_var_decl,
            .local_var_decl,
            .simple_var_decl,
            .aligned_var_decl,
            => {
                const var_decl = module.ast.fullVarDecl(decl) orelse continue;
                const name_token = var_decl.ast.mut_token + 1;
                const name = module.ast.tokenSlice(name_token);

                if (var_decl.ast.init_node.unwrap()) |init_node| {
                    try maybe_record_import(arena, module, name, init_node);
                    try collect_struct_methods(
                        arena,
                        module,
                        ast_index,
                        name,
                        init_node,
                        indexes,
                    );
                }
            },
            else => {},
        }
    }
}

fn maybe_record_import(
    arena: std.mem.Allocator,
    module: *ModuleRecord,
    alias_name: []const u8,
    init_node: Ast.Node.Index,
) !void {
    assert(alias_name.len > 0);
    assert(init_node == .root or @intFromEnum(init_node) < module.ast.nodes.len);
    if (alias_name.len == 0) return;
    const first = module.ast.firstToken(init_node);
    const last = module.ast.lastToken(init_node);

    var saw_import = false;
    var quoted: ?[]const u8 = null;

    var tok = first;
    while (tok <= last and tok < module.ast.tokens.len) : (tok += 1) {
        if (!saw_import) {
            if (std.mem.eql(u8, module.ast.tokenSlice(tok), "@import")) {
                saw_import = true;
            }
            continue;
        }

        if (module.ast.tokens.items(.tag)[tok] == .string_literal) {
            quoted = module.ast.tokenSlice(tok);
            break;
        }
    }

    const import_quoted = quoted orelse return;
    if (!saw_import or import_quoted.len < 2) {
        return;
    }

    const import_rel = import_quoted[1 .. import_quoted.len - 1];
    const resolved = resolve_import_path(arena, module.path, import_rel) catch |err| {
        if (err == error.PackageImport) {
            return; // Skip package imports (std, libtigercheck, etc.)
        }
        return err;
    };
    try module.imports.put(arena, try arena.dupe(u8, alias_name), resolved);
}

fn collect_struct_methods(
    arena: std.mem.Allocator,
    module: *ModuleRecord,
    ast_index: u32,
    type_name: []const u8,
    init_node: Ast.Node.Index,
    indexes: *const RootDeclIndexes,
) !void {
    assert(type_name.len > 0);
    assert(module.path.len > 0);
    if (type_name.len == 0) return;
    if (init_node == .root) return;
    switch (module.ast.nodes.items(.tag)[@intFromEnum(init_node)]) {
        .container_decl,
        .container_decl_trailing,
        .container_decl_two,
        .container_decl_two_trailing,
        .container_decl_arg,
        .container_decl_arg_trailing,
        => {},
        else => return,
    }

    const first = module.ast.firstToken(init_node);
    const last = module.ast.lastToken(init_node);

    var tok = first;
    while (tok + 2 <= last and tok + 2 < module.ast.tokens.len) : (tok += 1) {
        if (module.ast.tokens.items(.tag)[tok] == .keyword_fn) {
            // keep scanning
        } else {
            continue;
        }
        if (module.ast.tokens.items(.tag)[tok + 1] == .identifier) {
            // keep scanning
        } else {
            continue;
        }
        if (module.ast.tokens.items(.tag)[tok + 2] == .l_paren) {
            // keep scanning
        } else {
            continue;
        }

        const method_name = module.ast.tokenSlice(tok + 1);
        const canonical = try std.fmt.allocPrint(
            arena,
            "{s}::{s}.{s}",
            .{ module.path, type_name, method_name },
        );
        const key = try std.fmt.allocPrint(
            arena,
            "{s}::{s}.{s}",
            .{ module.path, type_name, method_name },
        );

        try indexes.functions.append(.{
            .canonical_name = canonical,
            .file_path = module.path,
            .name = method_name,
            .owner_type = try arena.dupe(u8, type_name),
            .body_node = null,
            .ast_index = ast_index,
        });
        try indexes.fn_by_file_owner_name.put(key, canonical);
    }
}

fn walk_body(
    arena: std.mem.Allocator,
    graph: *CallGraph,
    function: FunctionRecord,
    module: *const ModuleRecord,
    fn_by_file_name: *const std.StringHashMap([]const u8),
    fn_by_file_owner_name: *const std.StringHashMap([]const u8),
) !void {
    var local_var_types = std.StringHashMap([]const u8).init(arena);
    var visited = ast_walk.NodeVisited.init(arena);
    defer visited.deinit();

    var ctx = WalkBodyCtx{
        .arena = arena,
        .graph = graph,
        .function = function,
        .module = module,
        .local_var_types = &local_var_types,
        .fn_by_file_name = fn_by_file_name,
        .fn_by_file_owner_name = fn_by_file_owner_name,
    };
    const body_node = function.body_node orelse return;
    try ast_walk.walk_with_options(
        &module.ast,
        body_node,
        &ctx,
        walk_body_visit_node,
        .{ .visited = &visited },
    );
}

const WalkBodyCtx = struct {
    arena: std.mem.Allocator,
    graph: *CallGraph,
    function: FunctionRecord,
    module: *const ModuleRecord,
    local_var_types: *std.StringHashMap([]const u8),
    fn_by_file_name: *const std.StringHashMap([]const u8),
    fn_by_file_owner_name: *const std.StringHashMap([]const u8),
};

fn walk_body_visit_node(
    tree: *const Ast,
    node: Ast.Node.Index,
    ctx_opaque: *anyopaque,
) anyerror!ast_walk.VisitDecision {
    const ctx: *WalkBodyCtx = @ptrCast(@alignCast(ctx_opaque));
    if (node == .root or @intFromEnum(node) >= tree.nodes.len) return .visit_children;
    assert(ctx.function.canonical_name.len > 0);
    assert(ctx.module.path.len > 0);

    const tag = tree.nodes.items(.tag)[@intFromEnum(node)];
    switch (tag) {
        .call,
        .call_comma,
        .call_one,
        .call_one_comma,
        => {
            var call_buf: [1]Ast.Node.Index = undefined;
            const call = tree.fullCall(&call_buf, node) orelse return .visit_children;

            var path: CallPath = .{};
            collect_call_path(tree, call.ast.fn_expr, &path);

            if (try resolve_call_target(
                ctx.arena,
                ctx.function,
                ctx.module,
                &path,
                ctx.local_var_types,
                ctx.fn_by_file_name,
                ctx.fn_by_file_owner_name,
            )) |callee| {
                try ctx.graph.add_edge(ctx.function.canonical_name, callee);
            }
        },
        .local_var_decl,
        .simple_var_decl,
        .aligned_var_decl,
        => {
            if (ctx.module.ast.fullVarDecl(node)) |var_decl| {
                const name_token = var_decl.ast.mut_token + 1;
                const var_name = ctx.module.ast.tokenSlice(name_token);
                if (var_decl.ast.init_node.unwrap()) |init_nd| {
                    if (owner_type_from_init(&ctx.module.ast, init_nd)) |owner_type| {
                        try ctx.local_var_types.put(var_name, owner_type);
                    }
                }
            }
        },
        else => {},
    }

    return .visit_children;
}

fn resolve_call_target(
    arena: std.mem.Allocator,
    function: FunctionRecord,
    module: *const ModuleRecord,
    path: *const CallPath,
    local_var_types: *const std.StringHashMap([]const u8),
    fn_by_file_name: *const std.StringHashMap([]const u8),
    fn_by_file_owner_name: *const std.StringHashMap([]const u8),
) !?[]const u8 {
    if (path.len == 0) return null;

    if (path.len == 1) {
        const key =
            try std.fmt.allocPrint(arena, "{s}::{s}", .{ function.file_path, path.parts[0] });
        return fn_by_file_name.get(key);
    }

    return resolve_field_call(
        arena,
        path.parts[0],
        path.parts[path.len - 1],
        function.file_path,
        module,
        local_var_types,
        fn_by_file_name,
        fn_by_file_owner_name,
    );
}

fn owner_type_from_init(ast: *const Ast, init_node: Ast.Node.Index) ?[]const u8 {
    assert(ast.nodes.items(.main_token).len == ast.nodes.len);
    assert(init_node == .root or @intFromEnum(init_node) < ast.nodes.len);
    var init_buf: [2]Ast.Node.Index = undefined;
    const init = ast.fullStructInit(&init_buf, init_node) orelse return null;
    const type_expr = init.ast.type_expr;
    // type_expr is OptionalIndex; .none (0xFFFFFFFF) means no type was specified
    const type_expr_idx = type_expr.unwrap() orelse return null;
    if (ast.nodes.items(.tag)[@intFromEnum(type_expr_idx)] == .identifier) {
        // keep going
    } else {
        return null;
    }
    const type_token = ast.nodes.items(.main_token)[@intFromEnum(type_expr_idx)];
    return ast.tokenSlice(type_token);
}

const CallPath = struct {
    parts: [8][]const u8 = undefined,
    len: usize = 0,

    fn append(self: *CallPath, value: []const u8) void {
        if (self.len < self.parts.len) {
            self.parts[self.len] = value;
            self.len += 1;
        }
    }
};

fn collect_call_path(ast: *const Ast, expr_node: Ast.Node.Index, path: *CallPath) void {
    assert(ast.nodes.len > 0);
    assert(ast.nodes.items(.main_token).len == ast.nodes.len);
    assert(path.len <= path.parts.len);
    assert(expr_node == .root or @intFromEnum(expr_node) < ast.nodes.len);
    if (expr_node == .root or @intFromEnum(expr_node) >= ast.nodes.len) return;

    switch (ast.nodes.items(.tag)[@intFromEnum(expr_node)]) {
        .identifier => {
            const token = ast.nodes.items(.main_token)[@intFromEnum(expr_node)];
            path.append(ast.tokenSlice(token));
        },
        .field_access => {
            const data = ast.nodeData(expr_node);
            const lhs, const field_token = data.node_and_token;
            collect_call_path(ast, lhs, path);
            path.append(ast.tokenSlice(field_token));
        },
        .grouped_expression,
        .unwrap_optional,
        => {
            const child = ast.nodeData(expr_node).node_and_token[0];
            collect_call_path(ast, child, path);
        },
        .@"try",
        .@"comptime",
        => {
            const child = ast.nodeData(expr_node).node;
            collect_call_path(ast, child, path);
        },
        else => {},
    }
}

fn resolve_field_call(
    arena: std.mem.Allocator,
    lhs: []const u8,
    rhs: []const u8,
    current_file: []const u8,
    module: *const ModuleRecord,
    local_var_types: *const std.StringHashMap([]const u8),
    fn_by_file_name: *const std.StringHashMap([]const u8),
    fn_by_file_owner_name: *const std.StringHashMap([]const u8),
) !?[]const u8 {
    assert(lhs.len > 0);
    assert(rhs.len > 0);
    assert(current_file.len > 0);
    if (lhs.len == 0) return null;
    if (rhs.len == 0) return null;
    if (current_file.len == 0) return null;
    if (module.imports.get(lhs)) |import_file| {
        const key = try std.fmt.allocPrint(arena, "{s}::{s}", .{ import_file, rhs });
        return fn_by_file_name.get(key);
    }

    if (local_var_types.get(lhs)) |owner_type| {
        const key =
            try std.fmt.allocPrint(arena, "{s}::{s}.{s}", .{ current_file, owner_type, rhs });
        return fn_by_file_owner_name.get(key);
    }

    const type_key = try std.fmt.allocPrint(arena, "{s}::{s}.{s}", .{ current_file, lhs, rhs });
    return fn_by_file_owner_name.get(type_key);
}

fn resolve_import_path(
    arena: std.mem.Allocator,
    importer_file: []const u8,
    import_rel: []const u8,
) ![]const u8 {
    assert(importer_file.len > 0);
    assert(import_rel.len > 0);
    if (importer_file.len == 0) return error.InvalidInputPath;
    if (import_rel.len == 0) return error.InvalidInputPath;
    // Package imports (std, builtin, or project packages) are not file paths
    if (import_is_package_keyword(import_rel)) {
        return error.PackageImport;
    }

    // Package aliases without path separators are not resolvable as files
    // (e.g., "libtigercheck" defined in build.zig, not "./libtigercheck.zig")
    if (!std.mem.containsAtLeast(u8, import_rel, 1, "/") and
        !std.mem.endsWith(u8, import_rel, ".zig"))
    {
        return error.PackageImport;
    }

    const importer_dir = std.fs.path.dirname(importer_file) orelse ".";
    const joined = try std.fs.path.resolve(arena, &.{ importer_dir, import_rel });

    // If already has .zig extension, use as-is; otherwise append it
    if (std.mem.endsWith(u8, import_rel, ".zig")) {
        return joined;
    }

    return try std.mem.concat(arena, u8, &.{ joined, ".zig" });
}

fn import_is_package_keyword(import_rel: []const u8) bool {
    assert(import_rel.len > 0);
    if (import_rel.len == 0) return false;
    if (std.mem.eql(u8, import_rel, "std")) return true;
    if (std.mem.eql(u8, import_rel, "builtin")) return true;
    return std.mem.eql(u8, import_rel, "root");
}

fn collect_zig_files(
    arena: std.mem.Allocator,
    root_path: []const u8,
    files: *std.array_list.Managed([]const u8),
) !void {
    assert(root_path.len > 0);
    assert(files.items.len <= files.capacity);
    if (root_path.len == 0) return error.InvalidInputPath;
    const zig_file_queue_bound_limit: usize = 16384;
    if (std.mem.endsWith(u8, root_path, ".zig")) {
        if (files.items.len >= zig_file_queue_bound_limit) {
            return error.FileQueueBoundExceeded;
        }
        try commit(files, root_path);
        return;
    }

    const io = std.Options.debug_io;
    var dir = try std.Io.Dir.cwd().openDir(io, root_path, .{});
    defer dir.close(io);

    var iter = dir.iterate();
    while (try iter.next(io)) |entry| {
        const child = try std.fs.path.join(arena, &.{ root_path, entry.name });
        switch (entry.kind) {
            .file => {
                if (std.mem.endsWith(u8, child, ".zig")) {
                    if (files.items.len >= zig_file_queue_bound_limit) {
                        return error.FileQueueBoundExceeded;
                    }
                    try commit(files, child);
                }
            },
            .directory => {
                try collect_zig_files(arena, child, files);
            },
            .block_device,
            .character_device,
            .named_pipe,
            .sym_link,
            .unix_domain_socket,
            .whiteout,
            .door,
            .event_port,
            .unknown,
            => {},
        }
    }
}

fn commit(files: *std.array_list.Managed([]const u8), file_path: []const u8) !void {
    assert(file_path.len > 0);
    if (file_path.len == 0) return error.InvalidInputPath;
    try files.append(file_path);
}

const std = @import("std");
const assert = std.debug.assert;
const Ast = std.zig.Ast;
const rules = @import("rules.zig");

pub const StyleDiagnostic = struct {
    file_path: []const u8,
    rule_id: rules.Id,
    message: []const u8,
};

pub fn analyze_file(
    allocator: std.mem.Allocator,
    file_path: []const u8,
    diagnostics: *std.array_list.Managed(StyleDiagnostic),
) !void {
    assert(file_path.len > 0);
    assert(diagnostics.items.len <= diagnostics.capacity);
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

    try analyze_file_with_parsed(allocator, file_path, &tree, diagnostics);
}

pub fn analyze_file_with_parsed(
    allocator: std.mem.Allocator,
    file_path: []const u8,
    tree: *const Ast,
    diagnostics: *std.array_list.Managed(StyleDiagnostic),
) !void {
    assert(file_path.len > 0);
    assert(diagnostics.items.len <= diagnostics.capacity);
    if (file_path.len == 0) return error.InvalidInputPath;

    const stem = file_stem(file_path);

    for (tree.rootDecls()) |decl| {
        try analyze_decl(allocator, tree, file_path, stem, decl, true, diagnostics);
    }
}

fn analyze_decl(
    allocator: std.mem.Allocator,
    tree: *const Ast,
    file_path: []const u8,
    stem: []const u8,
    decl: Ast.Node.Index,
    is_top_level: bool,
    diagnostics: *std.array_list.Managed(StyleDiagnostic),
) anyerror!void {
    assert(tree.nodes.len > 0);
    assert(file_path.len > 0);
    assert(stem.len > 0);
    if (file_path.len == 0) return;
    if (stem.len == 0) return;
    if (decl == .root) return;
    assert(@intFromEnum(decl) < tree.nodes.len);
    const tag = tree.nodes.items(.tag)[@intFromEnum(decl)];
    switch (tag) {
        .fn_decl => {
            try analyze_fn_decl_style(
                allocator,
                tree,
                file_path,
                stem,
                decl,
                is_top_level,
                diagnostics,
            );
        },
        .global_var_decl,
        .local_var_decl,
        .simple_var_decl,
        .aligned_var_decl,
        => {
            const var_decl = tree.fullVarDecl(decl) orelse return;
            const name_token = var_decl.ast.mut_token + 1;
            const name = tree.tokenSlice(name_token);
            const mut_tag = tree.tokens.items(.tag)[var_decl.ast.mut_token];

            const allow_screaming = mut_tag == .keyword_const;
            try check_name_case(
                allocator,
                file_path,
                diagnostics,
                name,
                allow_screaming,
                true,
            );

            if (var_decl.ast.init_node.unwrap()) |init_node| {
                if (is_type_initializer(tree, init_node)) {
                    try analyze_container_order(allocator, tree, file_path, init_node, diagnostics);
                }
            }
        },
        else => {},
    }
}

fn analyze_fn_decl_style(
    allocator: std.mem.Allocator,
    tree: *const Ast,
    file_path: []const u8,
    stem: []const u8,
    decl: Ast.Node.Index,
    is_top_level: bool,
    diagnostics: *std.array_list.Managed(StyleDiagnostic),
) !void {
    assert(file_path.len > 0);
    assert(stem.len > 0);
    if (file_path.len == 0) return;
    if (stem.len == 0) return;
    var fn_buf: [1]Ast.Node.Index = undefined;
    const proto = tree.fullFnProto(&fn_buf, decl) orelse return;
    const name_token = proto.name_token orelse return;
    const function_name = tree.tokenSlice(name_token);

    try check_name_case(allocator, file_path, diagnostics, function_name, false, false);

    if (is_top_level and has_self_first_param(tree, proto)) {
        const msg = try std.fmt.allocPrint(
            allocator,
            "loose method '{s}': functions with first parameter `self` should " ++
                "be inside a struct",
            .{function_name},
        );
        try diagnostics.append(.{
            .file_path = file_path,
            .rule_id = .TS17_SNAKE_CASE,
            .message = msg,
        });
    }

    if (is_name_stutter(function_name, stem)) {
        const stutter_msg = try std.fmt.allocPrint(
            allocator,
            "name stutter: function '{s}' repeats file stem '{s}'",
            .{ function_name, stem },
        );
        try diagnostics.append(.{
            .file_path = file_path,
            .rule_id = .TS17_SNAKE_CASE,
            .message = stutter_msg,
        });
    }

    if (has_callback_not_last(tree, proto)) {
        const msg = try std.fmt.allocPrint(
            allocator,
            "TS21_CALLBACK_LAST: Callback parameter in '{s}' should be the last parameter",
            .{function_name},
        );
        try diagnostics.append(.{
            .file_path = file_path,
            .rule_id = .TS21_CALLBACK_LAST,
            .message = msg,
        });
    }
}

fn is_name_stutter(function_name: []const u8, stem: []const u8) bool {
    assert(function_name.len > 0);
    assert(stem.len > 0);
    if (function_name.len == 0) return false;
    if (stem.len == 0) return false;
    if (!starts_with_ascii_case_insensitive(function_name, stem)) return false;
    if (function_name.len <= stem.len) return false;
    return function_name[stem.len] == '_';
}

fn has_self_first_param(tree: *const Ast, proto: Ast.full.FnProto) bool {
    var it = proto.iterate(tree);
    const first = it.next() orelse return false;
    const name_token = first.name_token orelse return false;
    return std.mem.eql(u8, tree.tokenSlice(name_token), "self");
}

fn check_name_case(
    allocator: std.mem.Allocator,
    file_path: []const u8,
    diagnostics: *std.array_list.Managed(StyleDiagnostic),
    name: []const u8,
    allow_screaming: bool,
    enforce_suffix_order: bool,
) !void {
    assert(file_path.len > 0);
    assert(diagnostics.items.len <= diagnostics.capacity);
    if (name.len == 0) return;

    const starts_upper = name[0] >= 'A' and name[0] <= 'Z';
    if (starts_upper) {
        if (allow_screaming and is_screaming_snake(name)) {
            return;
        }
        if (!is_pascal_case(name)) {
            const msg = try std.fmt.allocPrint(
                allocator,
                "name must be PascalCase: '{s}'",
                .{name},
            );
            try diagnostics.append(.{
                .file_path = file_path,
                .rule_id = .TS17_SNAKE_CASE,
                .message = msg,
            });
            return;
        }
        try check_pascal_acronym_case(allocator, file_path, diagnostics, name);
        try check_no_abbreviation(allocator, file_path, diagnostics, name, true);
        return;
    }

    if (!is_snake_case(name)) {
        const msg = try std.fmt.allocPrint(
            allocator,
            "name must be snake_case: '{s}'",
            .{name},
        );
        try diagnostics.append(.{
            .file_path = file_path,
            .rule_id = .TS17_SNAKE_CASE,
            .message = msg,
        });
        return;
    }

    if (enforce_suffix_order) {
        try check_unit_suffix_order(allocator, file_path, diagnostics, name);
    }
    try check_no_abbreviation(allocator, file_path, diagnostics, name, false);
}

const AcronymAlias = struct {
    mixed: []const u8,
    canonical: []const u8,
};

const acronym_aliases = [_]AcronymAlias{
    .{ .mixed = "Http", .canonical = "HTTP" },
    .{ .mixed = "Https", .canonical = "HTTPS" },
    .{ .mixed = "Json", .canonical = "JSON" },
    .{ .mixed = "Sql", .canonical = "SQL" },
    .{ .mixed = "Tcp", .canonical = "TCP" },
    .{ .mixed = "Udp", .canonical = "UDP" },
    .{ .mixed = "Url", .canonical = "URL" },
    .{ .mixed = "Uri", .canonical = "URI" },
    .{ .mixed = "Uuid", .canonical = "UUID" },
    .{ .mixed = "Xml", .canonical = "XML" },
};

const AbbreviationAlias = struct {
    snake: []const u8,
    pascal: []const u8,
    canonical: []const u8,
};

const abbreviation_aliases = [_]AbbreviationAlias{
    .{ .snake = "cfg", .pascal = "Cfg", .canonical = "config" },
    .{ .snake = "cnt", .pascal = "Cnt", .canonical = "count" },
    .{ .snake = "idx", .pascal = "Idx", .canonical = "index" },
    .{ .snake = "msg", .pascal = "Msg", .canonical = "message" },
    .{ .snake = "num", .pascal = "Num", .canonical = "count" },
    .{ .snake = "tmp", .pascal = "Tmp", .canonical = "temp" },
};

const abbreviation_exceptions = [_][]const u8{
    "api",
    "ast",
    "cli",
    "cpu",
    "db",
    "dns",
    "fs",
    "http",
    "https",
    "id",
    "io",
    "ip",
    "jwt",
    "json",
    "os",
    "rpc",
    "sha",
    "sql",
    "tcp",
    "tls",
    "udp",
    "ui",
    "uri",
    "url",
    "uuid",
    "utf8",
    "xml",
};

fn check_pascal_acronym_case(
    allocator: std.mem.Allocator,
    file_path: []const u8,
    diagnostics: *std.array_list.Managed(StyleDiagnostic),
    name: []const u8,
) !void {
    assert(file_path.len > 0);
    assert(name.len > 0);
    assert(diagnostics.items.len <= diagnostics.capacity);
    if (file_path.len == 0) return;
    if (name.len == 0) return;
    for (acronym_aliases) |alias| {
        if (!contains_pascal_word(name, alias.mixed)) continue;
        const msg = try std.fmt.allocPrint(
            allocator,
            "TS18_ACRONYM_CASE: acronym in '{s}' should be '{s}'",
            .{ name, alias.canonical },
        );
        try diagnostics.append(.{
            .file_path = file_path,
            .rule_id = .TS18_ACRONYM_CASE,
            .message = msg,
        });
        return;
    }
}

fn contains_pascal_word(name: []const u8, word: []const u8) bool {
    assert(name.len > 0);
    if (word.len == 0 or word.len > name.len) return false;
    var search_start: usize = 0;
    while (search_start < name.len) {
        const idx = std.mem.indexOfPos(u8, name, search_start, word) orelse return false;
        const end = idx + word.len;
        const left_ok = idx == 0 or
            std.ascii.isLower(name[idx - 1]) or
            std.ascii.isDigit(name[idx - 1]);
        const right_ok = end == name.len or
            std.ascii.isUpper(name[end]) or
            std.ascii.isDigit(name[end]);
        if (left_ok and right_ok) {
            return true;
        }
        search_start = idx + 1;
    }
    return false;
}

fn check_no_abbreviation(
    allocator: std.mem.Allocator,
    file_path: []const u8,
    diagnostics: *std.array_list.Managed(StyleDiagnostic),
    name: []const u8,
    is_pascal: bool,
) !void {
    assert(file_path.len > 0);
    assert(name.len > 0);
    assert(diagnostics.items.len <= diagnostics.capacity);
    if (file_path.len == 0) return;
    if (name.len == 0) return;
    for (abbreviation_aliases) |alias| {
        if (is_abbreviation_exception(alias.snake)) continue;

        var found = false;
        if (is_pascal) {
            found = contains_pascal_word(name, alias.pascal);
        } else {
            found = contains_snake_word(name, alias.snake);
        }
        if (!found) continue;

        const msg = try std.fmt.allocPrint(
            allocator,
            "TS20_NO_ABBREVIATION: abbreviation '{s}' in '{s}' should be '{s}'",
            .{ alias.snake, name, alias.canonical },
        );
        try diagnostics.append(.{
            .file_path = file_path,
            .rule_id = .TS20_NO_ABBREVIATION,
            .message = msg,
        });
        return;
    }
}

fn contains_snake_word(name: []const u8, word: []const u8) bool {
    assert(name.len > 0);
    assert(word.len > 0);
    if (name.len == 0) return false;
    if (word.len == 0) return false;
    var start: usize = 0;
    while (start <= name.len) {
        const end = std.mem.indexOfPos(u8, name, start, "_") orelse name.len;
        const part = name[start..end];
        if (std.mem.eql(u8, part, word) and !is_abbreviation_exception(part)) {
            return true;
        }
        if (end == name.len) break;
        start = end + 1;
    }
    return false;
}

fn is_abbreviation_exception(part: []const u8) bool {
    assert(part.len > 0);
    if (part.len == 0) return false;
    for (abbreviation_exceptions) |allowed| {
        if (std.mem.eql(u8, part, allowed)) {
            return true;
        }
    }
    return false;
}

fn check_unit_suffix_order(
    allocator: std.mem.Allocator,
    file_path: []const u8,
    diagnostics: *std.array_list.Managed(StyleDiagnostic),
    name: []const u8,
) !void {
    assert(file_path.len > 0);
    assert(name.len > 0);
    assert(diagnostics.items.len <= diagnostics.capacity);
    if (file_path.len == 0) return;
    if (name.len == 0) return;
    var unit_part_index: ?u16 = null;
    var part_index: u16 = 0;
    var start: usize = 0;
    while (start <= name.len) {
        const end = std.mem.indexOfPos(u8, name, start, "_") orelse name.len;
        const part = name[start..end];

        if (prefix_qualifier_order_is_invalid(part_index, end != name.len, part)) {
            try append_big_endian_suffix_order_diag(allocator, file_path, diagnostics, name);
            return;
        }

        if (is_unit_suffix(part) and unit_part_index == null) {
            unit_part_index = part_index;
        }
        if (unit_suffix_order_is_invalid(unit_part_index, part_index, part)) {
            try append_big_endian_suffix_order_diag(allocator, file_path, diagnostics, name);
            return;
        }

        part_index += 1;
        if (end == name.len) break;
        start = end + 1;
    }
}

fn append_big_endian_suffix_order_diag(
    allocator: std.mem.Allocator,
    file_path: []const u8,
    diagnostics: *std.array_list.Managed(StyleDiagnostic),
    name: []const u8,
) !void {
    assert(file_path.len > 0);
    assert(name.len > 0);
    assert(diagnostics.items.len <= diagnostics.capacity);
    if (file_path.len == 0) return;
    if (name.len == 0) return;
    const msg = try std.fmt.allocPrint(
        allocator,
        "TS19_UNIT_SUFFIX_ORDER: use big-endian suffix order in '{s}'",
        .{name},
    );
    try diagnostics.append(.{
        .file_path = file_path,
        .rule_id = .TS19_UNIT_SUFFIX_ORDER,
        .message = msg,
    });
}

fn prefix_qualifier_order_is_invalid(
    part_index: u16,
    has_more_parts: bool,
    part: []const u8,
) bool {
    assert(part.len > 0);
    if (part.len == 0) return false;
    if (part_index != 0) return false;
    if (!has_more_parts) return false;
    return is_qualifier_suffix(part);
}

fn unit_suffix_order_is_invalid(
    unit_part_index: ?u16,
    part_index: u16,
    part: []const u8,
) bool {
    assert(part.len > 0);
    if (part.len == 0) return false;
    const unit_index = unit_part_index orelse return false;
    if (part_index <= unit_index) return false;
    return is_qualifier_suffix(part);
}

fn is_unit_suffix(part: []const u8) bool {
    assert(part.len > 0);
    if (part.len == 0) return false;
    return std.mem.eql(u8, part, "ns") or
        std.mem.eql(u8, part, "us") or
        std.mem.eql(u8, part, "ms") or
        std.mem.eql(u8, part, "sec") or
        std.mem.eql(u8, part, "min") or
        std.mem.eql(u8, part, "hour") or
        std.mem.eql(u8, part, "bytes") or
        std.mem.eql(u8, part, "kb") or
        std.mem.eql(u8, part, "mb") or
        std.mem.eql(u8, part, "gb");
}

fn is_qualifier_suffix(part: []const u8) bool {
    assert(part.len > 0);
    if (part.len == 0) return false;
    return std.mem.eql(u8, part, "max") or
        std.mem.eql(u8, part, "min") or
        std.mem.eql(u8, part, "avg") or
        std.mem.eql(u8, part, "mean") or
        std.mem.eql(u8, part, "limit") or
        std.mem.eql(u8, part, "cap") or
        std.mem.eql(u8, part, "bound") or
        std.mem.eql(u8, part, "total") or
        std.mem.eql(u8, part, "count");
}

fn analyze_container_order(
    allocator: std.mem.Allocator,
    tree: *const Ast,
    file_path: []const u8,
    node: Ast.Node.Index,
    diagnostics: *std.array_list.Managed(StyleDiagnostic),
) anyerror!void {
    assert(file_path.len > 0);
    assert(diagnostics.items.len <= diagnostics.capacity);
    assert(node == .root or @intFromEnum(node) < tree.nodes.len);
    if (file_path.len == 0) return;
    if (node == .root or @intFromEnum(node) >= tree.nodes.len) return;

    var pending = std.array_list.Managed(Ast.Node.Index).init(allocator);
    defer pending.deinit();
    try pending.append(node);

    const stem = file_stem(file_path);
    var ctx = ContainerAnalyzeCtx{
        .allocator = allocator,
        .tree = tree,
        .file_path = file_path,
        .stem = stem,
        .diagnostics = diagnostics,
        .pending = &pending,
    };
    var cursor: usize = 0;
    for (0..4096) |_| {
        if (cursor >= pending.items.len) break;
        const container_node = pending.items[cursor];
        cursor += 1;
        var buf: [2]Ast.Node.Index = undefined;
        const container = tree.fullContainerDecl(&buf, container_node) orelse continue;

        var seen_method = false;
        for (container.ast.members) |member| {
            seen_method = try analyze_container_member(&ctx, member, seen_method);
        }
    }
}

const ContainerAnalyzeCtx = struct {
    allocator: std.mem.Allocator,
    tree: *const Ast,
    file_path: []const u8,
    stem: []const u8,
    diagnostics: *std.array_list.Managed(StyleDiagnostic),
    pending: *std.array_list.Managed(Ast.Node.Index),
};

fn analyze_container_member(
    ctx: *ContainerAnalyzeCtx,
    member: Ast.Node.Index,
    seen_method: bool,
) !bool {
    assert(ctx.file_path.len > 0);
    assert(ctx.stem.len > 0);
    if (ctx.file_path.len == 0) return seen_method;
    const tag = ctx.tree.nodes.items(.tag)[@intFromEnum(member)];
    if (tag == .fn_decl) {
        try analyze_fn_decl_style(
            ctx.allocator,
            ctx.tree,
            ctx.file_path,
            ctx.stem,
            member,
            false,
            ctx.diagnostics,
        );
        return true;
    }

    if (container_member_is_field(tag)) {
        if (seen_method) {
            try ctx.diagnostics.append(.{
                .file_path = ctx.file_path,
                .rule_id = .TS22_STRUCT_ORDER,
                .message = "Fields must be declared before methods.",
            });
        }
        return seen_method;
    }

    if (container_member_is_nested_container(tag)) {
        try ctx.pending.append(member);
    }
    return seen_method;
}

fn container_member_is_field(tag: Ast.Node.Tag) bool {
    return tag == .container_field or
        tag == .container_field_init or
        tag == .container_field_align or
        tag == .global_var_decl or
        tag == .local_var_decl or
        tag == .simple_var_decl or
        tag == .aligned_var_decl;
}

fn container_member_is_nested_container(tag: Ast.Node.Tag) bool {
    return tag == .container_decl or
        tag == .container_decl_trailing or
        tag == .container_decl_two or
        tag == .container_decl_two_trailing or
        tag == .container_decl_arg or
        tag == .container_decl_arg_trailing or
        tag == .tagged_union or
        tag == .tagged_union_trailing or
        tag == .tagged_union_two or
        tag == .tagged_union_two_trailing or
        tag == .tagged_union_enum_tag or
        tag == .tagged_union_enum_tag_trailing;
}

fn is_type_initializer(tree: *const Ast, init_node: Ast.Node.Index) bool {
    if (init_node == .root or @intFromEnum(init_node) >= tree.nodes.len) return false;
    return switch (tree.nodes.items(.tag)[@intFromEnum(init_node)]) {
        .container_decl,
        .container_decl_trailing,
        .container_decl_two,
        .container_decl_two_trailing,
        .container_decl_arg,
        .container_decl_arg_trailing,
        .tagged_union,
        .tagged_union_trailing,
        .tagged_union_two,
        .tagged_union_two_trailing,
        .tagged_union_enum_tag,
        .tagged_union_enum_tag_trailing,
        => true,
        else => false,
    };
}

fn is_snake_case(name: []const u8) bool {
    assert(name.len > 0);
    assert(name.len <= 4096);
    if (name.len == 0) return false;
    if (name[0] == '_' or name[name.len - 1] == '_') return false;
    var prev_underscore = false;
    for (name) |c| {
        if (c == '_') {
            if (prev_underscore) return false;
            prev_underscore = true;
            continue;
        }
        prev_underscore = false;
        if (!is_lower_or_digit(c)) {
            return false;
        }
    }
    return true;
}

fn is_pascal_case(name: []const u8) bool {
    assert(name.len <= 4096);
    assert(name.len <= std.math.maxInt(u32));
    if (name.len == 0) return false;
    if (!(name[0] >= 'A' and name[0] <= 'Z')) return false;
    for (name) |c| {
        if (c == '_') return false;
        if (!is_ascii_alnum(c)) {
            return false;
        }
    }
    return true;
}

fn is_screaming_snake(name: []const u8) bool {
    assert(name.len > 0);
    assert(name.len <= 4096);
    if (name.len == 0) return false;
    if (name[0] == '_' or name[name.len - 1] == '_') return false;
    var prev_underscore = false;
    for (name) |c| {
        if (c == '_') {
            if (prev_underscore) return false;
            prev_underscore = true;
            continue;
        }
        prev_underscore = false;
        if (!is_upper_or_digit(c)) {
            return false;
        }
    }
    return true;
}

fn file_stem(file_path: []const u8) []const u8 {
    assert(file_path.len > 0);
    if (file_path.len == 0) return "";
    const base = std.fs.path.basename(file_path);
    if (std.mem.lastIndexOfScalar(u8, base, '.')) |dot| {
        return base[0..dot];
    }
    return base;
}

fn starts_with_ascii_case_insensitive(value: []const u8, prefix: []const u8) bool {
    assert(value.len > 0);
    assert(prefix.len > 0);
    if (value.len == 0) return false;
    if (prefix.len == 0) return false;
    if (prefix.len > value.len) return false;
    var i: usize = 0;
    while (i < prefix.len) : (i += 1) {
        if (std.ascii.toLower(value[i]) == std.ascii.toLower(prefix[i])) {
            continue;
        }
        {
            return false;
        }
    }
    return true;
}

// TS21_CALLBACK_LAST: Check if a callback parameter is not the last one
fn has_callback_not_last(tree: *const Ast, proto: Ast.full.FnProto) bool {
    assert(tree.nodes.len > 0);
    assert(tree.tokens.len > 0);

    var seen_callback = false;
    var it = proto.iterate(tree);
    while (it.next()) |param| {
        const type_expr = param.type_expr orelse continue;
        if (is_callback_type(tree, type_expr)) {
            seen_callback = true;
            continue;
        }
        if (seen_callback) {
            return true;
        }
    }

    return false;
}

fn is_callback_type(tree: *const Ast, type_node: Ast.Node.Index) bool {
    assert(tree.nodes.len > 0);
    if (type_node == .root or @intFromEnum(type_node) >= tree.nodes.len) return false;

    const tag = tree.nodes.items(.tag)[@intFromEnum(type_node)];

    // Handle optional callback types (?fn(...))
    if (tag == .optional_type) {
        const child = tree.nodeData(type_node).node;
        return is_callback_type(tree, child);
    }

    // Check for fn prototype types (fn(...) T)
    if (is_function_proto_tag(tag)) {
        return true;
    }

    // Handle grouped expressions
    if (tag == .grouped_expression) {
        const child = tree.nodeData(type_node).node_and_token[0];
        return is_callback_type(tree, child);
    }

    return false;
}

fn is_lower_or_digit(c: u8) bool {
    if (c >= 'a' and c <= 'z') return true;
    return c >= '0' and c <= '9';
}

fn is_upper_or_digit(c: u8) bool {
    if (c >= 'A' and c <= 'Z') return true;
    return c >= '0' and c <= '9';
}

fn is_ascii_alnum(c: u8) bool {
    if (is_upper_or_digit(c)) return true;
    return c >= 'a' and c <= 'z';
}

fn is_function_proto_tag(tag: Ast.Node.Tag) bool {
    if (tag == .fn_proto) return true;
    if (tag == .fn_proto_simple) return true;
    if (tag == .fn_proto_multi) return true;
    return tag == .fn_proto_one;
}

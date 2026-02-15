const std = @import("std");
const Ast = std.zig.Ast;
const assert = std.debug.assert;

pub const NodeVisited = std.AutoHashMap(Ast.Node.Index, void);

pub const VisitDecision = enum {
    visit_children,
    skip_children,
    stop,
};

pub const WalkOptions = struct {
    max_nodes: ?usize = null,
    visited: ?*NodeVisited = null,
};

pub const VisitCallback = *const fn (
    tree: *const Ast,
    node: Ast.Node.Index,
    context: *anyopaque,
) anyerror!void;

pub const VisitControlCallback = *const fn (
    tree: *const Ast,
    node: Ast.Node.Index,
    context: *anyopaque,
) anyerror!VisitDecision;

pub const VisitExitCallback = *const fn (
    tree: *const Ast,
    node: Ast.Node.Index,
    context: *anyopaque,
) anyerror!void;

pub const WalkHooks = struct {
    on_enter: VisitControlCallback,
    on_exit: ?VisitExitCallback = null,
};

pub fn walk(
    tree: *const Ast,
    node: Ast.Node.Index,
    context: *anyopaque,
    callback: VisitCallback,
) anyerror!void {
    var bridge = LegacyBridge{
        .context = context,
        .callback = callback,
    };
    try walk_with_options(tree, node, &bridge, legacy_bridge_callback, .{});
}

pub fn walk_with_options(
    tree: *const Ast,
    node: Ast.Node.Index,
    context: *anyopaque,
    callback: VisitControlCallback,
    options: WalkOptions,
) anyerror!void {
    return walk_with_hooks(
        tree,
        node,
        context,
        .{ .on_enter = callback },
        options,
    );
}

pub fn walk_with_hooks(
    tree: *const Ast,
    node: Ast.Node.Index,
    context: *anyopaque,
    hooks: WalkHooks,
    options: WalkOptions,
) anyerror!void {
    assert(tree.nodes.items(.tag).len == tree.nodes.len);
    assert(node == .root or @intFromEnum(node) < tree.nodes.len);
    var state = WalkState{};
    var frames: [8192]WalkFrame = undefined;
    var frame_len: u16 = 0;
    try push_frame(&frames, &frame_len, node, .enter);

    while (frame_len > 0 and !state.stopped) {
        const frame = pop_frame(&frames, &frame_len);
        try process_walk_frame(tree, frame, context, hooks, options, &state, &frames, &frame_len);
    }
}

fn process_walk_frame(
    tree: *const Ast,
    frame: WalkFrame,
    context: *anyopaque,
    hooks: WalkHooks,
    options: WalkOptions,
    state: *WalkState,
    frames: *[8192]WalkFrame,
    frame_len: *u16,
) !void {
    assert(tree.nodes.items(.tag).len == tree.nodes.len);
    assert(@as(usize, frame_len.*) <= frames.len);
    if (frame.node == .root or @intFromEnum(frame.node) >= tree.nodes.len) return;
    if (frame.phase == .exit) {
        try run_exit_hook(tree, frame.node, context, hooks.on_exit);
        return;
    }
    if (try node_was_already_visited(frame.node, options.visited)) return;

    state.visited_nodes += 1;
    if (options.max_nodes) |max_nodes| {
        if (state.visited_nodes > max_nodes) return error.AstWalkLimit;
    }

    const decision = try hooks.on_enter(tree, frame.node, context);
    try apply_visit_decision(tree, frame, context, hooks, decision, state, frames, frame_len);
}

fn run_exit_hook(
    tree: *const Ast,
    node: Ast.Node.Index,
    context: *anyopaque,
    on_exit: ?VisitExitCallback,
) !void {
    assert(node == .root or @intFromEnum(node) < tree.nodes.len);
    assert(on_exit == null or on_exit != null);
    if (on_exit == null) return;
    if (on_exit) |cb| {
        try cb(tree, node, context);
    }
}

fn node_was_already_visited(node: Ast.Node.Index, visited_opt: ?*NodeVisited) !bool {
    assert(visited_opt == null or visited_opt != null);
    if (visited_opt == null) return false;
    const visited = visited_opt orelse return false;
    if (visited.contains(node)) return true;
    try visited.put(node, {});
    return false;
}

fn apply_visit_decision(
    tree: *const Ast,
    frame: WalkFrame,
    context: *anyopaque,
    hooks: WalkHooks,
    decision: VisitDecision,
    state: *WalkState,
    frames: *[8192]WalkFrame,
    frame_len: *u16,
) !void {
    switch (decision) {
        .stop => {
            state.stopped = true;
            try run_exit_hook(tree, frame.node, context, hooks.on_exit);
        },
        .skip_children => try run_exit_hook(tree, frame.node, context, hooks.on_exit),
        .visit_children => {
            if (hooks.on_exit != null) {
                try push_frame(frames, frame_len, frame.node, .exit);
            }
            try push_children(tree, frame.node, frames, frame_len);
        },
    }
}

const LegacyBridge = struct {
    context: *anyopaque,
    callback: VisitCallback,
};

const WalkState = struct {
    visited_nodes: usize = 0,
    stopped: bool = false,
};

const WalkPhase = enum { enter, exit };

const WalkFrame = struct {
    node: Ast.Node.Index,
    phase: WalkPhase,
};

fn legacy_bridge_callback(
    tree: *const Ast,
    node: Ast.Node.Index,
    ctx_opaque: *anyopaque,
) anyerror!VisitDecision {
    const bridge: *LegacyBridge = @ptrCast(@alignCast(ctx_opaque));
    try bridge.callback(tree, node, bridge.context);
    return .visit_children;
}

fn push_frame(
    frames: *[8192]WalkFrame,
    frame_len: *u16,
    node: Ast.Node.Index,
    phase: WalkPhase,
) !void {
    if (@as(usize, frame_len.*) >= frames.len) return error.AstWalkLimit;
    frames[@as(usize, frame_len.*)] = .{ .node = node, .phase = phase };
    frame_len.* += 1;
}

fn pop_frame(frames: *[8192]WalkFrame, frame_len: *u16) WalkFrame {
    frame_len.* -= 1;
    return frames[@as(usize, frame_len.*)];
}

fn push_child(frames: *[8192]WalkFrame, frame_len: *u16, node: Ast.Node.Index) !void {
    try push_frame(frames, frame_len, node, .enter);
}

fn push_children(
    tree: *const Ast,
    node: Ast.Node.Index,
    frames: *[8192]WalkFrame,
    frame_len: *u16,
) anyerror!void {
    assert(tree.nodes.items(.tag).len == tree.nodes.len);
    assert(@as(usize, frame_len.*) <= frames.len);
    const tag = tree.nodes.items(.tag)[@intFromEnum(node)];
    if (try push_children_group_a(tree, node, tag, frames, frame_len)) return;
    if (try push_children_group_b(tree, node, tag, frames, frame_len)) return;
}

fn push_children_group_a(
    tree: *const Ast,
    node: Ast.Node.Index,
    tag: Ast.Node.Tag,
    frames: *[8192]WalkFrame,
    frame_len: *u16,
) !bool {
    assert(node == .root or @intFromEnum(node) < tree.nodes.len);
    assert(@as(usize, frame_len.*) <= frames.len);
    if (is_call_tag(tag)) {
        try push_children_call(tree, node, frames, frame_len);
        return true;
    }
    if (is_builtin_variadic_tag(tag)) {
        try push_children_builtin_variadic(tree, node, frames, frame_len);
        return true;
    }
    if (is_builtin_two_tag(tag)) {
        try push_children_builtin_two(tree, node, frames, frame_len);
        return true;
    }
    if (is_block_tag(tag)) {
        try push_children_block(tree, node, frames, frame_len);
        return true;
    }
    if (is_block_two_tag(tag)) {
        try push_children_block_two(tree, node, frames, frame_len);
        return true;
    }
    if (is_if_tag(tag)) {
        try push_children_if(tree, node, frames, frame_len);
        return true;
    }
    if (is_while_tag(tag)) {
        try push_children_while(tree, node, frames, frame_len);
        return true;
    }
    if (is_for_tag(tag)) {
        try push_children_for(tree, node, frames, frame_len);
        return true;
    }
    return false;
}

fn push_children_group_b(
    tree: *const Ast,
    node: Ast.Node.Index,
    tag: Ast.Node.Tag,
    frames: *[8192]WalkFrame,
    frame_len: *u16,
) !bool {
    assert(node == .root or @intFromEnum(node) < tree.nodes.len);
    assert(@as(usize, frame_len.*) <= frames.len);
    if (is_switch_tag(tag)) {
        try push_children_switch(tree, node, frames, frame_len);
        return true;
    }
    if (is_switch_case_tag(tag)) {
        try push_children_switch_case(tree, node, frames, frame_len);
        return true;
    }
    if (is_var_decl_tag(tag)) {
        try push_children_var_decl(tree, node, frames, frame_len);
        return true;
    }
    if (is_node_and_token_child_tag(tag)) {
        const child = tree.nodeData(node).node_and_token[0];
        try push_child(frames, frame_len, child);
        return true;
    }
    if (is_unary_node_child_tag(tag)) {
        const child = tree.nodeData(node).node;
        try push_child(frames, frame_len, child);
        return true;
    }
    if (is_binary_pair_tag(tag)) {
        const pair = tree.nodeData(node).node_and_node;
        try push_child(frames, frame_len, pair[1]);
        try push_child(frames, frame_len, pair[0]);
        return true;
    }
    return false;
}

fn push_children_call(
    tree: *const Ast,
    node: Ast.Node.Index,
    frames: *[8192]WalkFrame,
    frame_len: *u16,
) !void {
    var call_buf: [1]Ast.Node.Index = undefined;
    const call = tree.fullCall(&call_buf, node) orelse return;
    var index = call.ast.params.len;
    while (index > 0) {
        index -= 1;
        try push_child(frames, frame_len, call.ast.params[index]);
    }
    try push_child(frames, frame_len, call.ast.fn_expr);
}

fn push_children_builtin_variadic(
    tree: *const Ast,
    node: Ast.Node.Index,
    frames: *[8192]WalkFrame,
    frame_len: *u16,
) !void {
    const args = tree.extraDataSlice(tree.nodeData(node).extra_range, Ast.Node.Index);
    var index = args.len;
    while (index > 0) {
        index -= 1;
        try push_child(frames, frame_len, args[index]);
    }
}

fn push_children_builtin_two(
    tree: *const Ast,
    node: Ast.Node.Index,
    frames: *[8192]WalkFrame,
    frame_len: *u16,
) !void {
    const first, const second = tree.nodeData(node).opt_node_and_opt_node;
    if (second.unwrap()) |second_arg| {
        try push_child(frames, frame_len, second_arg);
    }
    if (first.unwrap()) |first_arg| {
        try push_child(frames, frame_len, first_arg);
    }
}

fn push_children_block(
    tree: *const Ast,
    node: Ast.Node.Index,
    frames: *[8192]WalkFrame,
    frame_len: *u16,
) !void {
    const stmts = tree.extraDataSlice(tree.nodeData(node).extra_range, Ast.Node.Index);
    var index = stmts.len;
    while (index > 0) {
        index -= 1;
        try push_child(frames, frame_len, stmts[index]);
    }
}

fn push_children_block_two(
    tree: *const Ast,
    node: Ast.Node.Index,
    frames: *[8192]WalkFrame,
    frame_len: *u16,
) !void {
    const first, const second = tree.nodeData(node).opt_node_and_opt_node;
    if (second.unwrap()) |second_stmt| {
        try push_child(frames, frame_len, second_stmt);
    }
    if (first.unwrap()) |first_stmt| {
        try push_child(frames, frame_len, first_stmt);
    }
}

fn push_children_if(
    tree: *const Ast,
    node: Ast.Node.Index,
    frames: *[8192]WalkFrame,
    frame_len: *u16,
) !void {
    const full = tree.fullIf(node) orelse return;
    if (full.ast.else_expr.unwrap()) |else_expr| {
        try push_child(frames, frame_len, else_expr);
    }
    try push_child(frames, frame_len, full.ast.then_expr);
    try push_child(frames, frame_len, full.ast.cond_expr);
}

fn push_children_while(
    tree: *const Ast,
    node: Ast.Node.Index,
    frames: *[8192]WalkFrame,
    frame_len: *u16,
) !void {
    assert(node == .root or @intFromEnum(node) < tree.nodes.len);
    const full = tree.fullWhile(node) orelse return;
    if (full.ast.else_expr.unwrap()) |else_expr| {
        try push_child(frames, frame_len, else_expr);
    }
    if (full.ast.cont_expr.unwrap()) |cont_expr| {
        try push_child(frames, frame_len, cont_expr);
    }
    try push_child(frames, frame_len, full.ast.then_expr);
    try push_child(frames, frame_len, full.ast.cond_expr);
}

fn push_children_for(
    tree: *const Ast,
    node: Ast.Node.Index,
    frames: *[8192]WalkFrame,
    frame_len: *u16,
) !void {
    assert(node == .root or @intFromEnum(node) < tree.nodes.len);
    const full = tree.fullFor(node) orelse return;
    if (full.ast.else_expr.unwrap()) |else_expr| {
        try push_child(frames, frame_len, else_expr);
    }
    try push_child(frames, frame_len, full.ast.then_expr);
    var index = full.ast.inputs.len;
    while (index > 0) {
        index -= 1;
        try push_child(frames, frame_len, full.ast.inputs[index]);
    }
}

fn push_children_switch(
    tree: *const Ast,
    node: Ast.Node.Index,
    frames: *[8192]WalkFrame,
    frame_len: *u16,
) !void {
    const full = tree.switchFull(node);
    var index = full.ast.cases.len;
    while (index > 0) {
        index -= 1;
        try push_child(frames, frame_len, full.ast.cases[index]);
    }
    try push_child(frames, frame_len, full.ast.condition);
}

fn push_children_switch_case(
    tree: *const Ast,
    node: Ast.Node.Index,
    frames: *[8192]WalkFrame,
    frame_len: *u16,
) !void {
    const full = tree.fullSwitchCase(node) orelse return;
    try push_child(frames, frame_len, full.ast.target_expr);
    var index = full.ast.values.len;
    while (index > 0) {
        index -= 1;
        try push_child(frames, frame_len, full.ast.values[index]);
    }
}

fn push_children_var_decl(
    tree: *const Ast,
    node: Ast.Node.Index,
    frames: *[8192]WalkFrame,
    frame_len: *u16,
) !void {
    const var_decl = tree.fullVarDecl(node) orelse return;
    if (var_decl.ast.init_node.unwrap()) |init_node| {
        try push_child(frames, frame_len, init_node);
    }
    if (var_decl.ast.type_node.unwrap()) |type_node| {
        try push_child(frames, frame_len, type_node);
    }
}

fn is_call_tag(tag: Ast.Node.Tag) bool {
    return tag == .call or
        tag == .call_comma or
        tag == .call_one or
        tag == .call_one_comma;
}

fn is_builtin_variadic_tag(tag: Ast.Node.Tag) bool {
    return tag == .builtin_call or tag == .builtin_call_comma;
}

fn is_builtin_two_tag(tag: Ast.Node.Tag) bool {
    return tag == .builtin_call_two or tag == .builtin_call_two_comma;
}

fn is_block_tag(tag: Ast.Node.Tag) bool {
    return tag == .block or tag == .block_semicolon;
}

fn is_block_two_tag(tag: Ast.Node.Tag) bool {
    return tag == .block_two or tag == .block_two_semicolon;
}

fn is_if_tag(tag: Ast.Node.Tag) bool {
    return tag == .@"if" or tag == .if_simple;
}

fn is_while_tag(tag: Ast.Node.Tag) bool {
    return tag == .@"while" or tag == .while_simple or tag == .while_cont;
}

fn is_for_tag(tag: Ast.Node.Tag) bool {
    return tag == .@"for" or tag == .for_simple;
}

fn is_switch_tag(tag: Ast.Node.Tag) bool {
    return tag == .@"switch" or tag == .switch_comma;
}

fn is_switch_case_tag(tag: Ast.Node.Tag) bool {
    return tag == .switch_case_one or
        tag == .switch_case_inline_one or
        tag == .switch_case or
        tag == .switch_case_inline;
}

fn is_var_decl_tag(tag: Ast.Node.Tag) bool {
    return tag == .global_var_decl or
        tag == .local_var_decl or
        tag == .simple_var_decl or
        tag == .aligned_var_decl;
}

fn is_node_and_token_child_tag(tag: Ast.Node.Tag) bool {
    return tag == .field_access or tag == .unwrap_optional or tag == .grouped_expression;
}

fn is_unary_node_child_tag(tag: Ast.Node.Tag) bool {
    return tag == .@"try" or
        tag == .@"comptime" or
        tag == .deref or
        tag == .bool_not or
        tag == .negation or
        tag == .bit_not or
        tag == .negation_wrap or
        tag == .address_of or
        tag == .optional_type;
}

fn is_binary_pair_tag(tag: Ast.Node.Tag) bool {
    return tag == .assign or
        tag == .bool_and or
        tag == .bool_or or
        tag == .@"catch" or
        tag == .@"orelse" or
        tag == .array_access;
}

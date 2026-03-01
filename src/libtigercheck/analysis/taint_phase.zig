const std = @import("std");
const assert = std.debug.assert;
const taint = @import("../taint.zig");
const diagnostics = @import("diagnostics.zig");

const Result = diagnostics.Result;

pub fn append_with_parsed(
    allocator: std.mem.Allocator,
    taint_green_functions: *const std.StringHashMap(void),
    tree: *const std.zig.Ast,
    file_path: []const u8,
    green: *const std.StringHashMap(void),
    red: *const std.StringHashMap(void),
    result: *Result,
) !void {
    assert(file_path.len > 0);
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    if (file_path.len == 0) return;
    if (result.diagnostics.items.len != result.warning_count + result.critical_count) return;

    var file_facts = try taint.analyze_file_with_parsed_and_green_functions(
        allocator,
        file_path,
        tree,
        taint_green_functions,
    );
    defer file_facts.deinit();

    try append_memory_phase_diags_from_facts(
        allocator,
        file_facts.functions.items,
        green,
        red,
        result,
    );
    try append_first_unbounded_loop_diag(allocator, file_facts.functions.items, file_path, result);
}

fn append_memory_phase_diags_from_facts(
    allocator: std.mem.Allocator,
    function_facts: []const taint.FunctionFacts,
    green: *const std.StringHashMap(void),
    red: *const std.StringHashMap(void),
    result: *Result,
) !void {
    assert(function_facts.len <= std.math.maxInt(u32));
    assert(green.count() <= std.math.maxInt(u32));
    assert(red.count() <= std.math.maxInt(u32));
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    if (function_facts.len == 0) return;
    if (green.count() == 0 and red.count() == 0) return;
    if (result.diagnostics.items.len != result.warning_count + result.critical_count) return;
    for (function_facts) |facts| {
        if (!facts.has_forbidden_alloc) continue;
        const in_green = green.contains(facts.canonical_name);
        const in_red = red.contains(facts.canonical_name);
        if (!in_red) continue;
        try append_memory_phase_diag_for_fact(allocator, facts, in_green, result);
    }
}

fn append_memory_phase_diag_for_fact(
    allocator: std.mem.Allocator,
    facts: taint.FunctionFacts,
    in_green: bool,
    result: *Result,
) !void {
    assert(facts.file_path.len > 0);
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    if (facts.file_path.len == 0) return;
    if (in_green) {
        const mixed_msg = try std.fmt.allocPrint(
            allocator,
            "runtime allocation reaches execution path in `{s}` (mixed GREEN/RED reachability)",
            .{facts.function_name},
        );
        try diagnostics.append_pair(
            result,
            .critical,
            .N03_STATIC_MEMORY,
            .TS07_MEMORY_PHASE,
            facts.file_path,
            mixed_msg,
        );
        return;
    }
    const red_msg = try std.fmt.allocPrint(
        allocator,
        "runtime allocation reaches execution path in `{s}` (RED)",
        .{facts.function_name},
    );
    try diagnostics.append_pair(
        result,
        .critical,
        .N03_STATIC_MEMORY,
        .TS07_MEMORY_PHASE,
        facts.file_path,
        red_msg,
    );
}

fn append_first_unbounded_loop_diag(
    allocator: std.mem.Allocator,
    function_facts: []const taint.FunctionFacts,
    file_path: []const u8,
    result: *Result,
) !void {
    assert(file_path.len > 0);
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    if (file_path.len == 0) return;
    if (result.diagnostics.items.len != result.warning_count + result.critical_count) return;
    for (function_facts) |facts| {
        if (!facts.has_unbounded_loop) continue;
        const msg = try std.fmt.allocPrint(
            allocator,
            "unproven loop bound in `{s}` (must be const/comptime/init-time immutable); " ++
                "rewrite with explicit finite upper bound",
            .{facts.function_name},
        );
        try diagnostics.append_pair(
            result,
            .critical,
            .N02_BOUNDED_LOOPS,
            .TS02_EXPLICIT_BOUNDS,
            file_path,
            msg,
        );
        return;
    }
}

const std = @import("std");
const assert = std.debug.assert;
const metrics = @import("../metrics.zig");
const asserts = @import("../asserts.zig");
const diagnostics = @import("diagnostics.zig");

const append_diag = diagnostics.append;
const Result = diagnostics.Result;

pub fn append_metric_quality_diagnostics(
    allocator: std.mem.Allocator,
    max_function_lines: u32,
    file_metrics: *const metrics.FileMetrics,
    result: *Result,
) !void {
    assert(max_function_lines > 0);
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    for (file_metrics.functions.items) |m| {
        if (m.logical_line_count > max_function_lines) {
            const msg = try std.fmt.allocPrint(
                allocator,
                "Function exceeds Tiger Style size limit in `{s}` ({d} > {d} lines).",
                .{ m.function_name, m.logical_line_count, max_function_lines },
            );
            try diagnostics.append_pair(
                result,
                .warning,
                .N04_FUNCTION_SIZE,
                .TS09_FUNCTION_SHAPE,
                m.file_path,
                msg,
            );
        }
        if (m.cyclomatic_complexity > 10) {
            const msg = try std.fmt.allocPrint(
                allocator,
                "Cyclomatic complexity too high in `{s}` (complexity={d}); split control-plane " ++
                    "branching from data-plane execution.",
                .{ m.function_name, m.cyclomatic_complexity },
            );
            try append_diag(result, .warning, .TS12_PLANE_BOUNDARY, m.file_path, msg);
        }
        if (m.comptime_max_nesting > 3) {
            const msg = try std.fmt.allocPrint(
                allocator,
                "Comptime complexity too high in `{s}` (max nesting={d}). " ++
                    "Refactor metaprogramming logic.",
                .{ m.function_name, m.comptime_max_nesting },
            );
            try append_diag(
                result,
                .warning,
                .N08_PREPROCESSOR_OR_COMPTIME_BUDGET,
                m.file_path,
                msg,
            );
        }
        if (m.total_node_count > 0 and (m.comptime_node_count * 100) > (m.total_node_count * 20)) {
            const msg = try std.fmt.allocPrint(
                allocator,
                "Comptime node budget exceeded in `{s}` (comptime={d}, total={d}). " ++
                    "Reduce metaprogramming surface.",
                .{ m.function_name, m.comptime_node_count, m.total_node_count },
            );
            try append_diag(
                result,
                .warning,
                .N08_PREPROCESSOR_OR_COMPTIME_BUDGET,
                m.file_path,
                msg,
            );
        }
    }
}

pub fn append_assert_quality_diagnostics(
    allocator: std.mem.Allocator,
    file_metrics: *const metrics.FileMetrics,
    file_asserts: *const asserts.FileAssertFacts,
    result: *Result,
) !void {
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    assert(file_asserts.functions.items.len <= file_asserts.functions.capacity);
    for (file_asserts.functions.items) |a| {
        const metric = find_metric(file_metrics, a.canonical_name) orelse continue;
        if (metric.statement_count > 10 and a.assert_count == 0) {
            const msg = try std.fmt.allocPrint(
                allocator,
                "N05_ASSERTION_DENSITY: Unsafe complexity (0 assertions) in `{s}`.",
                .{a.function_name},
            );
            try append_diag(result, .warning, .N05_ASSERTION_DENSITY, a.file_path, msg);
        }
        if (metric.cyclomatic_complexity > 5 and a.assert_count < 2) {
            const msg = try std.fmt.allocPrint(
                allocator,
                "High complexity requires stronger invariants in `{s}` " ++
                    "(complexity={d}, asserts={d}).",
                .{ a.function_name, metric.cyclomatic_complexity, a.assert_count },
            );
            try append_diag(result, .warning, .N05_ASSERTION_DENSITY, a.file_path, msg);
        }
        if (a.has_relevant_params and !has_complete_param_assert_coverage(a)) {
            const msg = try std.fmt.allocPrint(
                allocator,
                "TS06_POS_NEG_ASSERT: function `{s}` needs both positive " ++
                    "assertions and negative-space guards for inputs",
                .{a.function_name},
            );
            try append_diag(result, .warning, .TS06_POS_NEG_ASSERT, a.file_path, msg);
        }
        if (a.has_unpaired_path_assert) {
            const msg = try std.fmt.allocPrint(
                allocator,
                "TS05_PAIR_ASSERT: function `{s}` has independent param paths " ++
                    "with unpaired assertions",
                .{a.function_name},
            );
            try append_diag(result, .warning, .TS05_PAIR_ASSERT, a.file_path, msg);
        }
        if (a.has_split_assert) {
            try append_diag(
                result,
                .critical,
                .TS13_BOOLEAN_SPLIT,
                a.file_path,
                "Ambiguous assertion. Split `assert(A and B)` into " ++
                    "`assert(A); assert(B);`.",
            );
        }
        if (!a.has_param_precondition) {
            try append_missing_param_precondition_diagnostics(allocator, a, result);
        }
        if (a.has_negative_invariant) {
            try append_diag(
                result,
                .warning,
                .TS14_POSITIVE_INVARIANTS,
                a.file_path,
                "TS14_POSITIVE_INVARIANTS: Prefer positive invariant forms. " ++
                    "Use ordered boundary checks instead of negated comparisons " ++
                    "(except null checks).",
            );
        }
    }
}

fn has_complete_param_assert_coverage(facts: asserts.FunctionAssertFacts) bool {
    if (!facts.has_positive_param_assert) return false;
    return facts.has_negative_param_guard;
}

fn append_missing_param_precondition_diagnostics(
    allocator: std.mem.Allocator,
    facts: asserts.FunctionAssertFacts,
    result: *Result,
) !void {
    const n07_msg = try std.fmt.allocPrint(
        allocator,
        "N07_RETURN_AND_PARAM_CHECKS: missing parameter precondition coverage in `{s}`",
        .{facts.function_name},
    );
    try append_diag(
        result,
        .warning,
        .N07_RETURN_AND_PARAM_CHECKS,
        facts.file_path,
        n07_msg,
    );
    const msg = try std.fmt.allocPrint(
        allocator,
        "Missing pre-condition check for arguments in `{s}`.",
        .{facts.function_name},
    );
    try append_diag(result, .warning, .TS04_ASSERTIONS, facts.file_path, msg);
}

fn find_metric(
    file_metrics: *const metrics.FileMetrics,
    canonical_name: []const u8,
) ?metrics.FunctionMetric {
    assert(canonical_name.len > 0);
    assert(std.mem.indexOf(u8, canonical_name, "::") != null);
    if (canonical_name.len == 0) return null;
    if (std.mem.indexOf(u8, canonical_name, "::") == null) return null;
    for (file_metrics.functions.items) |m| {
        if (std.mem.eql(u8, m.canonical_name, canonical_name)) {
            return m;
        }
    }
    return null;
}


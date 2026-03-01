const std = @import("std");
const assert = std.debug.assert;
const style = @import("../style.zig");
const metrics = @import("../metrics.zig");
const diagnostics = @import("diagnostics.zig");

const append_diag = diagnostics.append;
const Result = diagnostics.Result;

pub fn append_style_diagnostics_with_parsed(
    allocator: std.mem.Allocator,
    file_path: []const u8,
    tree: *const std.zig.Ast,
    result: *Result,
) !void {
    assert(file_path.len > 0);
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    if (file_path.len == 0) return;
    if (result.diagnostics.items.len != result.warning_count + result.critical_count) return;
    var style_diagnostics = std.array_list.Managed(style.StyleDiagnostic).init(allocator);
    defer style_diagnostics.deinit();
    try style.analyze_file_with_parsed(allocator, file_path, tree, &style_diagnostics);
    for (style_diagnostics.items) |diag| {
        try append_diag(result, .warning, diag.rule_id, diag.file_path, diag.message);
    }
}

pub fn append_line_length_diag(
    allocator: std.mem.Allocator,
    file_path: []const u8,
    file_metrics: *const metrics.FileMetrics,
    line_length_limit: u32,
    result: *Result,
) !void {
    assert(file_path.len > 0);
    assert(line_length_limit > 0);
    if (file_path.len == 0) return;
    if (line_length_limit == 0) return;
    const long_line_count = count_lines_over_limit(file_metrics, line_length_limit);
    if (long_line_count == 0) return;
    const msg = try std.fmt.allocPrint(
        allocator,
        "TS26_LINE_LENGTH: {d} line(s) exceed {d} column limit (max: {d})",
        .{
            long_line_count,
            line_length_limit,
            file_metrics.max_line_length,
        },
    );
    try append_diag(result, .warning, .TS26_LINE_LENGTH, file_path, msg);
}

fn count_lines_over_limit(file_metrics: *const metrics.FileMetrics, limit: u32) u32 {
    assert(limit > 0);
    var count: u32 = 0;
    for (file_metrics.line_lengths.items) |line_length| {
        if (line_length > limit) {
            count += 1;
        }
    }
    return count;
}

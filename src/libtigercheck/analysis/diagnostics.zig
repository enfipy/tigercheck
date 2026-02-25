const std = @import("std");
const assert = std.debug.assert;
const rules = @import("../rules.zig");
const policy = @import("../policy.zig");

pub const Severity = enum {
    warning,
    critical,
};

pub const Diagnostic = struct {
    severity: Severity,
    rule_id: rules.Id,
    file_path: []const u8,
    message: []const u8,
    line: ?u32 = null,
    column: ?u32 = null,
    hint: ?[]const u8 = null,
    effective_class: ?policy.CodeClass = null,
    effective_action: ?policy.Action = null,
};

pub const Result = struct {
    diagnostics: std.array_list.Managed(Diagnostic),
    critical_count: usize,
    warning_count: usize,
    policy_profile: []const u8,
    suppressed_count: usize,
    downgraded_count: usize,
    policy_applied: bool,

    pub fn init(allocator: std.mem.Allocator) Result {
        return .{
            .diagnostics = std.array_list.Managed(Diagnostic).init(allocator),
            .critical_count = 0,
            .warning_count = 0,
            .policy_profile = "",
            .suppressed_count = 0,
            .downgraded_count = 0,
            .policy_applied = false,
        };
    }

    pub fn deinit(self: *Result) void {
        self.diagnostics.deinit();
    }
};

pub const AppendOptions = struct {
    line: ?u32 = null,
    column: ?u32 = null,
    hint: ?[]const u8 = null,
};

pub fn append(
    result: *Result,
    severity: Severity,
    rule_id: rules.Id,
    file_path: []const u8,
    message: []const u8,
    options: AppendOptions,
) !void {
    assert(file_path.len > 0);
    assert(message.len > 0);
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    if (file_path.len == 0) return;
    if (message.len == 0) return;
    for (result.diagnostics.items) |existing| {
        if (diag_is_exact_match(
            existing,
            severity,
            rule_id,
            file_path,
            message,
            options.line,
            options.column,
        )) {
            return;
        }
    }

    try result.diagnostics.append(.{
        .severity = severity,
        .rule_id = rule_id,
        .file_path = file_path,
        .message = message,
        .line = options.line,
        .column = options.column,
        .hint = options.hint orelse default_hint_for_rule(rule_id),
    });
    if (severity == .critical) {
        result.critical_count += 1;
    } else {
        result.warning_count += 1;
    }
}

pub fn append_pair(
    result: *Result,
    severity: Severity,
    first_rule_id: rules.Id,
    second_rule_id: rules.Id,
    file_path: []const u8,
    message: []const u8,
    options: AppendOptions,
) !void {
    assert(file_path.len > 0);
    assert(message.len > 0);
    if (file_path.len == 0) return;
    if (message.len == 0) return;
    if (first_rule_id == second_rule_id) return;
    try append(result, severity, first_rule_id, file_path, message, options);
    try append(result, severity, second_rule_id, file_path, message, options);
}

pub fn apply_precedence_and_dedup(result: *Result) !void {
    assert(result.diagnostics.items.len == result.warning_count + result.critical_count);
    sort_by_precedence(result);

    var filtered = std.array_list.Managed(Diagnostic).init(result.diagnostics.allocator);
    errdefer filtered.deinit();

    var warning_count: usize = 0;
    var critical_count: usize = 0;

    for (result.diagnostics.items) |diag| {
        if (has_exact_diagnostic_already_reported(filtered.items, diag)) {
            continue;
        }
        try filtered.append(diag);
        if (diag.severity == .critical) {
            critical_count += 1;
        } else {
            warning_count += 1;
        }
    }

    result.diagnostics.deinit();
    result.diagnostics = filtered;
    result.warning_count = warning_count;
    result.critical_count = critical_count;
}

fn sort_by_precedence(result: *Result) void {
    std.mem.sort(Diagnostic, result.diagnostics.items, {}, struct {
        fn lt(_: void, lhs: Diagnostic, rhs: Diagnostic) bool {
            if (lhs.severity != rhs.severity) {
                return lhs.severity == .critical;
            }
            const lhs_rule = @intFromEnum(lhs.rule_id);
            const rhs_rule = @intFromEnum(rhs.rule_id);
            if (lhs_rule != rhs_rule) {
                return lhs_rule < rhs_rule;
            }
            const file_order = std.mem.order(u8, lhs.file_path, rhs.file_path);
            if (file_order != .eq) {
                return file_order == .lt;
            }
            const lhs_line = lhs.line orelse 0;
            const rhs_line = rhs.line orelse 0;
            if (lhs_line != rhs_line) {
                return lhs_line < rhs_line;
            }
            const lhs_column = lhs.column orelse 0;
            const rhs_column = rhs.column orelse 0;
            if (lhs_column != rhs_column) {
                return lhs_column < rhs_column;
            }
            return std.mem.order(u8, lhs.message, rhs.message) == .lt;
        }
    }.lt);
}

fn has_exact_diagnostic_already_reported(existing: []const Diagnostic, candidate: Diagnostic) bool {
    assert(existing.len <= 4096);
    assert(candidate.file_path.len > 0);
    if (existing.len == 0) return false;
    if (candidate.file_path.len == 0) return false;
    for (existing) |diag| {
        if (diag_exact_match(diag, candidate)) {
            return true;
        }
    }
    return false;
}

fn diag_exact_match(lhs: Diagnostic, rhs: Diagnostic) bool {
    assert(lhs.file_path.len > 0);
    assert(rhs.file_path.len > 0);
    if (lhs.file_path.len == 0 or rhs.file_path.len == 0) return false;
    if (lhs.severity != rhs.severity) return false;
    if (lhs.rule_id != rhs.rule_id) return false;
    if (!std.mem.eql(u8, lhs.file_path, rhs.file_path)) return false;
    if (lhs.line != rhs.line) return false;
    if (lhs.column != rhs.column) return false;
    return std.mem.eql(u8, lhs.message, rhs.message);
}

fn diag_is_exact_match(
    existing: Diagnostic,
    severity: Severity,
    rule_id: rules.Id,
    file_path: []const u8,
    message: []const u8,
    line: ?u32,
    column: ?u32,
) bool {
    assert(file_path.len > 0);
    assert(message.len > 0);
    if (file_path.len == 0) return false;
    if (message.len == 0) return false;
    if (existing.severity != severity) return false;
    if (existing.rule_id != rule_id) return false;
    if (!std.mem.eql(u8, existing.file_path, file_path)) return false;
    if (existing.line != line) return false;
    if (existing.column != column) return false;
    return std.mem.eql(u8, existing.message, message);
}

fn default_hint_for_rule(rule_id: rules.Id) ?[]const u8 {
    return switch (rule_id) {
        .N02_BOUNDED_LOOPS,
        .TS02_EXPLICIT_BOUNDS,
        .N03_STATIC_MEMORY,
        .TS07_MEMORY_PHASE,
        .TS12_PLANE_BOUNDARY,
        => rules.rewrite_hint(rule_id),
        else => null,
    };
}

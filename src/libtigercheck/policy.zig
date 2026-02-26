const std = @import("std");
const assert = std.debug.assert;
const rules = @import("rules.zig");
const build_options = @import("build_options");

pub const Action = enum {
    enforce,
    warn,
    off,
};

pub const CodeClass = enum {
    runtime,
    test_or_fuzz,
    tooling,
    bindings,
    vendored,
};

pub const Thresholds = struct {
    max_function_lines: ?u16 = null,
    max_line_length: ?u16 = null,
};

pub const RuleOverrides = struct {
    off_csv: []const u8,
};

const SegmentNeedle = struct {
    value: []const u8,
};

pub const Policy = struct {
    profile_name: []const u8,
    hard_rules: []const rules.Id,
    default_action: Action,
    default_thresholds: Thresholds,
    rule_overrides: RuleOverrides,
};

const hard_rules_v1 = [_]rules.Id{
    .N03_STATIC_MEMORY,
    .N06_SCOPE_MINIMIZATION,
    .N07_RETURN_AND_PARAM_CHECKS,
    .N09_POINTER_DISCIPLINE,
    .TS13_BOOLEAN_SPLIT,
    .N02_BOUNDED_LOOPS,
};
const rule_override_tokens_max = @typeInfo(rules.Id).@"enum".fields.len;

pub fn for_core() Policy {
    return .{
        .profile_name = "core",
        .hard_rules = &hard_rules_v1,
        .default_action = .enforce,
        .default_thresholds = .{ .max_function_lines = 70, .max_line_length = 100 },
        .rule_overrides = .{ .off_csv = csv_option("off_rules") },
    };
}

pub fn validate(policy_value: Policy) !void {
    assert(policy_value.profile_name.len > 0);

    var seen = std.StaticBitSet(@typeInfo(rules.Id).@"enum".fields.len).initEmpty();
    try validate_off_override_csv(policy_value, policy_value.rule_overrides.off_csv, &seen);
}

pub fn classify_path(_: Policy, file_path: []const u8) CodeClass {
    assert(file_path.len > 0);
    assert(file_path.len <= 4096);
    assert(std.mem.indexOfScalar(u8, file_path, 0) == null);
    if (file_path.len == 0) return .runtime;
    if (file_path.len > 4096) return .runtime;
    if (path_has_any_segment(
        file_path,
        &.{
            .{ .value = "vendor" },
            .{ .value = "vendors" },
            .{ .value = "vendored" },
            .{ .value = "third_party" },
            .{ .value = "third-party" },
            .{ .value = "external" },
            .{ .value = "deps" },
            .{ .value = "dependency" },
            .{ .value = "dependencies" },
        },
    )) {
        return .vendored;
    }
    if (path_has_any_segment(
        file_path,
        &.{
            .{ .value = "binding" },
            .{ .value = "bindings" },
            .{ .value = "ffi" },
            .{ .value = "cbindgen" },
            .{ .value = "interop" },
        },
    )) {
        return .bindings;
    }
    if (path_has_any_segment(
        file_path,
        &.{
            .{ .value = "test" },
            .{ .value = "tests" },
            .{ .value = "fuzz" },
            .{ .value = "fuzzer" },
            .{ .value = "fuzzers" },
            .{ .value = "bench" },
            .{ .value = "benches" },
        },
    )) {
        return .test_or_fuzz;
    }
    if (path_has_any_segment(
        file_path,
        &.{
            .{ .value = "tool" },
            .{ .value = "tools" },
            .{ .value = "scripts" },
            .{ .value = "script" },
            .{ .value = "ci" },
        },
    )) {
        return .tooling;
    }
    return .runtime;
}

pub fn action_for(policy_value: Policy, class: CodeClass, rule: rules.Id) Action {
    assert(policy_value.profile_name.len > 0);

    if (is_effectively_hard_rule(policy_value, class, rule)) {
        return .enforce;
    }

    if (csv_mentions_rule(policy_value.rule_overrides.off_csv, rule)) {
        return .off;
    }

    return switch (class) {
        .runtime => policy_value.default_action,
        .test_or_fuzz, .tooling, .bindings => .warn,
        .vendored => .off,
    };
}

pub fn thresholds_for(policy_value: Policy, class: CodeClass) Thresholds {
    return switch (class) {
        .runtime => policy_value.default_thresholds,
        .test_or_fuzz => policy_value.default_thresholds,
        .tooling => .{
            .max_function_lines = if (policy_value.default_thresholds.max_function_lines) |v|
                v +| 40
            else
                null,
            .max_line_length = if (policy_value.default_thresholds.max_line_length) |v|
                v +| 20
            else
                null,
        },
        .bindings => .{
            .max_function_lines = if (policy_value.default_thresholds.max_function_lines) |v|
                v +| 20
            else
                null,
            .max_line_length = policy_value.default_thresholds.max_line_length,
        },
        .vendored => .{
            .max_function_lines = if (policy_value.default_thresholds.max_function_lines) |v|
                v +| 180
            else
                null,
            .max_line_length = if (policy_value.default_thresholds.max_line_length) |v|
                v +| 80
            else
                null,
        },
    };
}

pub fn is_effectively_hard_rule(policy_value: Policy, class: CodeClass, rule: rules.Id) bool {
    return switch (class) {
        .runtime,
        .test_or_fuzz,
        .tooling,
        .bindings,
        .vendored,
        => contains_rule(policy_value.hard_rules, rule),
    };
}

fn path_has_any_segment(file_path: []const u8, needles: []const SegmentNeedle) bool {
    assert(file_path.len > 0);
    assert(needles.len > 0);
    if (file_path.len == 0) return false;
    for (needles) |needle| {
        if (needle.value.len == 0) continue;
        if (path_has_segment(file_path, needle.value)) {
            return true;
        }
    }
    return false;
}

fn path_has_segment(file_path: []const u8, needle: []const u8) bool {
    assert(file_path.len > 0);
    assert(needle.len > 0);
    if (file_path.len == 0) return false;
    if (needle.len == 0) return false;
    var start: usize = 0;
    var i: usize = 0;
    while (i <= file_path.len) : (i += 1) {
        if (i != file_path.len and !is_path_separator(file_path[i])) {
            continue;
        }
        const segment = file_path[start..i];
        if (std.ascii.eqlIgnoreCase(segment, needle)) {
            return true;
        }
        start = i + 1;
    }
    return false;
}

fn is_path_separator(byte: u8) bool {
    return byte == '/' or byte == '\\';
}

fn validate_off_override_csv(
    policy_value: Policy,
    csv: []const u8,
    seen: *std.StaticBitSet(@typeInfo(rules.Id).@"enum".fields.len),
) !void {
    assert(policy_value.profile_name.len > 0);
    assert(csv.len <= 4096);
    if (csv.len == 0) return;

    var tokens = std.mem.tokenizeScalar(u8, csv, ',');
    for (0..rule_override_tokens_max) |_| {
        const raw = tokens.next() orelse break;
        const token = std.mem.trim(u8, raw, " \t\r\n");
        if (token.len == 0) {
            continue;
        }

        const rule = parse_rule_id(token) orelse return error.InvalidRuleOverride;
        const idx = @intFromEnum(rule);
        if (seen.isSet(idx)) {
            return error.DuplicateRuleOverride;
        }
        seen.set(idx);

        if (contains_rule(policy_value.hard_rules, rule)) {
            return error.HardRuleDowngradeForbidden;
        }
    }
    if (tokens.next() != null) {
        return error.TooManyRuleOverrides;
    }
}

fn csv_mentions_rule(csv: []const u8, target: rules.Id) bool {
    assert(csv.len <= 4096);
    assert(@intFromEnum(target) < @typeInfo(rules.Id).@"enum".fields.len);
    if (csv.len == 0) return false;

    var tokens = std.mem.tokenizeScalar(u8, csv, ',');
    for (0..rule_override_tokens_max) |_| {
        const raw = tokens.next() orelse break;
        const token = std.mem.trim(u8, raw, " \t\r\n");
        if (token.len == 0) {
            continue;
        }
        const rule = parse_rule_id(token) orelse continue;
        if (rule == target) {
            return true;
        }
    }
    return false;
}

fn parse_rule_id(value: []const u8) ?rules.Id {
    assert(value.len > 0);
    if (value.len == 0) return null;
    return std.meta.stringToEnum(rules.Id, value);
}

fn contains_rule(hard_rules: []const rules.Id, rule: rules.Id) bool {
    assert(hard_rules.len <= @typeInfo(rules.Id).@"enum".fields.len);
    if (hard_rules.len == 0) return false;
    for (hard_rules) |hard_rule| {
        if (hard_rule == rule) {
            return true;
        }
    }
    return false;
}

fn csv_option(comptime name: []const u8) []const u8 {
    assert(name.len > 0);
    if (name.len == 0) return "";
    if (@hasDecl(build_options, name)) {
        return @field(build_options, name);
    }
    return "";
}

test "default core policy enforces by default" {
    const p = for_core();
    try validate(p);
    try std.testing.expect(action_for(p, .runtime, .TS17_SNAKE_CASE) == .enforce);
    try std.testing.expect(action_for(p, .runtime, .N02_BOUNDED_LOOPS) == .enforce);
}

test "hard rules cannot be downgraded" {
    const bad = Policy{
        .profile_name = "bad",
        .hard_rules = &hard_rules_v1,
        .default_action = .enforce,
        .default_thresholds = .{ .max_function_lines = 70, .max_line_length = 100 },
        .rule_overrides = .{ .off_csv = "N03_STATIC_MEMORY" },
    };
    try std.testing.expectError(error.HardRuleDowngradeForbidden, validate(bad));
}

test "override CSV rejects duplicates" {
    const bad = Policy{
        .profile_name = "bad",
        .hard_rules = &hard_rules_v1,
        .default_action = .enforce,
        .default_thresholds = .{ .max_function_lines = 70, .max_line_length = 100 },
        .rule_overrides = .{ .off_csv = "TS17_SNAKE_CASE,TS17_SNAKE_CASE" },
    };
    try std.testing.expectError(error.DuplicateRuleOverride, validate(bad));
}

test "classify_path routes known code classes" {
    const p = for_core();
    try std.testing.expectEqual(
        CodeClass.runtime,
        classify_path(p, "/repo/src/libtigercheck/analysis/root.zig"),
    );
    try std.testing.expectEqual(
        CodeClass.test_or_fuzz,
        classify_path(p, "/repo/tests/corpus/nasa/fail_N01_recursion.zig"),
    );
    try std.testing.expectEqual(
        CodeClass.tooling,
        classify_path(p, "/repo/src/tools/release.zig"),
    );
    try std.testing.expectEqual(
        CodeClass.bindings,
        classify_path(p, "/repo/bindings/c/tigercheck.zig"),
    );
    try std.testing.expectEqual(
        CodeClass.vendored,
        classify_path(p, "/repo/third_party/lib/something.zig"),
    );
}

test "class actions differ and hard rules stay enforced" {
    const p = for_core();
    try std.testing.expectEqual(Action.enforce, action_for(p, .runtime, .TS17_SNAKE_CASE));
    try std.testing.expectEqual(Action.warn, action_for(p, .tooling, .TS17_SNAKE_CASE));
    try std.testing.expectEqual(Action.off, action_for(p, .vendored, .TS17_SNAKE_CASE));
    try std.testing.expectEqual(Action.enforce, action_for(p, .vendored, .N02_BOUNDED_LOOPS));
}

test "thresholds vary by class" {
    const p = for_core();
    const runtime = thresholds_for(p, .runtime);
    const test_or_fuzz = thresholds_for(p, .test_or_fuzz);
    const tooling = thresholds_for(p, .tooling);
    const vendored = thresholds_for(p, .vendored);
    try std.testing.expect(runtime.max_function_lines.? == 70);
    try std.testing.expect(runtime.max_line_length.? == 100);
    try std.testing.expect(test_or_fuzz.max_function_lines.? == runtime.max_function_lines.?);
    try std.testing.expect(test_or_fuzz.max_line_length.? == runtime.max_line_length.?);
    try std.testing.expect(tooling.max_function_lines.? > runtime.max_function_lines.?);
    try std.testing.expect(vendored.max_line_length.? > tooling.max_line_length.?);
}

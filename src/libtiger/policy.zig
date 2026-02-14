const std = @import("std");
const assert = std.debug.assert;
const rules = @import("rules.zig");

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

pub const RuleAction = struct {
    rule: rules.Id,
    action: Action,
};

pub const PathGlob = struct {
    pattern: []const u8,
};

pub const Thresholds = struct {
    max_function_lines: ?u16 = null,
    max_line_length: ?u16 = null,
};

pub const ClassPolicy = struct {
    class: CodeClass,
    path_globs: []const PathGlob,
    rule_actions: []const RuleAction,
    thresholds: Thresholds,
};

pub const Profile = enum {
    strict_core,
    tigerbeetle_repo,
};

pub const Policy = struct {
    profile_name: []const u8,
    hard_rules: []const rules.Id,
    class_policies: []const ClassPolicy,
    default_action: Action,
    default_thresholds: Thresholds,
};

const empty_rule_actions = [_]RuleAction{};
const empty_class_policies = [_]ClassPolicy{};

const hard_rules_v1 = [_]rules.Id{
    .N03_STATIC_MEMORY,
    .N06_SCOPE_MINIMIZATION,
    .N07_RETURN_AND_PARAM_CHECKS,
    .N09_POINTER_DISCIPLINE,
    .TS13_BOOLEAN_SPLIT,
    .N02_BOUNDED_LOOPS,
};

const test_or_fuzz_globs = [_]PathGlob{
    .{ .pattern = "**/testing/**" },
    .{ .pattern = "**/tests/**" },
    .{ .pattern = "**/*_fuzz.zig" },
    .{ .pattern = "**/*_test.zig" },
    .{ .pattern = "**/unit_tests.zig" },
    .{ .pattern = "**/fuzz_tests.zig" },
};

const tooling_globs = [_]PathGlob{
    .{ .pattern = "**/scripts/**" },
    .{ .pattern = "**/docs_website/**" },
};

const bindings_globs = [_]PathGlob{
    .{ .pattern = "**/clients/**" },
};

const vendored_globs = [_]PathGlob{
    .{ .pattern = "**/vendored/**" },
    .{ .pattern = "**/vendor/**" },
};

const test_or_fuzz_rule_actions = [_]RuleAction{
    .{ .rule = .N04_FUNCTION_SIZE, .action = .warn },
    .{ .rule = .N05_ASSERTION_DENSITY, .action = .off },
    .{ .rule = .N08_PREPROCESSOR_OR_COMPTIME_BUDGET, .action = .warn },
    .{ .rule = .TS04_ASSERTIONS, .action = .off },
    .{ .rule = .TS17_SNAKE_CASE, .action = .warn },
    .{ .rule = .TS21_CALLBACK_LAST, .action = .warn },
    .{ .rule = .TS22_STRUCT_ORDER, .action = .warn },
    .{ .rule = .TS26_LINE_LENGTH, .action = .warn },
    .{ .rule = .N02_BOUNDED_LOOPS, .action = .warn },
};

const tooling_rule_actions = [_]RuleAction{
    .{ .rule = .TS17_SNAKE_CASE, .action = .off },
    .{ .rule = .TS21_CALLBACK_LAST, .action = .off },
    .{ .rule = .TS22_STRUCT_ORDER, .action = .off },
    .{ .rule = .TS26_LINE_LENGTH, .action = .off },
    .{ .rule = .N04_FUNCTION_SIZE, .action = .warn },
    .{ .rule = .N05_ASSERTION_DENSITY, .action = .off },
    .{ .rule = .N08_PREPROCESSOR_OR_COMPTIME_BUDGET, .action = .warn },
    .{ .rule = .TS04_ASSERTIONS, .action = .off },
    .{ .rule = .N02_BOUNDED_LOOPS, .action = .warn },
};

const bindings_rule_actions = [_]RuleAction{
    .{ .rule = .TS17_SNAKE_CASE, .action = .off },
    .{ .rule = .TS21_CALLBACK_LAST, .action = .off },
    .{ .rule = .TS22_STRUCT_ORDER, .action = .off },
    .{ .rule = .TS26_LINE_LENGTH, .action = .off },
    .{ .rule = .N04_FUNCTION_SIZE, .action = .warn },
    .{ .rule = .N05_ASSERTION_DENSITY, .action = .off },
    .{ .rule = .N08_PREPROCESSOR_OR_COMPTIME_BUDGET, .action = .warn },
    .{ .rule = .TS04_ASSERTIONS, .action = .off },
    .{ .rule = .N02_BOUNDED_LOOPS, .action = .warn },
};

const vendored_rule_actions = [_]RuleAction{
    .{ .rule = .TS17_SNAKE_CASE, .action = .off },
    .{ .rule = .TS21_CALLBACK_LAST, .action = .off },
    .{ .rule = .TS22_STRUCT_ORDER, .action = .off },
    .{ .rule = .TS26_LINE_LENGTH, .action = .off },
    .{ .rule = .N04_FUNCTION_SIZE, .action = .off },
    .{ .rule = .N05_ASSERTION_DENSITY, .action = .off },
    .{ .rule = .N08_PREPROCESSOR_OR_COMPTIME_BUDGET, .action = .off },
    .{ .rule = .TS04_ASSERTIONS, .action = .off },
    .{ .rule = .N02_BOUNDED_LOOPS, .action = .warn },
};

const tigerbeetle_class_policies = [_]ClassPolicy{
    .{
        .class = .test_or_fuzz,
        .path_globs = &test_or_fuzz_globs,
        .rule_actions = &test_or_fuzz_rule_actions,
        .thresholds = .{ .max_function_lines = 180, .max_line_length = 120 },
    },
    .{
        .class = .tooling,
        .path_globs = &tooling_globs,
        .rule_actions = &tooling_rule_actions,
        .thresholds = .{ .max_function_lines = 180, .max_line_length = 120 },
    },
    .{
        .class = .bindings,
        .path_globs = &bindings_globs,
        .rule_actions = &bindings_rule_actions,
        .thresholds = .{ .max_function_lines = 220, .max_line_length = 140 },
    },
    .{
        .class = .vendored,
        .path_globs = &vendored_globs,
        .rule_actions = &vendored_rule_actions,
        .thresholds = .{ .max_function_lines = 280, .max_line_length = 160 },
    },
};

pub fn parse_profile_name(name: []const u8) ?Profile {
    assert(name.len > 0);
    if (name.len == 0) return null;
    if (std.mem.eql(u8, name, "strict_core")) return .strict_core;
    if (std.mem.eql(u8, name, "tigerbeetle_repo")) return .tigerbeetle_repo;
    return null;
}

pub fn profile_name(profile: Profile) []const u8 {
    return switch (profile) {
        .strict_core => "strict_core",
        .tigerbeetle_repo => "tigerbeetle_repo",
    };
}

pub fn for_profile(profile: Profile) Policy {
    return switch (profile) {
        .strict_core => .{
            .profile_name = "strict_core",
            .hard_rules = &hard_rules_v1,
            .class_policies = &empty_class_policies,
            .default_action = .enforce,
            .default_thresholds = .{ .max_function_lines = 70, .max_line_length = 100 },
        },
        .tigerbeetle_repo => .{
            .profile_name = "tigerbeetle_repo",
            .hard_rules = &hard_rules_v1,
            .class_policies = &tigerbeetle_class_policies,
            .default_action = .enforce,
            .default_thresholds = .{ .max_function_lines = 120, .max_line_length = 100 },
        },
    };
}

pub fn validate(policy_value: Policy) !void {
    assert(policy_value.profile_name.len > 0);
    var seen = std.StaticBitSet(@typeInfo(CodeClass).@"enum".fields.len).initEmpty();
    for (policy_value.class_policies) |class_policy| {
        const class_index = @intFromEnum(class_policy.class);
        if (seen.isSet(class_index)) {
            return error.DuplicateClassPolicy;
        }
        seen.set(class_index);
        try validate_class_policy(policy_value, class_policy);
    }
}

fn validate_class_policy(policy_value: Policy, class_policy: ClassPolicy) !void {
    assert(policy_value.profile_name.len > 0);
    assert(class_policy.path_globs.len <= 32);
    if (class_policy.path_globs.len == 0) {
        return error.EmptyPathGlobSet;
    }
    for (class_policy.path_globs) |glob| {
        if (glob.pattern.len == 0) {
            return error.EmptyPathGlob;
        }
    }
    for (class_policy.rule_actions) |rule_action| {
        const hard = is_effectively_hard_rule(
            policy_value,
            class_policy.class,
            rule_action.rule,
        );
        if (hard and rule_action.action != .enforce) {
            return error.HardRuleDowngradeForbidden;
        }
    }
}

pub fn classify_path(policy_value: Policy, file_path: []const u8) CodeClass {
    assert(file_path.len > 0);
    if (file_path.len == 0) return .runtime;
    for (policy_value.class_policies) |class_policy| {
        if (path_matches_any_glob(file_path, class_policy.path_globs)) {
            return class_policy.class;
        }
    }
    return .runtime;
}

pub fn action_for(policy_value: Policy, class: CodeClass, rule: rules.Id) Action {
    assert(policy_value.profile_name.len > 0);
    if (is_effectively_hard_rule(policy_value, class, rule)) {
        return .enforce;
    }

    const class_policy = class_policy_for(policy_value, class) orelse {
        return policy_value.default_action;
    };
    for (class_policy.rule_actions) |rule_action| {
        if (rule_action.rule == rule) {
            return rule_action.action;
        }
    }
    return policy_value.default_action;
}

pub fn thresholds_for(policy_value: Policy, class: CodeClass) Thresholds {
    var out = policy_value.default_thresholds;
    const class_policy = class_policy_for(policy_value, class) orelse return out;

    if (class_policy.thresholds.max_function_lines) |max_lines| {
        out.max_function_lines = max_lines;
    }
    if (class_policy.thresholds.max_line_length) |max_line_len| {
        out.max_line_length = max_line_len;
    }
    return out;
}

pub fn is_effectively_hard_rule(policy_value: Policy, class: CodeClass, rule: rules.Id) bool {
    if (!contains_rule(policy_value.hard_rules, rule)) {
        return false;
    }
    if (rule == .N02_BOUNDED_LOOPS) {
        return class == .runtime;
    }
    return true;
}

fn class_policy_for(policy_value: Policy, class: CodeClass) ?ClassPolicy {
    for (policy_value.class_policies) |class_policy| {
        if (class_policy.class == class) {
            return class_policy;
        }
    }
    return null;
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

fn path_matches_any_glob(file_path: []const u8, globs: []const PathGlob) bool {
    assert(file_path.len > 0);
    if (file_path.len == 0) return false;
    for (globs) |glob| {
        if (path_glob_matches(file_path, glob.pattern)) {
            return true;
        }
    }
    return false;
}

fn path_glob_matches(file_path: []const u8, glob: []const u8) bool {
    assert(file_path.len > 0);
    assert(glob.len > 0);
    if (file_path.len == 0) return false;
    if (glob.len == 0) return false;

    if (std.mem.eql(u8, glob, "**")) {
        return true;
    }

    if (std.mem.startsWith(u8, glob, "**/") and std.mem.endsWith(u8, glob, "/**")) {
        if (glob.len <= 6) return false;
        const segment = glob[3 .. glob.len - 3];
        return contains_path_segment(file_path, segment);
    }

    if (std.mem.startsWith(u8, glob, "**/*")) {
        const suffix = glob[4..];
        return suffix.len > 0 and std.mem.endsWith(u8, file_path, suffix);
    }

    if (std.mem.startsWith(u8, glob, "**/")) {
        const suffix = glob[3..];
        return suffix.len > 0 and std.mem.endsWith(u8, file_path, suffix);
    }

    if (std.mem.endsWith(u8, glob, "/**")) {
        const prefix = glob[0 .. glob.len - 3];
        return prefix.len > 0 and std.mem.startsWith(u8, file_path, prefix);
    }

    return std.mem.eql(u8, file_path, glob);
}

fn contains_path_segment(file_path: []const u8, segment: []const u8) bool {
    assert(file_path.len > 0);
    assert(segment.len > 0);
    if (file_path.len == 0) return false;
    if (segment.len == 0) return false;

    var search_start: usize = 0;
    while (search_start < file_path.len) {
        const rel = std.mem.indexOfPos(u8, file_path, search_start, segment) orelse return false;
        const end = rel + segment.len;
        const left_ok = rel == 0 or file_path[rel - 1] == '/';
        const right_ok = end == file_path.len or file_path[end] == '/';
        if (left_ok and right_ok) {
            return true;
        }
        search_start = rel + 1;
    }
    return false;
}

test "profile parsing" {
    try std.testing.expect(parse_profile_name("strict_core") == .strict_core);
    try std.testing.expect(parse_profile_name("tigerbeetle_repo") == .tigerbeetle_repo);
    try std.testing.expect(parse_profile_name("unknown") == null);
}

test "runtime keeps hard rules enforced" {
    const p = for_profile(.tigerbeetle_repo);
    try std.testing.expect(action_for(p, .runtime, .N03_STATIC_MEMORY) == .enforce);
    try std.testing.expect(action_for(p, .runtime, .N02_BOUNDED_LOOPS) == .enforce);
}

test "non runtime can downgrade bounded loops" {
    const p = for_profile(.tigerbeetle_repo);
    try std.testing.expect(action_for(p, .test_or_fuzz, .N02_BOUNDED_LOOPS) == .warn);
}

test "soft rule class override works" {
    const p = for_profile(.tigerbeetle_repo);
    try std.testing.expect(action_for(p, .bindings, .TS17_SNAKE_CASE) == .off);
    try std.testing.expect(action_for(p, .runtime, .TS17_SNAKE_CASE) == .enforce);
}

test "classify path by first matching glob class" {
    const p = for_profile(.tigerbeetle_repo);
    try std.testing.expect(classify_path(p, "tigerbeetle/src/testing/foo.zig") == .test_or_fuzz);
    try std.testing.expect(classify_path(p, "tigerbeetle/src/scripts/foo.zig") == .tooling);
    try std.testing.expect(classify_path(p, "tigerbeetle/src/clients/go/foo.zig") == .bindings);
    try std.testing.expect(classify_path(p, "tigerbeetle/src/vsr/replica.zig") == .runtime);
}

test "threshold merge by class" {
    const p = for_profile(.tigerbeetle_repo);
    const runtime_t = thresholds_for(p, .runtime);
    try std.testing.expect(runtime_t.max_function_lines.? == 120);
    try std.testing.expect(runtime_t.max_line_length.? == 100);

    const bindings_t = thresholds_for(p, .bindings);
    try std.testing.expect(bindings_t.max_function_lines.? == 220);
    try std.testing.expect(bindings_t.max_line_length.? == 140);
}

test "policy validates hard-rule downgrade rejection" {
    const bad_actions = [_]RuleAction{.{ .rule = .N03_STATIC_MEMORY, .action = .warn }};
    const bad_globs = [_]PathGlob{.{ .pattern = "**/scripts/**" }};
    const bad_classes = [_]ClassPolicy{.{
        .class = .tooling,
        .path_globs = &bad_globs,
        .rule_actions = &bad_actions,
        .thresholds = .{},
    }};
    const bad = Policy{
        .profile_name = "bad",
        .hard_rules = &hard_rules_v1,
        .class_policies = &bad_classes,
        .default_action = .enforce,
        .default_thresholds = .{ .max_function_lines = 70, .max_line_length = 100 },
    };
    try std.testing.expectError(error.HardRuleDowngradeForbidden, validate(bad));
}

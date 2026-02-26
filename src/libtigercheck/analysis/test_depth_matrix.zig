const std = @import("std");

const ModuleTarget = struct {
    module: []const u8,
    min_unit_tests: u8,
};

pub const analyzer_core_targets = [_]ModuleTarget{
    .{ .module = "ast_walk", .min_unit_tests = 3 },
    .{ .module = "analysis/call_expr", .min_unit_tests = 2 },
    .{ .module = "analysis/roles", .min_unit_tests = 2 },
    .{ .module = "analysis/event_pacing", .min_unit_tests = 1 },
    .{ .module = "analysis/control_data_boundary", .min_unit_tests = 1 },
    .{ .module = "analysis/queue_growth_bounds", .min_unit_tests = 1 },
};

test "analyzer core module targets are tracked" {
    inline for (analyzer_core_targets) |target| {
        try std.testing.expect(target.module.len > 0);
        try std.testing.expect(target.min_unit_tests > 0);
    }
}

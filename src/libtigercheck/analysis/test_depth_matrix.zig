const std = @import("std");
const assert = std.debug.assert;

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

test "analyzer core module targets meet minimum unit test counts" {
    const allocator = std.testing.allocator;
    for (analyzer_core_targets) |target| {
        const source_path = try module_source_path(allocator, target.module);
        defer allocator.free(source_path);

        const source = try std.fs.cwd().readFileAllocOptions(
            std.Options.debug_io,
            source_path,
            allocator,
            std.Io.Limit.limited(2 * 1024 * 1024),
            .of(u8),
            0,
        );
        defer allocator.free(source);

        var tree = try std.zig.Ast.parse(allocator, source, .zig);
        defer tree.deinit(allocator);

        const test_count = count_unit_tests(&tree);
        try std.testing.expect(test_count >= target.min_unit_tests);
    }
}

fn module_source_path(allocator: std.mem.Allocator, module: []const u8) ![]const u8 {
    assert(module.len > 0);
    if (module.len == 0) return error.InvalidArguments;
    return std.fmt.allocPrint(allocator, "src/libtigercheck/{s}.zig", .{module});
}

fn count_unit_tests(tree: *const std.zig.Ast) u8 {
    assert(tree.tokens.items(.tag).len == tree.tokens.len);
    if (tree.tokens.items(.tag).len != tree.tokens.len) return 0;
    const count = std.mem.count(
        std.zig.Token.Tag,
        tree.tokens.items(.tag),
        &.{.keyword_test},
    );
    if (count == 0) return 0;
    if (count > std.math.maxInt(u8)) {
        return std.math.maxInt(u8);
    }
    return @intCast(count);
}

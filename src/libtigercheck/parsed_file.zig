const std = @import("std");
const assert = std.debug.assert;

pub const Parsed = struct {
    allocator: std.mem.Allocator,
    source: [:0]u8,
    tree: std.zig.Ast,

    pub fn deinit(self: *Parsed) void {
        self.tree.deinit(self.allocator);
        self.allocator.free(self.source);
    }
};

pub fn parse(allocator: std.mem.Allocator, file_path: []const u8) !Parsed {
    assert(file_path.len > 0);
    if (file_path.len == 0) return error.InvalidInputPath;

    const source = try std.Io.Dir.cwd().readFileAllocOptions(
        std.Options.debug_io,
        file_path,
        allocator,
        std.Io.Limit.limited(16 * 1024 * 1024),
        .of(u8),
        0,
    );
    errdefer allocator.free(source);

    const tree = try std.zig.Ast.parse(allocator, source, .zig);

    return .{
        .allocator = allocator,
        .source = source,
        .tree = tree,
    };
}

const std = @import("std");
const graph = @import("../graph.zig");
const parsed_file = @import("../parsed_file.zig");

const assert = std.debug.assert;

pub const ParsedFile = struct {
    source: [:0]u8,
    tree: std.zig.Ast,
};

pub const Cache = struct {
    allocator: std.mem.Allocator,
    by_file: std.StringHashMap(ParsedFile),

    pub fn init(allocator: std.mem.Allocator) Cache {
        return .{
            .allocator = allocator,
            .by_file = std.StringHashMap(ParsedFile).init(allocator),
        };
    }

    pub fn deinit(self: *Cache) void {
        var it = self.by_file.iterator();
        while (it.next()) |entry| {
            var tree = entry.value_ptr.tree;
            tree.deinit(self.allocator);
            self.allocator.free(entry.value_ptr.source);
        }
        self.by_file.deinit();
    }

    pub fn build_for_call_graph(self: *Cache, call_graph: *const graph.CallGraph) !void {
        for (call_graph.files.items) |file_path| {
            if (self.by_file.contains(file_path)) continue;
            var parsed = try parsed_file.parse(self.allocator, file_path);
            errdefer parsed.deinit();

            try self.by_file.put(file_path, .{ .source = parsed.source, .tree = parsed.tree });
        }
    }

    pub fn get(self: *const Cache, file_path: []const u8) ?*const ParsedFile {
        assert(file_path.len > 0);
        if (file_path.len == 0) return null;
        return self.by_file.getPtr(file_path);
    }
};

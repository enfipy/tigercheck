const std = @import("std");

fn process_tick(allocator: std.mem.Allocator) void {
    _ = allocator.alloc(u8, 8) catch {};
}

pub fn main() void {
    var buffer: [128]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buffer);
    const allocator = fba.allocator();

    while (true) {
        process_tick(allocator);
        break;
    }
}

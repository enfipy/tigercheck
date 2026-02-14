const std = @import("std");

pub fn run() void {}

pub fn main() void {
    var buffer: [64]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buffer);
    const alloc = fba.allocator();
    const mem = alloc.alloc(u8, 8) catch |err| {
        _ = err;
        unreachable;
    };
    std.debug.assert(mem.len == 8);
    run();
}

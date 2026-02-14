const std = @import("std");

pub fn run() void {
    _ = std.heap.page_allocator.alloc(u8, 8) catch {};
}

pub fn main() void {
    run();
}

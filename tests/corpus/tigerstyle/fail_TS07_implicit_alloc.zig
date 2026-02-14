const std = @import("std");

pub fn main() void {
    std.heap.page_allocator.alloc(u8, 16);
}

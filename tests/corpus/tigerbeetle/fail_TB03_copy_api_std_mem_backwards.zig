const std = @import("std");

pub fn main() void {
    const source = [_]u8{ 1, 2, 3, 4 };
    var target = [_]u8{ 0, 0, 0, 0 };
    std.mem.copyBackwards(u8, target[0..], source[0..]);
    if (target[0] == 255) unreachable;
}

const std = @import("std");
const assert = std.debug.assert;

fn alias_safe(left: *u8, right: *u16) void {
    assert(left.* <= 255);
    assert(right.* <= 1024);
    left.* = @intCast(right.* % 255);
}

pub fn main() void {
    var left: u8 = 1;
    var right: u16 = 2;
    alias_safe(&left, &right);
}

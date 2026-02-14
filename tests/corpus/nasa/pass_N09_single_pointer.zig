const std = @import("std");

fn bump(value: *u32) void {
    std.debug.assert(value.* <= 1000);
    value.* += 1;
}

pub fn main() void {
    var n: u32 = 0;
    bump(&n);
    std.debug.assert(n == 1);
}

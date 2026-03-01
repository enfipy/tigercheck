const std = @import("std");

fn bump(value: usize) usize {
    return value + 1;
}

pub fn main() void {
    var value: usize = 0;
    value = bump(value);
    std.debug.assert(value > 0);
}

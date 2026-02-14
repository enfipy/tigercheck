const std = @import("std");

pub fn main() void {
    var x: i32 = 0;
    x += 1;
    x += 2;
    x += 3;
    x += 4;
    x += 5;
    x += 6;
    x += 7;
    x += 8;
    x += 9;
    x += 10;
    x += 11;
    std.debug.assert(x > 0);
    std.debug.assert(x < 100);
}

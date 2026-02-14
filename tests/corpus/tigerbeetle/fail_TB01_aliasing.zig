const std = @import("std");
const assert = std.debug.assert;

fn alias_overlap(left: *u8, right: *u8) void {
    assert(left != right);
    left.* = right.*;
}

pub fn main() void {
    var left: u8 = 1;
    var right: u8 = 2;
    alias_overlap(&left, &right);
}

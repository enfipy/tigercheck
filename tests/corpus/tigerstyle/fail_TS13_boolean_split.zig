const std = @import("std");

pub fn main() void {
    const idx: usize = 1;
    const len: usize = 4;
    const valid = true;
    std.debug.assert(idx < len and valid);
}

const std = @import("std");

pub fn main() void {
    var i: usize = 0;
    const dynamic_input: usize = @intCast(std.time.timestamp() & 255);

    while (i < dynamic_input) : (i += 1) {}
}

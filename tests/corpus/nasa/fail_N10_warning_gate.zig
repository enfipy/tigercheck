const std = @import("std");

pub fn main() void {
    comptime var i: usize = 0;
    inline while (i < 1) : (i += 1) {
        inline for ([_]u8{1}) |_| {
            comptime var j: usize = 0;
            inline while (j < 1) : (j += 1) {
                inline for ([_]u8{1}) |_| {
                    std.debug.assert(j < 2);
                }
            }
        }
    }
}

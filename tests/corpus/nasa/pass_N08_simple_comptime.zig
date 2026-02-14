const Algo = struct {
    fn identity(comptime T: type, value: T) T {
        return value;
    }
};

pub fn main() void {
    const v = Algo.identity(u32, 42);
    std.debug.assert(v == 42);
}

const std = @import("std");

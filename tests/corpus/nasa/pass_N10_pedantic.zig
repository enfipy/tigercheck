const Flow = struct {
    fn run_once(limit: usize) usize {
        std.debug.assert(limit > 0);
        var i: usize = 0;
        while (i < limit) : (i += 1) {}
        return i;
    }
};

pub fn main() void {
    const got = Flow.run_once(8);
    std.debug.assert(got == 8);
}

const std = @import("std");

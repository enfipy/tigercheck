const std = @import("std");

const Worker = struct {
    fn maybe_value(ok: bool) error{Failed}!u8 {
        if (!ok) return error.Failed;
        return 7;
    }
};

fn call() error{Boom}!void {
    return error.Boom;
}

fn log(err: anyerror) void {
    _ = err;
}

pub fn main() void {
    if (Worker.maybe_value(true)) |v| {
        std.debug.assert(v == 7);
    } else |_| {
        unreachable;
    }

    call() catch |err| {
        log(err);
        std.debug.assert(true);
    };
}

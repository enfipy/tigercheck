fn call() error{Boom}!void {
    return error.Boom;
}

fn consume_error(err: anyerror) void {
    _ = err;
}

pub fn main() void {
    call() catch |err| {
        consume_error(err);
    };
}

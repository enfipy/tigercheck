fn call() error{Boom}!void {
    return error.Boom;
}

pub fn main() void {
    _ = call() catch {};
}

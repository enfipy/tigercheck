// expect-rule: TS15_ERROR_HANDLING
fn call() error{Boom}!void {
    return error.Boom;
}

pub fn main() void {
    _ = call() catch {};
}

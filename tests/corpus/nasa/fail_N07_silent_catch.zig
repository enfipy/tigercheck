// expect-rule: N07_RETURN_AND_PARAM_CHECKS
fn call() error{Boom}!void {
    return error.Boom;
}

pub fn main() void {
    _ = call() catch {};
}

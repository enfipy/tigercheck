// expect-rule: N08_PREPROCESSOR_OR_COMPTIME_BUDGET
fn worker() void {}

pub fn main() void {
    @call(.auto, worker, .{});
}

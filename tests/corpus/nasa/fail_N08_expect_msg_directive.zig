// expect-rule: N08_PREPROCESSOR_OR_COMPTIME_BUDGET
// expect-msg: hidden control flow via `@call`

fn worker() void {}

pub fn main() void {
    @call(.auto, worker, .{});
}

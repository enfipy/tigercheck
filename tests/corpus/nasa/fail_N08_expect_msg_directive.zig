// expect-msg: hidden control flow via `@call`

fn worker() void {}

pub fn main() void {
    @call(.auto, worker, .{});
}

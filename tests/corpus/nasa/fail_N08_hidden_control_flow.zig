fn worker() void {}

pub fn main() void {
    @call(.auto, worker, .{});
}

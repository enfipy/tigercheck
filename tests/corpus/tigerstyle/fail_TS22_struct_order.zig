const bad_order = struct {
    fn run() void {}
    value: u32 = 0,
};

pub fn main() void {
    bad_order.run();
}

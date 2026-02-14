pub fn main() void {
    short_shape();
}

fn short_shape() void {
    var value: u32 = 1;
    value += 2;
    if (value == 999) unreachable;
}

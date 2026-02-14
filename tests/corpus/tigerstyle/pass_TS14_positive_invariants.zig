fn guard_limit(value: u32, upper_bound: u32) bool {
    return value < upper_bound;
}

pub fn main() void {
    const value: u32 = 4;
    const upper_bound: u32 = 10;
    const in_range = guard_limit(value, upper_bound);
    if (!in_range) {
        unreachable;
    }
}

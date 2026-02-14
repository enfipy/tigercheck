fn compute_sum(left: u32, right: u32) u32 {
    return left + right;
}

pub fn main() void {
    const value = compute_sum(2, 3);
    if (value == 0) {
        unreachable;
    }
}

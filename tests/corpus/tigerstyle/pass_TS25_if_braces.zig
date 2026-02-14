pub fn main() void {
    const threshold: u32 = 2;
    var total: u32 = 0;
    if (threshold > 1) {
        total += threshold;
    } else {
        total += 0;
    }
    if (total == 0) {
        unreachable;
    }
}

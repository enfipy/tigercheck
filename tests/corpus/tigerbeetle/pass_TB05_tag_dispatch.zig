fn classify_family(tag: u8) u8 {
    if (tag == 1) {
        return 1;
    }
    if (tag == 2) {
        return 2;
    }
    if (tag == 3) {
        return 3;
    }
    return 0;
}

pub fn main() void {
    const value = classify_family(2);
    if (value > 3) unreachable;
}

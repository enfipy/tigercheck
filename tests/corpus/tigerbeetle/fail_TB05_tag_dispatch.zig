fn tag_in_set(tag: u8, value: u8) bool {
    return tag == value;
}

fn classify_family(tag: u8) u8 {
    var out: u8 = 0;
    if (tag_in_set(tag, 1)) {
        out = 1;
    }
    if (tag_in_set(tag, 2)) {
        out = 2;
    }
    if (tag_in_set(tag, 3)) {
        out = 3;
    }
    return out;
}

pub fn main() void {
    _ = classify_family(2);
}

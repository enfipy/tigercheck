fn assert(cond: bool) void {
    if (!cond) unreachable;
}

fn validate_input(input: ?[]const u8) void {
    assert(input != null);
    if (input == null) return;

    if (input != null) {
        assert(input != null);
    } else {
        assert(input == null);
    }
}

pub fn main() void {
    validate_input("ok");
}

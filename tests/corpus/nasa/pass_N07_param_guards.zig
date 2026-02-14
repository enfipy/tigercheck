fn assert(cond: bool) void {
    if (!cond) unreachable;
}

fn parse_payload(payload: ?[]const u8) void {
    assert(payload != null);
    const bytes = payload orelse return;
    _ = bytes.len;
}

pub fn main() void {
    parse_payload("ok");
}

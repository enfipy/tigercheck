// expect-rule: N07_RETURN_AND_PARAM_CHECKS
fn parse_payload(payload: ?[]const u8) void {
    _ = payload;
}

pub fn main() void {
    parse_payload(null);
}

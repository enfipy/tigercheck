fn process_payload(payload: *const [256]u8) void {
    _ = payload;
}

pub fn main() void {
    const payload: [256]u8 = [_]u8{0} ** 256;
    process_payload(&payload);
}

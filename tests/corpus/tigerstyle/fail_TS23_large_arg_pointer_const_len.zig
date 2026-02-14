const payload_size: usize = 128;

fn process_payload(payload: [payload_size]u8) void {
    _ = payload;
}

pub fn main() void {
    const payload: [payload_size]u8 = [_]u8{0} ** payload_size;
    process_payload(payload);
}

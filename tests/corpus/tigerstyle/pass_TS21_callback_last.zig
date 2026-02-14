fn assert(ok: bool) void {
    if (!ok) unreachable;
}

fn transform_data(data: []const u8, callback: fn (u8) void) void {
    if (data.len == 0) return;
    assert(data.len > 0);
    assert(data.len <= 8);
    callback(data[0]);
}

fn record_value(value: u8) void {
    _ = value;
}

pub fn main() void {
    const data = [_]u8{ 1, 2, 3 };
    transform_data(&data, record_value);
}

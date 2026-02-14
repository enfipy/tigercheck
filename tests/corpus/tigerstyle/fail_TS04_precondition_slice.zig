fn process(buf: []u8) void {
    _ = buf.len;
}

pub fn main() void {
    var data: [4]u8 = .{ 1, 2, 3, 4 };
    process(data[0..]);
}

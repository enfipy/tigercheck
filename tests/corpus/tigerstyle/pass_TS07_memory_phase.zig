const Buffer = [16]u8;

fn process_buffer(buffer: *Buffer) void {
    _ = buffer;
}

pub fn main() void {
    var buffer = [_]u8{0} ** 16;
    process_buffer(&buffer);
}

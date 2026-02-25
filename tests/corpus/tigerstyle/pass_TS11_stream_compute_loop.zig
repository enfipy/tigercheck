const Stream = struct {
    fn next(self: *Stream) ?u32 {
        _ = self;
        return 1;
    }
};

const Buffer = struct {
    len: u32 = 0,

    fn append(self: *Buffer, value: u32) void {
        _ = value;
        self.len += 1;
    }
};

pub fn main() void {
    var stream = Stream{};
    var buffer = Buffer{};
    var i: u32 = 0;
    while (i < 4) : (i += 1) {
        if (stream.next()) |value| {
            buffer.append(value);
        }
    }
}

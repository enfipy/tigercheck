const Queue = struct {
    len: usize = 0,

    fn append(self: *Queue, value: u32) void {
        _ = value;
        self.len += 1;
    }
};

pub fn main() void {
    var queue = Queue{};
    var i: u32 = 0;
    while (i < 8) : (i += 1) {
        queue.append(i);
    }
}

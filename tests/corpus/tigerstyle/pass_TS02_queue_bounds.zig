const Queue = struct {
    len: usize = 0,

    fn append(self: *Queue, value: u32) void {
        _ = value;
        self.len += 1;
    }
};

pub fn main() void {
    var queue = Queue{};
    const max_queue: usize = 8;
    var i: u32 = 0;
    while (i < 8) : (i += 1) {
        if (queue.len < max_queue) {
            queue.append(i);
        }
    }
}

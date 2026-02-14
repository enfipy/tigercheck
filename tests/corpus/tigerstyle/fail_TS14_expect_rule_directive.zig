// expect-rule: TS11_PACED_CONTROL
// expect-msg: explicit batch boundary before state updates

const EventSource = struct {
    fn recv(self: *EventSource) ?u32 {
        _ = self;
        return 1;
    }
};

const Queue = struct {
    len: usize = 0,

    fn append(self: *Queue, value: u32) void {
        _ = value;
        self.len += 1;
    }
};

pub fn main() void {
    var source = EventSource{};
    var queue = Queue{};
    const max_queue: usize = 4;
    var i: u32 = 0;
    while (i < 4) : (i += 1) {
        if (source.recv()) |value| {
            if (queue.len >= max_queue) continue;
            queue.append(value);
        }
    }
}

const EventSource = struct {
    fn recv(self: *EventSource) ?u32 {
        _ = self;
        return 1;
    }
};

fn assert(cond: bool) void {
    if (!cond) unreachable;
}

const Queue = struct {
    len: usize = 0,

    fn append(self: *Queue, value: u32) void {
        _ = value;
        self.len += 1;
    }

    fn commit(self: *Queue) void {
        _ = self;
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
        queue.commit();
    }
    assert(queue.len <= max_queue);
}

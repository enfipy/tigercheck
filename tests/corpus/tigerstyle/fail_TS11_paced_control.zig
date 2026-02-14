const EventSource = struct {
    fn recv(self: *EventSource) ?u32 {
        _ = self;
        return 1;
    }
};

const Queue = struct {
    fn append(self: *Queue, value: u32) void {
        _ = self;
        _ = value;
    }
};

pub fn main() void {
    var source = EventSource{};
    var queue = Queue{};
    var i: u32 = 0;
    while (i < 4) : (i += 1) {
        if (source.recv()) |value| {
            queue.append(value);
        }
    }
}

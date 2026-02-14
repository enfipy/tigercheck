const EventSource = struct {};

const QueueStore = struct {
    len: usize = 0,
};

fn pull(src: *EventSource) ?u32 {
    _ = src;
    return 1;
}

fn observe(dst: *const QueueStore, value: u32) void {
    _ = dst;
    _ = value;
}

pub fn main() void {
    var source = EventSource{};
    const store = QueueStore{};
    var i: u32 = 0;
    while (i < 4) : (i += 1) {
        if (pull(&source)) |value| {
            observe(&store, value);
        }
    }
}

const EventSource = struct {};

const QueueStore = struct {
    len: usize = 0,
};

fn pull(src: *EventSource) ?u32 {
    _ = src;
    return 1;
}

fn mutate(dst: *QueueStore, value: u32) void {
    _ = value;
    dst.len += 1;
}

pub fn main() void {
    var source = EventSource{};
    var store = QueueStore{};
    var i: u32 = 0;
    while (i < 4) : (i += 1) {
        if (pull(&source)) |value| {
            mutate(&store, value);
        }
    }
}

const Counter = struct {
    value: u32,

    fn increment(self: *Counter) void {
        self.value += 1;
    }
};

pub fn main() void {
    var counter = Counter{ .value = 0 };
    counter.increment();
}

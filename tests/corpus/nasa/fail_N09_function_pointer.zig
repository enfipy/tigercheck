fn install(handler: *const fn (value: u32) void) void {
    _ = handler;
}

fn on_event(value: u32) void {
    _ = value;
}

pub fn main() void {
    install(on_event);
}

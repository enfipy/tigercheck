const std = @import("std");

// TS21: Callback parameter should be last
fn process_with_callback(callback: fn (u32) void, data: []u8) void {
    _ = callback;
    _ = data;
}

fn main() void {
    process_with_callback(my_callback, &[_]u8{ 1, 2, 3 });
}

fn my_callback(x: u32) void {
    _ = x;
}

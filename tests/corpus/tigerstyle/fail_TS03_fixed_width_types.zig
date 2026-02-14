const std = @import("std");

// TS03: Using usize in function signature
fn process_buffer(data: []u8, len: usize) usize {
    _ = data;
    return len;
}

// TS03: Using isize in return type
fn get_offset() isize {
    return 0;
}

// TS03: Using ?usize in parameter
fn maybe_process(data: []u8, len: ?usize) void {
    _ = data;
    _ = len;
}

fn main() void {}

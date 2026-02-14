const std = @import("std");

pub fn main() void {
    std.process.run(.{
        .max_output_bytes = 4096,
    });
}

const std = @import("std");

fn main() void {
    const x = 5;
    // TS25: if without braces (multi-line)
    if (x > 0)
        std.debug.print("positive\n", .{});

    // TS25: else without braces
    if (x > 0) {
        std.debug.print("positive\n", .{});
    } else std.debug.print("non-positive\n", .{});
}

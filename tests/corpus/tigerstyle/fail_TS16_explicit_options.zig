// expect-rule: TS16_EXPLICIT_OPTIONS
const std = @import("std");

pub fn main() void {
    std.process.run(.{});
}

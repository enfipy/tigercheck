const std = @import("std");

fn main() void {
    const x: u32 = 5;
    const y: u32 = 10;

    // TS14: Negative invariant - !(x < y) should be x >= y
    assert(!(x < y));

    // TS14: Using != instead of positive form
    assert(x != y);
}

fn assert(cond: bool) void {
    if (!cond) unreachable;
}

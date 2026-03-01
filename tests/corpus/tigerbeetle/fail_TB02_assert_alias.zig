// expect-rule: TB02_ASSERT_ALIAS
const std = @import("std");

pub fn main() void {
    std.debug.assert(true);
}

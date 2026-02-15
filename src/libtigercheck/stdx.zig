const std = @import("std");
const assert = std.debug.assert;

pub fn copy_disjoint(comptime T: type, target: []T, source: []const T) void {
    assert(target.len >= source.len);
    if (source.len == 0 or @sizeOf(T) == 0) return;

    const target_start = @intFromPtr(target.ptr);
    const source_start = @intFromPtr(source.ptr);
    const bytes = source.len * @sizeOf(T);
    const target_end = target_start + bytes;
    const source_end = source_start + bytes;

    assert(target_end <= source_start or source_end <= target_start);
    std.mem.copyForwards(T, target[0..source.len], source);
}

pub fn copy_left(comptime T: type, target: []T, source: []const T) void {
    assert(target.len >= source.len);
    if (source.len == 0) return;
    if (target.len < source.len) return;
    std.mem.copyForwards(T, target[0..source.len], source);
}

pub fn copy_right(comptime T: type, target: []T, source: []const T) void {
    assert(target.len >= source.len);
    if (source.len == 0) return;
    if (target.len < source.len) return;
    std.mem.copyBackwards(T, target[0..source.len], source);
}

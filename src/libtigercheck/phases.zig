const std = @import("std");

pub const Phase = enum {
    green,
    red,
    amber,
};

pub const PhaseMap = std.StringHashMap(Phase);

pub const PhaseResult = struct {
    phases: PhaseMap,

    pub fn init(allocator: std.mem.Allocator) PhaseResult {
        return .{ .phases = PhaseMap.init(allocator) };
    }

    pub fn deinit(self: *PhaseResult) void {
        self.phases.deinit();
    }
};

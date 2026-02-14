const std = @import("std");
const rules = @import("../rules.zig");

pub const WarningFamilies = struct {
    saw_nasa: bool = false,
    saw_tigerstyle: bool = false,
};

pub fn note_warning_rule(rule: rules.Id, families: *WarningFamilies) void {
    switch (rules.family(rule)) {
        .nasa => families.saw_nasa = true,
        .tigerstyle => families.saw_tigerstyle = true,
        .tigerbeetle => families.saw_nasa = true,
    }
}

pub fn gate_rule_for_families(saw_nasa: bool, saw_tigerstyle: bool) rules.Id {
    if (saw_tigerstyle and !saw_nasa) {
        return .TS10_PEDANTIC;
    }
    return .N10_PEDANTIC_PIPELINE;
}

pub fn gate_message(
    allocator: std.mem.Allocator,
    gate_rule: rules.Id,
    warning_count: u32,
) ![]const u8 {
    if (gate_rule == .TS10_PEDANTIC) {
        return std.fmt.allocPrint(
            allocator,
            "TS10_PEDANTIC: zero-warning policy violated ({d} warning(s))",
            .{warning_count},
        );
    }
    if (gate_rule == .N10_PEDANTIC_PIPELINE) {
        return std.fmt.allocPrint(
            allocator,
            "N10_PEDANTIC_PIPELINE: {d} warning(s) present; " ++
                "fail the pipeline until warning count is zero",
            .{warning_count},
        );
    }
    unreachable;
}

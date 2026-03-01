const std = @import("std");
const roles = @import("roles.zig");
const diagnostics = @import("diagnostics.zig");

const assert = std.debug.assert;

pub const ErrorDisciplineVisitCtx = struct {
    file_path: []const u8,
    result: *diagnostics.Result,
};

pub const ImplicitVisitCtx = struct {
    tree: *const std.zig.Ast,
    role_index: *roles.SemanticIndex,
    source: []const u8,
    file_path: []const u8,
    enable_tigerbeetle_profile_rules: bool,
    result: *diagnostics.Result,
};

pub fn assert_implicit_walk_ctx(ctx: *const ImplicitVisitCtx) void {
    assert(ctx.file_path.len > 0);
    assert(ctx.source.len > 0);
    const diag_len = ctx.result.diagnostics.items.len;
    const diag_count = ctx.result.warning_count + ctx.result.critical_count;
    assert(diag_len == diag_count);
}

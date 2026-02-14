const std = @import("std");
const assert = std.debug.assert;

pub fn main(init: std.process.Init) !void {
    var args = init.minimal.args.iterate();
    const argv0 = args.next();
    assert(argv0 != null);

    const tiger_check_bin = args.next() orelse fatal("missing tigercheck binary path");
    assert(tiger_check_bin.len > 0);
    const budget_ms_arg = args.next() orelse fatal("missing budget_ms argument");
    const budget_ms = std.fmt.parseInt(u64, budget_ms_arg, 10) catch {
        fatal("invalid budget_ms argument");
    };
    assert(budget_ms > 0);

    const allocator = init.gpa;
    var targets = std.array_list.Managed([]const u8).init(allocator);
    defer targets.deinit();
    while (args.next()) |target| {
        try targets.append(target);
    }
    if (targets.items.len == 0) {
        fatal("missing benchmark target path");
    }

    const io = init.io;
    var stdout_buf: [4096]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writerStreaming(io, &stdout_buf);
    const stdout = &stdout_writer.interface;

    var total_ms: u64 = 0;
    for (targets.items) |target| {
        total_ms += try run_target(allocator, io, stdout, tiger_check_bin, target);
    }

    try stdout.print(
        "perf-bench: total_elapsed_ms={d} budget_ms={d}\n",
        .{ total_ms, budget_ms },
    );
    if (total_ms > budget_ms) {
        try stdout.print(
            "perf-bench: budget exceeded by {d}ms\n",
            .{total_ms - budget_ms},
        );
        try stdout.flush();
        std.process.exit(1);
    }

    try stdout.writeAll("perf-bench: OK\n");
    try stdout.flush();
}

fn run_target(
    allocator: std.mem.Allocator,
    io: std.Io,
    stdout: *std.Io.Writer,
    tiger_check_bin: []const u8,
    target: []const u8,
) !u64 {
    assert(tiger_check_bin.len > 0);
    assert(target.len > 0);
    if (tiger_check_bin.len == 0 or target.len == 0) return error.InvalidInputPath;
    const start_ms = wall_clock_ms();
    const result = std.process.run(allocator, io, .{
        .argv = &.{ tiger_check_bin, target },
    }) catch |err| {
        try stdout.print("perf-bench: failed to run target={s}: {}\n", .{ target, err });
        try stdout.flush();
        std.process.exit(1);
    };
    defer {
        allocator.free(result.stdout);
        allocator.free(result.stderr);
    }

    const elapsed_ms = wall_clock_ms() - start_ms;
    const exited_ok = switch (result.term) {
        .exited => |code| code == 0,
        .signal, .stopped, .unknown => false,
    };

    try stdout.print("perf-bench: target={s} elapsed_ms={d}\n", .{ target, elapsed_ms });
    if (!exited_ok) {
        try stdout.print(
            "perf-bench: target failed; stdout={s} stderr={s}\n",
            .{
                std.mem.trimEnd(u8, result.stdout, "\n"),
                std.mem.trimEnd(u8, result.stderr, "\n"),
            },
        );
        try stdout.flush();
        std.process.exit(1);
    }
    return elapsed_ms;
}

fn wall_clock_ms() u64 {
    var tv: std.c.timeval = undefined;
    const rc = std.c.gettimeofday(&tv, null);
    if (rc != 0) {
        fatal("gettimeofday failed");
    }
    const secs: u64 = @intCast(tv.sec);
    const usecs: u64 = @intCast(tv.usec);
    return secs * 1000 + (usecs / 1000);
}

fn fatal(msg: []const u8) noreturn {
    assert(msg.len > 0);
    if (msg.len == 0) {
        std.debug.print("perf-bench: fatal\n", .{});
        std.process.exit(2);
        unreachable;
    }
    std.debug.print("perf-bench: {s}\n", .{msg});
    std.process.exit(2);
}

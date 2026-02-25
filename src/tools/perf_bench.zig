const std = @import("std");
const assert = std.debug.assert;

const TargetSummary = struct {
    target: []const u8,
    runs: u16,
    total_ms: u64,
    min_ms: u64,
    p50_ms: u64,
    p95_ms: u64,
    max_ms: u64,
};

const JsonSummary = struct {
    schema_version: u32,
    budget_ms: u64,
    total_elapsed_ms: u64,
    runs: u16,
    targets: []const TargetSummary,
};

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

    var runs: u16 = 1;
    var json_output = false;

    const allocator = init.gpa;
    var targets = std.array_list.Managed([]const u8).init(allocator);
    defer targets.deinit();

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--runs")) {
            const runs_arg = args.next() orelse fatal("missing value for --runs");
            const parsed_runs = std.fmt.parseInt(u16, runs_arg, 10) catch {
                fatal("invalid --runs value");
            };
            if (parsed_runs == 0) {
                fatal("--runs must be > 0");
            }
            runs = parsed_runs;
            continue;
        }
        if (std.mem.eql(u8, arg, "--json")) {
            json_output = true;
            continue;
        }
        if (std.mem.startsWith(u8, arg, "--")) {
            fatal("unknown flag");
        }
        try targets.append(arg);
    }

    if (targets.items.len == 0) {
        fatal("missing benchmark target path");
    }

    const io = init.io;
    var stdout_buf: [4096]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writerStreaming(io, &stdout_buf);
    const stdout = &stdout_writer.interface;

    var summaries = std.array_list.Managed(TargetSummary).init(allocator);
    defer summaries.deinit();

    var total_ms: u64 = 0;
    for (targets.items) |target| {
        const summary = try run_target(allocator, io, stdout, tiger_check_bin, target, runs);
        total_ms += summary.total_ms;
        try summaries.append(summary);
        if (!json_output) {
            try stdout.print(
                "perf-bench: target={s} runs={d} total_ms={d} min_ms={d} p50_ms={d} p95_ms={d} max_ms={d}\n",
                .{
                    summary.target,
                    summary.runs,
                    summary.total_ms,
                    summary.min_ms,
                    summary.p50_ms,
                    summary.p95_ms,
                    summary.max_ms,
                },
            );
        }
    }

    if (json_output) {
        var out: std.Io.Writer.Allocating = .init(allocator);
        defer out.deinit();
        const payload = JsonSummary{
            .schema_version = 1,
            .budget_ms = budget_ms,
            .total_elapsed_ms = total_ms,
            .runs = runs,
            .targets = summaries.items,
        };
        try std.json.Stringify.value(payload, .{ .whitespace = .indent_2 }, &out.writer);
        try out.writer.writeAll("\n");
        try stdout.writeAll(out.written());
    } else {
        try stdout.print(
            "perf-bench: total_elapsed_ms={d} budget_ms={d}\n",
            .{ total_ms, budget_ms },
        );
    }

    if (total_ms > budget_ms) {
        try stdout.print(
            "perf-bench: budget exceeded by {d}ms\n",
            .{total_ms - budget_ms},
        );
        try stdout.flush();
        std.process.exit(1);
    }

    if (!json_output) {
        try stdout.writeAll("perf-bench: OK\n");
    }
    try stdout.flush();
}

fn run_target(
    allocator: std.mem.Allocator,
    io: std.Io,
    stdout: *std.Io.Writer,
    tiger_check_bin: []const u8,
    target: []const u8,
    runs: u16,
) !TargetSummary {
    assert(tiger_check_bin.len > 0);
    assert(target.len > 0);
    assert(runs > 0);
    if (tiger_check_bin.len == 0 or target.len == 0) return error.InvalidInputPath;
    if (runs == 0) return error.InvalidArguments;

    var samples = std.array_list.Managed(u64).init(allocator);
    defer samples.deinit();

    var total_ms: u64 = 0;
    for (0..runs) |_| {
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
        total_ms += elapsed_ms;
        try samples.append(elapsed_ms);

        const exited_ok = switch (result.term) {
            .exited => |code| code == 0,
            .signal, .stopped, .unknown => false,
        };
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
    }

    std.mem.sort(u64, samples.items, {}, std.sort.asc(u64));
    const min_ms = samples.items[0];
    const max_ms = samples.items[samples.items.len - 1];
    const p50_ms = percentile(samples.items, 50, 100);
    const p95_ms = percentile(samples.items, 95, 100);

    return .{
        .target = target,
        .runs = runs,
        .total_ms = total_ms,
        .min_ms = min_ms,
        .p50_ms = p50_ms,
        .p95_ms = p95_ms,
        .max_ms = max_ms,
    };
}

fn percentile(samples_sorted: []const u64, numerator: usize, denominator: usize) u64 {
    assert(samples_sorted.len > 0);
    assert(denominator > 0);
    if (samples_sorted.len == 0) return 0;
    if (denominator == 0) return samples_sorted[samples_sorted.len - 1];

    const max_index = samples_sorted.len - 1;
    const index = (max_index * numerator + (denominator / 2)) / denominator;
    return samples_sorted[index];
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

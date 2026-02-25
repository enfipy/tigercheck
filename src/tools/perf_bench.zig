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

const JSONSummary = struct {
    schema_version: u32,
    budget_ms: u64,
    total_elapsed_ms: u64,
    runs: u16,
    targets: []const TargetSummary,
};

const CliOptions = struct {
    tiger_check_bin: []const u8,
    budget_ms: u64,
    runs: u16,
    json_output: bool,
    targets: std.array_list.Managed([]const u8),

    fn deinit(self: *CliOptions) void {
        self.targets.deinit();
    }
};

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    var cli = try parse_cli_options(init, allocator);
    defer cli.deinit();
    assert(cli.budget_ms > 0);
    assert(cli.runs > 0);
    assert(cli.targets.items.len > 0);

    const io = init.io;
    var stdout_buf: [4096]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writerStreaming(io, &stdout_buf);
    const stdout = &stdout_writer.interface;

    var summaries = std.array_list.Managed(TargetSummary).init(allocator);
    defer summaries.deinit();

    const total_ms = try benchmark_targets(
        allocator,
        io,
        stdout,
        &cli,
        &summaries,
    );

    try report_benchmark_result(allocator, stdout, &cli, summaries.items, total_ms);
    try enforce_budget(stdout, cli.budget_ms, total_ms);
    try stdout.flush();
}

fn parse_cli_options(init: std.process.Init, allocator: std.mem.Allocator) !CliOptions {
    var args = init.minimal.args.iterate();
    const argv0 = args.next();
    assert(argv0 != null);
    if (argv0 == null) return error.InvalidArguments;

    const tiger_check_bin = args.next() orelse return error.InvalidArguments;
    const budget_ms_arg = args.next() orelse return error.InvalidArguments;
    const budget_ms = std.fmt.parseInt(u64, budget_ms_arg, 10) catch {
        return error.InvalidArguments;
    };
    assert(tiger_check_bin.len > 0);
    assert(budget_ms > 0);
    if (tiger_check_bin.len == 0 or budget_ms == 0) return error.InvalidArguments;

    var out = CliOptions{
        .tiger_check_bin = tiger_check_bin,
        .budget_ms = budget_ms,
        .runs = 1,
        .json_output = false,
        .targets = std.array_list.Managed([]const u8).init(allocator),
    };
    errdefer out.deinit();

    try parse_optional_args(&args, &out);
    if (out.targets.items.len == 0) return error.InvalidArguments;
    return out;
}

fn parse_optional_args(args: *std.process.Args.Iterator, out: *CliOptions) !void {
    assert(out.runs > 0);
    assert(out.targets.items.len <= out.targets.capacity);
    var parsed_all = false;
    var step_count: u16 = 0;
    while (step_count < 1024) : (step_count += 1) {
        const arg = args.next() orelse {
            parsed_all = true;
            break;
        };
        if (std.mem.eql(u8, arg, "--runs")) {
            out.runs = try parse_runs_value(args.next());
            assert(out.runs > 0);
            continue;
        }
        if (std.mem.eql(u8, arg, "--json")) {
            out.json_output = true;
            continue;
        }
        if (std.mem.startsWith(u8, arg, "--")) {
            return error.InvalidArguments;
        }
        try out.targets.append(arg);
    }
    if (!parsed_all) return error.InvalidArguments;
}

fn parse_runs_value(value_opt: ?[]const u8) !u16 {
    assert(value_opt == null or value_opt.?.len > 0);
    const value = value_opt orelse return error.InvalidArguments;
    assert(value.len > 0);
    if (value.len == 0) return error.InvalidArguments;
    const parsed = std.fmt.parseInt(u16, value, 10) catch return error.InvalidArguments;
    if (parsed == 0) return error.InvalidArguments;
    return parsed;
}

fn benchmark_targets(
    allocator: std.mem.Allocator,
    io: std.Io,
    stdout: *std.Io.Writer,
    cli: *const CliOptions,
    summaries: *std.array_list.Managed(TargetSummary),
) !u64 {
    assert(cli.targets.items.len > 0);
    assert(cli.runs > 0);
    assert(summaries.items.len == 0);

    var total_ms: u64 = 0;
    for (cli.targets.items) |target| {
        const summary = try run_target(
            allocator,
            io,
            stdout,
            cli.tiger_check_bin,
            target,
            cli.runs,
        );
        total_ms += summary.total_ms;
        try summaries.append(summary);
    }
    return total_ms;
}

fn report_benchmark_result(
    allocator: std.mem.Allocator,
    stdout: *std.Io.Writer,
    cli: *const CliOptions,
    summaries: []const TargetSummary,
    total_ms: u64,
) !void {
    assert(cli.budget_ms > 0);
    assert(cli.runs > 0);
    assert(summaries.len > 0);
    if (cli.budget_ms == 0) return error.InvalidArguments;
    if (cli.runs == 0) return error.InvalidArguments;
    if (summaries.len == 0) return error.InvalidArguments;
    if (cli.json_output) {
        try report_json(allocator, stdout, cli.budget_ms, cli.runs, summaries, total_ms);
        return;
    }

    if (!cli.json_output and summaries.len == 0) return error.InvalidArguments;

    for (summaries) |summary| {
        try report_target_text(stdout, summary);
    }
    try stdout.print(
        "perf-bench: total_elapsed_ms={d} budget_ms={d}\n",
        .{ total_ms, cli.budget_ms },
    );
    try stdout.writeAll("perf-bench: OK\n");
}

fn report_json(
    allocator: std.mem.Allocator,
    stdout: *std.Io.Writer,
    budget_ms: u64,
    runs: u16,
    summaries: []const TargetSummary,
    total_ms: u64,
) !void {
    assert(budget_ms > 0);
    assert(runs > 0);
    assert(summaries.len > 0);
    if (budget_ms == 0) return error.InvalidArguments;
    if (runs == 0) return error.InvalidArguments;
    if (summaries.len == 0) return error.InvalidArguments;

    var out: std.Io.Writer.Allocating = .init(allocator);
    defer out.deinit();

    const payload = JSONSummary{
        .schema_version = 1,
        .budget_ms = budget_ms,
        .total_elapsed_ms = total_ms,
        .runs = runs,
        .targets = summaries,
    };
    try std.json.Stringify.value(payload, .{ .whitespace = .indent_2 }, &out.writer);
    try out.writer.writeAll("\n");
    try stdout.writeAll(out.written());
}

fn report_target_text(stdout: *std.Io.Writer, summary: TargetSummary) !void {
    try stdout.print(
        "perf-bench: target={s} runs={d} total_ms={d} " ++
            "min_ms={d} p50_ms={d} p95_ms={d} max_ms={d}\n",
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

fn enforce_budget(stdout: *std.Io.Writer, budget_ms: u64, total_ms: u64) !void {
    assert(budget_ms > 0);
    if (total_ms <= budget_ms) return;

    try stdout.print(
        "perf-bench: budget exceeded by {d}ms\n",
        .{total_ms - budget_ms},
    );
    std.process.exit(1);
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
    const max_runs: u16 = 64;
    assert(runs <= max_runs);
    if (tiger_check_bin.len == 0 or target.len == 0) return error.InvalidInputPath;
    if (runs > max_runs) return error.InvalidArguments;

    var samples = std.array_list.Managed(u64).init(allocator);
    defer samples.deinit();

    var total_ms: u64 = 0;
    for (0..max_runs) |raw_index| {
        const run_index: u16 = @intCast(raw_index + 1);
        if (run_index > runs) {
            break;
        }
        const elapsed_ms = try benchmark_once(allocator, io, stdout, tiger_check_bin, target);
        total_ms += elapsed_ms;
        try samples.append(elapsed_ms);
    }

    std.mem.sort(u64, samples.items, {}, std.sort.asc(u64));
    return .{
        .target = target,
        .runs = runs,
        .total_ms = total_ms,
        .min_ms = samples.items[0],
        .p50_ms = percentile(samples.items, 50, 100),
        .p95_ms = percentile(samples.items, 95, 100),
        .max_ms = samples.items[samples.items.len - 1],
    };
}

fn benchmark_once(
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
    try execute_target_process(allocator, io, stdout, tiger_check_bin, target);
    const elapsed_ms = wall_clock_ms() - start_ms;
    return elapsed_ms;
}

fn execute_target_process(
    allocator: std.mem.Allocator,
    io: std.Io,
    stdout: *std.Io.Writer,
    tiger_check_bin: []const u8,
    target: []const u8,
) !void {
    assert(tiger_check_bin.len > 0);
    assert(target.len > 0);
    if (tiger_check_bin.len == 0 or target.len == 0) return error.InvalidInputPath;

    const result = std.process.run(allocator, io, .{
        .argv = &.{ tiger_check_bin, target },
    }) catch |err| {
        try stdout.print("perf-bench: failed to run target={s}: {}\n", .{ target, err });
        std.process.exit(1);
    };
    defer {
        allocator.free(result.stdout);
        allocator.free(result.stderr);
    }

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
        std.process.exit(1);
    }
}

fn percentile(samples_sorted: []const u64, numerator: u32, denominator: u32) u64 {
    assert(samples_sorted.len > 0);
    assert(denominator > 0);
    if (samples_sorted.len == 0) return 0;

    const max_index: u64 = @intCast(samples_sorted.len - 1);
    const num_u64: u64 = numerator;
    const den_u64: u64 = denominator;
    const index_u64 = (max_index * num_u64 + (den_u64 / 2)) / den_u64;
    const index: usize = @intCast(index_u64);
    return samples_sorted[index];
}

fn wall_clock_ms() u64 {
    var tv: std.c.timeval = undefined;
    const rc = std.c.gettimeofday(&tv, null);
    if (rc != 0) {
        std.debug.panic("internal invariant violated: gettimeofday failed", .{});
    }
    const secs: u64 = @intCast(tv.sec);
    const usecs: u64 = @intCast(tv.usec);
    return secs * 1000 + (usecs / 1000);
}

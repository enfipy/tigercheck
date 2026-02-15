const std = @import("std");
const assert = std.debug.assert;

const CanonicalAlias = struct {
    from: []const u8,
    to: []const u8,
};

const canonical_aliases = [_]CanonicalAlias{
    .{ .from = "TS01", .to = "N01" },
    .{ .from = "TS02", .to = "N02" },
    .{ .from = "TS07", .to = "N03" },
    .{ .from = "TS08", .to = "N06" },
    .{ .from = "TS09", .to = "N04" },
    .{ .from = "TS10", .to = "N10" },
};

pub fn fallback_rule_prefix(primary_prefix: []const u8) ?[]const u8 {
    assert(primary_prefix.len > 0);
    assert(primary_prefix.len <= 8);
    if (primary_prefix.len == 0) {
        return null;
    }
    return alias_for_prefix(primary_prefix);
}

pub fn case_pass_prefix() []const u8 {
    return "pass_";
}

pub fn case_fail_prefix() []const u8 {
    return "fail_";
}

pub fn zig_file_extension() []const u8 {
    return ".zig";
}

pub fn tigerbeetle_corpus_dir() []const u8 {
    return "tests/corpus/tigerbeetle/";
}

pub fn is_pass_case_basename(basename: []const u8) bool {
    assert(basename.len > 0);
    if (basename.len == 0) {
        return false;
    }
    return std.mem.startsWith(u8, basename, case_pass_prefix());
}

pub fn is_fail_case_basename(basename: []const u8) bool {
    assert(basename.len > 0);
    if (basename.len == 0) {
        return false;
    }
    return std.mem.startsWith(u8, basename, case_fail_prefix());
}

pub fn is_zig_case_file(basename: []const u8) bool {
    assert(basename.len > 0);
    if (basename.len == 0) {
        return false;
    }
    return std.mem.endsWith(u8, basename, zig_file_extension());
}

pub fn is_tigerbeetle_corpus_file(file_path: []const u8) bool {
    assert(file_path.len > 0);
    if (file_path.len == 0) {
        return false;
    }
    const corpus_dir = tigerbeetle_corpus_dir();
    if (std.mem.startsWith(u8, file_path, corpus_dir)) {
        return true;
    }
    return std.mem.indexOf(u8, file_path, "/tests/corpus/tigerbeetle/") != null;
}

pub fn canonical_rule_prefix(prefix: []const u8) []const u8 {
    assert(prefix.len > 0);
    if (prefix.len == 0) {
        return prefix;
    }
    return alias_for_prefix(prefix) orelse prefix;
}

fn alias_for_prefix(prefix: []const u8) ?[]const u8 {
    assert(prefix.len > 0);
    if (prefix.len == 0) {
        return null;
    }
    for (canonical_aliases) |alias| {
        assert(alias.from.len > 0);
        assert(alias.to.len > 0);
        if (std.mem.eql(u8, prefix, alias.from)) {
            return alias.to;
        }
    }
    return null;
}

pub fn sort_paths(paths: *std.array_list.Managed([]const u8)) void {
    assert(paths.items.len <= paths.capacity);
    std.mem.sort([]const u8, paths.items, {}, struct {
        fn lt(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.order(u8, a, b) == .lt;
        }
    }.lt);
}

pub fn deinit_owned_paths(
    allocator: std.mem.Allocator,
    paths: *std.array_list.Managed([]const u8),
) void {
    assert(paths.items.len <= paths.capacity);
    for (paths.items) |path| {
        allocator.free(path);
    }
    paths.deinit();
}

pub fn collect_zig_files(
    allocator: std.mem.Allocator,
    root_path: []const u8,
    files: *std.array_list.Managed([]const u8),
) !void {
    assert(root_path.len > 0);
    assert(files.items.len <= files.capacity);
    if (root_path.len == 0) {
        return error.InvalidCorpusPath;
    }

    const io = std.Options.debug_io;
    var dir = std.Io.Dir.cwd().openDir(io, root_path, .{ .iterate = true }) catch |err| {
        std.debug.print("corpus-common: cannot open directory '{s}': {}\n", .{ root_path, err });
        return err;
    };
    defer dir.close(io);

    var iter = dir.iterate();
    while (try iter.next(io)) |entry| {
        const child = try std.fs.path.join(allocator, &.{ root_path, entry.name });
        errdefer allocator.free(child);

        switch (entry.kind) {
            .file => {
                if (std.mem.endsWith(u8, child, ".zig")) {
                    try files.append(child);
                } else {
                    allocator.free(child);
                }
            },
            .directory => {
                try collect_zig_files(allocator, child, files);
                allocator.free(child);
            },
            .block_device,
            .character_device,
            .named_pipe,
            .sym_link,
            .unix_domain_socket,
            .whiteout,
            .door,
            .event_port,
            .unknown,
            => {
                allocator.free(child);
            },
        }
    }
}

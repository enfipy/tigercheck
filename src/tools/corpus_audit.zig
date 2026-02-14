const std = @import("std");
const assert = std.debug.assert;
const libtiger = @import("libtiger");
const corpus_common = @import("corpus_common.zig");

const rule_count: usize = @typeInfo(libtiger.rules.Id).@"enum".fields.len;
const all_rule_ids: [rule_count]libtiger.rules.Id = blk: {
    var out: [rule_count]libtiger.rules.Id = undefined;
    for (@typeInfo(libtiger.rules.Id).@"enum".fields, 0..) |field, i| {
        out[i] = @field(libtiger.rules.Id, field.name);
    }
    break :blk out;
};

const Coverage = struct {
    pass_count: u32 = 0,
    fail_count: u32 = 0,
};

const CaseKind = enum {
    pass,
    fail,
};

const CaseName = struct {
    kind: CaseKind,
    prefix: []const u8,
};

const AuditData = struct {
    file_count: usize,
    tracked_prefixes: usize,
    invalid_names: std.array_list.Managed([]const u8),
    missing_pass_or_fail: std.array_list.Managed([]const u8),

    fn deinit(self: *AuditData, allocator: std.mem.Allocator) void {
        assert(self.file_count >= self.invalid_names.items.len);
        for (self.invalid_names.items) |path| allocator.free(path);
        self.invalid_names.deinit();
        self.missing_pass_or_fail.deinit();
    }
};

const PrefixLists = struct {
    required: std.array_list.Managed([]const u8),
    required_set: std.StringHashMap(void),

    fn deinit(self: *PrefixLists) void {
        self.required.deinit();
        self.required_set.deinit();
    }
};

const ScanResult = struct {
    coverage_by_prefix: std.StringHashMap(Coverage),
    invalid_names: std.array_list.Managed([]const u8),

    fn deinit(self: *ScanResult, allocator: std.mem.Allocator) void {
        for (self.invalid_names.items) |path| allocator.free(path);
        self.invalid_names.deinit();
        self.coverage_by_prefix.deinit();
    }
};

const MissingLists = struct {
    missing_pass_or_fail: std.array_list.Managed([]const u8),

    fn deinit(self: *MissingLists) void {
        self.missing_pass_or_fail.deinit();
    }
};

pub fn main(init: std.process.Init) !void {
    const corpus_dir = parse_cli_args(init) catch {
        print_usage();
        std.process.exit(2);
    };
    assert(corpus_dir.len > 0);

    const allocator = init.gpa;
    var audit = try run_audit(allocator, corpus_dir);
    defer audit.deinit(allocator);
    assert(audit.tracked_prefixes > 0);

    try print_audit(init.io, &audit);
    if (audit_has_failures(&audit)) {
        std.process.exit(1);
    }
}

fn parse_cli_args(init: std.process.Init) ![]const u8 {
    var args = init.minimal.args.iterate();
    const argv0 = args.next();
    assert(argv0 != null);
    if (argv0 == null) {
        return error.InvalidArguments;
    }

    const corpus_dir = args.next() orelse return error.InvalidArguments;
    assert(corpus_dir.len > 0);
    if (corpus_dir.len == 0) {
        return error.InvalidArguments;
    }
    if (args.next() != null) {
        return error.InvalidArguments;
    }
    return corpus_dir;
}

fn print_usage() void {
    std.debug.print("usage: corpus-audit <corpus-dir>\n", .{});
}

fn run_audit(allocator: std.mem.Allocator, corpus_dir: []const u8) !AuditData {
    assert(corpus_dir.len > 0);
    if (corpus_dir.len == 0) {
        return error.InvalidCorpusPath;
    }

    var files = try collect_sorted_zig_files(allocator, corpus_dir);
    defer corpus_common.deinit_owned_paths(allocator, &files);

    var prefixes = try collect_required_prefixes(allocator);
    defer prefixes.deinit();

    var scan = try scan_corpus_files(allocator, &files, &prefixes.required_set);
    errdefer scan.deinit(allocator);
    defer scan.coverage_by_prefix.deinit();

    var canonical_coverage = try build_canonical_coverage(allocator, &scan.coverage_by_prefix);
    defer canonical_coverage.deinit();

    var missing = try collect_missing_lists(
        allocator,
        &prefixes.required,
        &canonical_coverage,
    );
    errdefer missing.deinit();

    return .{
        .file_count = files.items.len,
        .tracked_prefixes = prefixes.required.items.len,
        .invalid_names = scan.invalid_names,
        .missing_pass_or_fail = missing.missing_pass_or_fail,
    };
}

fn collect_sorted_zig_files(
    allocator: std.mem.Allocator,
    corpus_dir: []const u8,
) !std.array_list.Managed([]const u8) {
    assert(corpus_dir.len > 0);
    if (corpus_dir.len == 0) {
        return error.InvalidCorpusPath;
    }

    var files = std.array_list.Managed([]const u8).init(allocator);
    errdefer corpus_common.deinit_owned_paths(allocator, &files);

    try corpus_common.collect_zig_files(allocator, corpus_dir, &files);
    corpus_common.sort_paths(&files);
    return files;
}

fn collect_required_prefixes(allocator: std.mem.Allocator) !PrefixLists {
    var out = PrefixLists{
        .required = std.array_list.Managed([]const u8).init(allocator),
        .required_set = std.StringHashMap(void).init(allocator),
    };
    errdefer out.deinit();

    for (all_rule_ids) |rule_id| {
        const prefix = rule_prefix(rule_id);
        const gop = try out.required_set.getOrPut(prefix);
        if (!gop.found_existing) {
            try out.required.append(prefix);
        }
    }
    return out;
}

fn scan_corpus_files(
    allocator: std.mem.Allocator,
    files: *const std.array_list.Managed([]const u8),
    required_set: *const std.StringHashMap(void),
) !ScanResult {
    assert(files.items.len <= files.capacity);
    var out = ScanResult{
        .coverage_by_prefix = std.StringHashMap(Coverage).init(allocator),
        .invalid_names = std.array_list.Managed([]const u8).init(allocator),
    };
    errdefer out.deinit(allocator);

    for (files.items) |file_path| {
        const basename = std.fs.path.basename(file_path);
        const parsed = parse_case_name(basename) orelse {
            try append_invalid_name(allocator, &out.invalid_names, file_path);
            continue;
        };
        if (!is_required_prefix(required_set, parsed.prefix)) {
            try append_invalid_name(allocator, &out.invalid_names, file_path);
            continue;
        }
        try bump_coverage(&out.coverage_by_prefix, parsed);
    }
    return out;
}

fn append_invalid_name(
    allocator: std.mem.Allocator,
    invalid_names: *std.array_list.Managed([]const u8),
    file_path: []const u8,
) !void {
    assert(file_path.len > 0);
    if (file_path.len == 0) {
        return error.InvalidFilePath;
    }
    const owned = try allocator.dupe(u8, file_path);
    errdefer allocator.free(owned);
    try invalid_names.append(owned);
}

fn bump_coverage(
    coverage_by_prefix: *std.StringHashMap(Coverage),
    parsed: CaseName,
) !void {
    assert(parsed.prefix.len > 0);
    const gop = try coverage_by_prefix.getOrPut(parsed.prefix);
    if (!gop.found_existing) {
        gop.value_ptr.* = .{};
    }
    switch (parsed.kind) {
        .pass => gop.value_ptr.pass_count += 1,
        .fail => gop.value_ptr.fail_count += 1,
    }
}

fn build_canonical_coverage(
    allocator: std.mem.Allocator,
    coverage_by_prefix: *const std.StringHashMap(Coverage),
) !std.StringHashMap(Coverage) {
    assert(coverage_by_prefix.count() <= 4096);
    if (coverage_by_prefix.count() > 4096) {
        return error.InvalidCoverageSet;
    }

    var out = std.StringHashMap(Coverage).init(allocator);
    errdefer out.deinit();

    var it = coverage_by_prefix.iterator();
    while (it.next()) |entry| {
        const canonical = corpus_common.canonical_rule_prefix(entry.key_ptr.*);
        const gop = try out.getOrPut(canonical);
        if (!gop.found_existing) {
            gop.value_ptr.* = .{};
        }
        gop.value_ptr.pass_count += entry.value_ptr.pass_count;
        gop.value_ptr.fail_count += entry.value_ptr.fail_count;
    }
    return out;
}

fn collect_missing_lists(
    allocator: std.mem.Allocator,
    required_prefixes: *const std.array_list.Managed([]const u8),
    canonical_coverage: *const std.StringHashMap(Coverage),
) !MissingLists {
    assert(required_prefixes.items.len <= rule_count);
    assert(canonical_coverage.count() <= 4096);
    if (required_prefixes.items.len == 0) {
        return error.InvalidRuleSet;
    }

    var out = MissingLists{
        .missing_pass_or_fail = std.array_list.Managed([]const u8).init(allocator),
    };
    errdefer out.deinit();

    for (required_prefixes.items) |prefix| {
        assert(prefix.len > 0);
        const coverage =
            canonical_coverage.get(corpus_common.canonical_rule_prefix(prefix)) orelse Coverage{};
        if (coverage.pass_count == 0 or coverage.fail_count == 0) {
            try out.missing_pass_or_fail.append(prefix);
        }
    }
    return out;
}

fn print_audit(io: std.Io, audit: *const AuditData) !void {
    assert(audit.tracked_prefixes > 0);
    assert(audit.file_count >= audit.invalid_names.items.len);

    var stdout_buf: [4096]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writerStreaming(io, &stdout_buf);
    const stdout = &stdout_writer.interface;

    try stdout.print(
        "corpus-audit: files={d} tracked_prefixes={d}\n",
        .{ audit.file_count, audit.tracked_prefixes },
    );

    if (audit.invalid_names.items.len > 0) {
        try stdout.writeAll("corpus-audit: invalid corpus filenames\n");
        for (audit.invalid_names.items) |file_path| {
            try stdout.print("  - {s}\n", .{file_path});
        }
    }

    if (audit.missing_pass_or_fail.items.len > 0) {
        try stdout.writeAll("corpus-audit: missing pass/fail coverage\n");
        for (audit.missing_pass_or_fail.items) |prefix| {
            try stdout.print("  - {s}\n", .{prefix});
        }
    }

    try stdout.flush();
}

fn audit_has_failures(audit: *const AuditData) bool {
    assert(audit.file_count >= audit.invalid_names.items.len);
    if (audit.invalid_names.items.len > 0) {
        return true;
    }
    return audit.missing_pass_or_fail.items.len > 0;
}

fn rule_prefix(rule_id: libtiger.rules.Id) []const u8 {
    const id = libtiger.rules.id_string(rule_id);
    assert(id.len > 0);
    if (id.len == 0) {
        return id;
    }
    const sep = std.mem.indexOfScalar(u8, id, '_') orelse return id;
    return id[0..sep];
}

fn is_required_prefix(required_set: *const std.StringHashMap(void), prefix: []const u8) bool {
    assert(prefix.len > 0);
    if (prefix.len == 0) {
        return false;
    }
    return required_set.contains(prefix);
}

fn parse_case_name(basename: []const u8) ?CaseName {
    assert(basename.len > 0);
    if (basename.len == 0) {
        return null;
    }
    if (!corpus_common.is_zig_case_file(basename)) {
        return null;
    }
    if (corpus_common.is_pass_case_basename(basename)) {
        const stem_start = corpus_common.case_pass_prefix().len;
        const stem_end = basename.len - corpus_common.zig_file_extension().len;
        return parse_case_name_tail(
            .pass,
            basename[stem_start..stem_end],
        );
    }
    if (corpus_common.is_fail_case_basename(basename)) {
        const stem_start = corpus_common.case_fail_prefix().len;
        const stem_end = basename.len - corpus_common.zig_file_extension().len;
        return parse_case_name_tail(
            .fail,
            basename[stem_start..stem_end],
        );
    }
    return null;
}

fn parse_case_name_tail(kind: CaseKind, tail: []const u8) ?CaseName {
    assert(tail.len > 0);
    if (tail.len == 0) {
        return null;
    }

    const sep = std.mem.indexOfScalar(u8, tail, '_') orelse return null;
    if (sep == 0 or sep + 1 >= tail.len) {
        return null;
    }
    const prefix = tail[0..sep];
    if (!is_valid_rule_prefix(prefix)) {
        return null;
    }
    return .{
        .kind = kind,
        .prefix = prefix,
    };
}

fn is_valid_rule_prefix(prefix: []const u8) bool {
    assert(prefix.len <= 8);
    if (prefix.len < 3 or prefix.len > 4) {
        return false;
    }
    if (!std.ascii.isUpper(prefix[0])) {
        return false;
    }
    if (prefix.len == 3) {
        return std.ascii.isDigit(prefix[1]) and std.ascii.isDigit(prefix[2]);
    }
    return std.ascii.isUpper(prefix[1]) and
        std.ascii.isDigit(prefix[2]) and
        std.ascii.isDigit(prefix[3]);
}

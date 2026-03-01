const std = @import("std");
const assert = std.debug.assert;

const ReleaseArgs = struct {
    version: []const u8,
    sha: ?[]const u8,
    dry_run: bool,
};

const ValidateArgs = struct {
    tag: ?[]const u8,
};

const release_script_template =
    \\set -euo pipefail
    \\VERSION="__VERSION__"
    \\SHA="__SHA__"
    \\DRY_RUN="__DRY_RUN__"
    \\TARGETS=(
    \\  x86_64-linux
    \\  aarch64-linux
    \\  x86_64-windows
    \\  aarch64-macos
    \\)
    \\
    \\if [ -z "${SHA}" ]; then
    \\  SHA="$(git rev-parse HEAD)"
    \\fi
    \\
    \\if [ "${DRY_RUN}" = "0" ]; then
    \\  gh --version
    \\
    \\  if [ -z "${GITHUB_REPOSITORY:-}" ]; then
    \\    echo "GITHUB_REPOSITORY is required"
    \\    exit 1
    \\  fi
    \\  if [ -z "${GITHUB_TOKEN:-}" ]; then
    \\    echo "GITHUB_TOKEN is required"
    \\    exit 1
    \\  fi
    \\
    \\  if git rev-parse -q --verify "refs/tags/${VERSION}" >/dev/null; then
    \\    echo "Tag ${VERSION} already exists"
    \\    exit 1
    \\  fi
    \\
    \\  if gh release view "${VERSION}" >/dev/null 2>&1; then
    \\    echo "Release ${VERSION} already exists"
    \\    exit 1
    \\  fi
    \\fi
    \\
    \\echo "release: running quality gates"
    \\./zig/zig build test
    \\./zig/zig build precision-check
    \\./zig/zig build check-strict -Dstyle-path=./src/libtigercheck
    \\
    \\rm -rf zig-out/dist/tigercheck
    \\mkdir -p zig-out/dist/tigercheck
    \\
    \\for target in "${TARGETS[@]}"; do
    \\  echo "release: building target=${target}"
    \\  ./zig/zig build -Doptimize=ReleaseSafe -Dtarget="${target}"
    \\
    \\  binary="zig-out/bin/tigercheck"
    \\  if [ "${target}" = "x86_64-windows" ]; then
    \\    binary="${binary}.exe"
    \\  fi
    \\
    \\  zip -j "zig-out/dist/tigercheck/tigercheck-${target}.zip" "${binary}"
    \\done
    \\
    \\if command -v sha256sum >/dev/null 2>&1; then
    \\  (
    \\    cd zig-out/dist/tigercheck
    \\    sha256sum ./*.zip > SHA256SUMS
    \\  )
    \\elif command -v shasum >/dev/null 2>&1; then
    \\  (
    \\    cd zig-out/dist/tigercheck
    \\    shasum -a 256 ./*.zip > SHA256SUMS
    \\  )
    \\else
    \\  echo "Need sha256sum or shasum"
    \\  exit 1
    \\fi
    \\
    \\ZIG_VERSION="$(./zig/zig version)"
    \\TARGET_LIST="${TARGETS[*]}"
    \\
    \\cat > zig-out/dist/tigercheck/RELEASE_METADATA <<EOF
    \\version=${VERSION}
    \\source_sha=${SHA}
    \\zig_version=${ZIG_VERSION}
    \\targets=${TARGET_LIST}
    \\gates=test,precision-check,check-strict
    \\EOF
    \\
    \\cat > zig-out/dist/tigercheck/RELEASE_NOTES.md <<EOF
    \\Release ${VERSION}
    \\
    \\- Source SHA: ${SHA}
    \\- Zig version: ${ZIG_VERSION}
    \\- Targets: ${TARGET_LIST}
    \\- Quality gates: test, precision-check, check-strict
    \\EOF
    \\
    \\if [ "${DRY_RUN}" = "1" ]; then
    \\  echo "release: dry-run complete; artifacts ready in zig-out/dist/tigercheck"
    \\  ls -1 zig-out/dist/tigercheck
    \\  exit 0
    \\fi
    \\
    \\echo "release: creating draft release ${VERSION}"
    \\RELEASE_BODY="$(cat zig-out/dist/tigercheck/RELEASE_NOTES.md)"
    \\create_args=(
    \\  --method POST
    \\  "repos/${GITHUB_REPOSITORY}/releases"
    \\  -f "tag_name=${VERSION}"
    \\  -f "target_commitish=${SHA}"
    \\  -f "name=tigercheck ${VERSION}"
    \\  -f "body=${RELEASE_BODY}"
    \\  -F "draft=true"
    \\)
    \\gh api "${create_args[@]}" >/dev/null
    \\
    \\upload_args=(
    \\  "${VERSION}"
    \\  zig-out/dist/tigercheck/tigercheck-x86_64-linux.zip
    \\  zig-out/dist/tigercheck/tigercheck-aarch64-linux.zip
    \\  zig-out/dist/tigercheck/tigercheck-x86_64-windows.zip
    \\  zig-out/dist/tigercheck/tigercheck-aarch64-macos.zip
    \\  zig-out/dist/tigercheck/SHA256SUMS
    \\  zig-out/dist/tigercheck/RELEASE_METADATA
    \\  zig-out/dist/tigercheck/RELEASE_NOTES.md
    \\)
    \\gh release upload "${upload_args[@]}"
    \\
    \\gh release edit "${VERSION}" --draft=false --latest=true
    \\echo "release: release ${VERSION} complete"
;

const validate_script =
    \\set -euo pipefail
    \\
    \\gh --version
    \\TAG="__TAG__"
    \\if [ -z "${TAG}" ]; then
    \\  TAG="$(gh release list --limit 1 --json tagName --jq '.[0].tagName')"
    \\fi
    \\
    \\if [ -z "${TAG}" ] || [ "${TAG}" = "null" ]; then
    \\  echo "No GitHub release found"
    \\  exit 1
    \\fi
    \\
    \\git fetch origin "refs/tags/${TAG}:refs/tags/${TAG}"
    \\git switch --detach "tags/${TAG}"
    \\
    \\rm -rf zig-out/release-validate
    \\mkdir -p zig-out/release-validate
    \\gh release download "${TAG}" --dir zig-out/release-validate
    \\
    \\artifact_names=(
    \\  tigercheck-x86_64-linux.zip
    \\  tigercheck-aarch64-linux.zip
    \\  tigercheck-x86_64-windows.zip
    \\  tigercheck-aarch64-macos.zip
    \\  SHA256SUMS
    \\  RELEASE_METADATA
    \\  RELEASE_NOTES.md
    \\)
    \\for artifact in "${artifact_names[@]}"; do
    \\  if [ ! -f "zig-out/release-validate/${artifact}" ]; then
    \\    echo "Missing release artifact: ${artifact}"
    \\    exit 1
    \\  fi
    \\done
    \\
    \\(
    \\  cd zig-out/release-validate
    \\  sha256sum --check SHA256SUMS
    \\)
    \\
    \\if grep -q "^version=${TAG}$" zig-out/release-validate/RELEASE_METADATA; then
    \\  :
    \\else
    \\  echo "release metadata version mismatch"
    \\  cat zig-out/release-validate/RELEASE_METADATA
    \\  exit 1
    \\fi
    \\if grep -q "^source_sha=" zig-out/release-validate/RELEASE_METADATA; then
    \\  :
    \\else
    \\  echo "release metadata missing source_sha"
    \\  cat zig-out/release-validate/RELEASE_METADATA
    \\  exit 1
    \\fi
    \\if grep -q "Release ${TAG}" zig-out/release-validate/RELEASE_NOTES.md; then
    \\  :
    \\else
    \\  echo "release notes header mismatch"
    \\  cat zig-out/release-validate/RELEASE_NOTES.md
    \\  exit 1
    \\fi
    \\
    \\if [ "$(uname -s)" = "Linux" ]; then
    \\  rm -rf zig-out/release-validate/bin
    \\  mkdir -p zig-out/release-validate/bin
    \\  linux_archive=zig-out/release-validate/tigercheck-x86_64-linux.zip
    \\  unzip -o "${linux_archive}" -d zig-out/release-validate/bin
    \\  chmod +x zig-out/release-validate/bin/tigercheck
    \\  usage_output="$(zig-out/release-validate/bin/tigercheck 2>&1 || true)"
    \\  if printf '%s\\n' "${usage_output}" | grep -q '^usage: tigercheck'; then
    \\    :
    \\  else
    \\    echo "Unexpected tigercheck usage output"
    \\    printf '%s\\n' "${usage_output}"
    \\    exit 1
    \\  fi
    \\else
    \\  echo "release: skipping binary execution test on non-linux host"
    \\fi
    \\
    \\echo "release: running validation quality gates"
    \\./zig/zig build test
    \\./zig/zig build precision-check
    \\./zig/zig build check-strict -Dstyle-path=./src/libtigercheck
    \\
    \\echo "release: release ${TAG} validated"
;

pub fn main(init: std.process.Init) !void {
    var stdout_buffer: [4096]u8 = undefined;
    assert(stdout_buffer.len == 4096);
    var stdout_stream = std.Io.File.stdout().writerStreaming(init.io, &stdout_buffer);
    const stdout = &stdout_stream.interface;

    var args = try init.minimal.args.iterateAllocator(init.gpa);
    defer args.deinit();

    const argv0 = args.next() orelse {
        try print_usage(stdout);
        try stdout.flush();
        std.process.exit(2);
    };
    assert_non_empty(argv0) catch {
        try print_usage(stdout);
        try stdout.flush();
        std.process.exit(2);
    };

    const command = args.next() orelse {
        try print_usage(stdout);
        try stdout.flush();
        return;
    };
    assert(command.len > 0);

    if (std.mem.eql(u8, command, "--help") or std.mem.eql(u8, command, "-h")) {
        try print_usage(stdout);
        try stdout.flush();
        return;
    }

    if (std.mem.eql(u8, command, "release")) {
        try handle_release_command(&args, init.gpa, init.io, stdout);
        try stdout.flush();
        return;
    }

    if (std.mem.eql(u8, command, "validate")) {
        try handle_validate_command(&args, init.gpa, init.io, stdout);
        try stdout.flush();
        return;
    }

    try print_usage(stdout);
    try stdout.flush();
    std.process.exit(2);
}

fn handle_release_command(
    args: *std.process.Args.Iterator,
    allocator: std.mem.Allocator,
    io: std.Io,
    stdout: *std.Io.Writer,
) !void {
    assert(@sizeOf(@TypeOf(args.*)) > 0);
    assert(@sizeOf(@TypeOf(stdout.*)) > 0);

    var tokens: [5]?[]const u8 = .{ null, null, null, null, null };
    var token_count: u8 = 0;
    while (token_count < tokens.len) : (token_count += 1) {
        tokens[token_count] = args.next() orelse break;
    }
    if (token_count == tokens.len and args.next() != null) {
        try print_usage(stdout);
        try stdout.flush();
        std.process.exit(2);
    }

    const parsed_args = parse_release_args(
        tokens[0],
        tokens[1],
        tokens[2],
        tokens[3],
        tokens[4],
    ) catch {
        try print_usage(stdout);
        try stdout.flush();
        std.process.exit(2);
    };

    run_release(allocator, io, stdout, parsed_args) catch |err| {
        try stdout.print("release: release failed: {}\n", .{err});
        try stdout.flush();
        std.process.exit(1);
    };
}

fn handle_validate_command(
    args: *std.process.Args.Iterator,
    allocator: std.mem.Allocator,
    io: std.Io,
    stdout: *std.Io.Writer,
) !void {
    assert(@sizeOf(@TypeOf(args.*)) > 0);
    assert(@sizeOf(@TypeOf(stdout.*)) > 0);

    const parsed_args = parse_validate_args(args.next(), args.next()) catch {
        try print_usage(stdout);
        try stdout.flush();
        std.process.exit(2);
    };
    if (args.next() != null) {
        try print_usage(stdout);
        try stdout.flush();
        std.process.exit(2);
    }

    run_validate(allocator, io, stdout, parsed_args) catch |err| {
        try stdout.print("release: validation failed: {}\n", .{err});
        try stdout.flush();
        std.process.exit(1);
    };
}

fn parse_release_args(
    arg1: ?[]const u8,
    arg2: ?[]const u8,
    arg3: ?[]const u8,
    arg4: ?[]const u8,
    arg5: ?[]const u8,
) !ReleaseArgs {
    assert(arg1 != null or arg2 == null);
    assert(arg3 == null or arg3.?.len > 0);
    assert(arg4 == null or arg4.?.len > 0);
    assert(arg5 == null or arg5.?.len > 0);
    if (arg1 == null) return error.InvalidArguments;

    var tokens = [_]?[]const u8{ arg1, arg2, arg3, arg4, arg5 };
    assert(tokens[0] != null);

    var state = ParseState{ .version = null, .sha = null, .dry_run = false };
    var token_index: u8 = 0;
    while (token_index < tokens.len) : (token_index += 1) {
        const flag = tokens[token_index] orelse break;
        token_index = try parse_release_token(flag, &tokens, token_index, &state);
        token_index -= 1;
    }

    return try finalize_release_args(state);
}

fn parse_release_token(
    flag: []const u8,
    tokens: *const [5]?[]const u8,
    token_index: u8,
    state: *ParseState,
) !u8 {
    assert(flag.len > 0);
    assert(token_index < tokens.len);
    assert(state.version == null or state.version.?.len > 0);
    if (flag.len == 0) return error.InvalidArguments;

    if (std.mem.eql(u8, flag, "--dry-run")) {
        if (state.dry_run) return error.InvalidArguments;
        state.dry_run = true;
        return token_index + 1;
    }

    const value_index = token_index + 1;
    if (value_index >= tokens.len) return error.InvalidArguments;
    const value = tokens[value_index] orelse return error.InvalidArguments;
    state.* = try parse_release_pair(state.*, flag, value);
    return value_index + 1;
}

const ParseState = struct {
    version: ?[]const u8,
    sha: ?[]const u8,
    dry_run: bool,
};

fn parse_release_pair(state_in: ParseState, flag: []const u8, value: []const u8) !ParseState {
    assert(flag.len > 0);
    assert(value.len > 0);
    if (flag.len == 0 or value.len == 0) return error.InvalidArguments;

    var state = state_in;
    if (std.mem.eql(u8, flag, "--version")) {
        if (state.version != null) return error.InvalidArguments;
        state.version = value;
        return state;
    }
    if (std.mem.eql(u8, flag, "--sha")) {
        if (state.sha != null) return error.InvalidArguments;
        state.sha = value;
        return state;
    }
    return error.InvalidArguments;
}

fn finalize_release_args(state: ParseState) !ReleaseArgs {
    const parsed_version = state.version orelse return error.InvalidArguments;
    if (is_semver(parsed_version)) {
        // positive invariant
    } else {
        return error.InvalidArguments;
    }

    if (state.sha) |parsed_sha| {
        if (is_hex_sha(parsed_sha)) {
            // positive invariant
        } else {
            return error.InvalidArguments;
        }
    }

    return .{ .version = parsed_version, .sha = state.sha, .dry_run = state.dry_run };
}

fn parse_validate_args(arg1: ?[]const u8, arg2: ?[]const u8) !ValidateArgs {
    assert(arg1 == null or arg1.?.len > 0);
    assert(arg2 == null or arg2.?.len <= 32);
    if (arg1 == null and arg2 == null) {
        return .{ .tag = null };
    }
    if (arg1 == null or arg2 == null) {
        return error.InvalidArguments;
    }
    if (std.mem.eql(u8, arg1.?, "--tag")) {
        // positive invariant
    } else {
        return error.InvalidArguments;
    }
    if (arg2.?.len == 0) {
        return .{ .tag = null };
    }
    if (is_semver(arg2.?)) {
        // positive invariant
    } else {
        return error.InvalidArguments;
    }
    return .{ .tag = arg2.? };
}

fn run_release(
    allocator: std.mem.Allocator,
    io: std.Io,
    stdout: *std.Io.Writer,
    args: ReleaseArgs,
) !void {
    assert(args.version.len > 0);
    const sha = args.sha orelse "";

    const with_version = try std.mem.replaceOwned(
        u8,
        allocator,
        release_script_template,
        "__VERSION__",
        args.version,
    );
    defer allocator.free(with_version);

    const with_sha = try std.mem.replaceOwned(
        u8,
        allocator,
        with_version,
        "__SHA__",
        sha,
    );
    defer allocator.free(with_sha);

    var dry_run_value = "0";
    if (args.dry_run) {
        dry_run_value = "1";
    }
    const script = try std.mem.replaceOwned(
        u8,
        allocator,
        with_sha,
        "__DRY_RUN__",
        dry_run_value,
    );
    defer allocator.free(script);

    try run_shell(allocator, io, stdout, script);
}

fn run_validate(
    allocator: std.mem.Allocator,
    io: std.Io,
    stdout: *std.Io.Writer,
    args: ValidateArgs,
) !void {
    const tag = args.tag orelse "";
    const script = try std.mem.replaceOwned(
        u8,
        allocator,
        validate_script,
        "__TAG__",
        tag,
    );
    defer allocator.free(script);
    try run_shell(allocator, io, stdout, script);
}

fn run_shell(
    allocator: std.mem.Allocator,
    io: std.Io,
    stdout: *std.Io.Writer,
    script: []const u8,
) !void {
    assert(script.len > 0);
    assert(script.len <= 2 * 1024 * 1024);
    assert(@sizeOf(@TypeOf(stdout.*)) > 0);

    if (script.len == 0) return error.InvalidArguments;

    const result = try std.process.run(allocator, io, .{
        .argv = &.{ "bash", "-lc", script },
        .stdout_limit = .limited(128 * 1024 * 1024),
        .stderr_limit = .limited(128 * 1024 * 1024),
    });
    defer {
        allocator.free(result.stdout);
        allocator.free(result.stderr);
    }

    const exit_code = switch (result.term) {
        .exited => |code| code,
        .signal, .stopped, .unknown => 255,
    };
    if (exit_code == 0) return;

    if (result.stdout.len > 0) {
        try stdout.print("stdout:\n{s}\n", .{std.mem.trimEnd(u8, result.stdout, "\n")});
    }
    if (result.stderr.len > 0) {
        try stdout.print("stderr:\n{s}\n", .{std.mem.trimEnd(u8, result.stderr, "\n")});
    }

    return error.CommandFailed;
}

fn is_semver(version: []const u8) bool {
    assert(version.len <= 256);
    assert(std.mem.indexOfScalar(u8, version, 0) == null);
    if (version.len < 5 or version.len > 32) return false;

    const first_dot = std.mem.indexOfScalar(u8, version, '.') orelse return false;
    if (first_dot == 0) return false;

    const tail_after_first = version[first_dot + 1 ..];
    const second_dot_rel = std.mem.indexOfScalar(u8, tail_after_first, '.') orelse return false;
    const second_dot = first_dot + 1 + second_dot_rel;
    if (second_dot + 1 >= version.len) return false;

    const third_dot = std.mem.indexOfScalar(u8, version[second_dot + 1 ..], '.');
    if (third_dot != null) return false;

    const major = version[0..first_dot];
    const minor = version[first_dot + 1 .. second_dot];
    const patch = version[second_dot + 1 ..];
    assert(major.len > 0);
    assert(minor.len > 0);
    assert(patch.len > 0);

    if (is_decimal_u32(major)) {
        // positive invariant
    } else {
        return false;
    }
    if (is_decimal_u32(minor)) {
        // positive invariant
    } else {
        return false;
    }
    if (is_decimal_u32(patch)) {
        // positive invariant
    } else {
        return false;
    }
    return true;
}

fn is_hex_sha(sha: []const u8) bool {
    assert(sha.len <= 64);
    if (sha.len < 7 or sha.len > 40) return false;

    for (sha) |byte| {
        const is_digit = byte >= '0' and byte <= '9';
        const is_lower_hex = byte >= 'a' and byte <= 'f';
        const is_upper_hex = byte >= 'A' and byte <= 'F';
        const is_hex = is_digit or is_lower_hex or is_upper_hex;
        if (is_hex) {
            // positive invariant
        } else {
            return false;
        }
    }
    return true;
}

fn is_decimal_u32(text: []const u8) bool {
    assert(text.len <= 16);
    if (text.len == 0 or text.len > 10) return false;

    const value = std.fmt.parseInt(u64, text, 10) catch return false;
    return value <= std.math.maxInt(u32);
}

fn assert_non_empty(text: []const u8) !void {
    assert(text.len <= 4096);
    if (text.len == 0) return error.InvalidArguments;
}

fn print_usage(stdout: *std.Io.Writer) !void {
    try stdout.writeAll(
        "usage:\n" ++
            "  release release --version <x.y.z> [--sha <commit>] [--dry-run]\n" ++
            "  release validate [--tag <x.y.z>]\n",
    );
}

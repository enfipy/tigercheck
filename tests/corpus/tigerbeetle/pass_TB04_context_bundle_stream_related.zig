const ImplicitStreamCtx = struct {
    tree: u32,
    source: u32,
    node: u32,
    file_path: u32,
    result: u32,
    visited: u32,
};

fn walk_implicit_stream_related(ctx: *const ImplicitStreamCtx) void {
    _ = ctx;
}

pub fn main() void {
    const ctx = ImplicitStreamCtx{
        .tree = 1,
        .source = 2,
        .node = 3,
        .file_path = 4,
        .result = 5,
        .visited = 6,
    };
    walk_implicit_stream_related(&ctx);
}

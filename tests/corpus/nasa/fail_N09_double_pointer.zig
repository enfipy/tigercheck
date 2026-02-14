fn walk(root: **u8) void {
    _ = root;
}

pub fn main() void {
    var p: *u8 = undefined;
    walk(&p);
}

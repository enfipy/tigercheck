pub fn main() void {
    var x: usize = 0;
    x += 1;
    x += 2;
    x += 3;
    x += 4;
    x += 5;
    if (x > 3) {
        x += 1;
    }
    if (x == 0) unreachable;
}

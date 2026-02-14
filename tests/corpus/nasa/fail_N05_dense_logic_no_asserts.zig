pub fn main() void {
    var x: i32 = 0;
    x += 1;
    x += 2;
    x += 3;
    x += 4;
    x += 5;
    if (x > 1) x += 1;
    if (x > 2) x += 1;
    if (x > 3) x += 1;
    if (x > 4) x += 1;
    if (x > 5) x += 1;
    while (x < 30) : (x += 1) {
        if (x % 2 == 0) x += 1;
    }
    if (x == -1) unreachable;
}

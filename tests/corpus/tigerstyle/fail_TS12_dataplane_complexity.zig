pub fn main() void {
    var x: i32 = 0;
    if (x == 0) x += 1;
    if (x == 1) x += 1;
    if (x == 2) x += 1;
    if (x == 3) x += 1;
    if (x == 4) x += 1;
    if (x == 5) x += 1;
    while (x < 20) : (x += 1) {
        if (x % 2 == 0) x += 1;
    }
    for (0..3) |_| {
        if (x > 10) x -= 1;
    }
    switch (x) {
        1 => x += 1,
        2 => x += 1,
        3 => x += 1,
        else => x += 1,
    }
}

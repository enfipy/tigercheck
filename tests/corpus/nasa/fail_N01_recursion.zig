fn a() void {
    b();
}

fn b() void {
    a();
}

pub fn main() void {
    a();
}

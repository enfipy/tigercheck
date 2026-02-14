const Flow = struct {
    fn c() void {}

    fn b() void {
        c();
    }

    fn a() void {
        b();
    }
};

pub fn main() void {
    Flow.a();
}

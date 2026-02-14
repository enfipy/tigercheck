const Math = struct {
    fn add(a: u32, b: u32) u32 {
        return a + b;
    }
};

pub fn main() void {
    const sum = Math.add(1, 2);
    if (sum == 0) unreachable;
}

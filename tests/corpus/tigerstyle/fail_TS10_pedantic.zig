// expect-rule: TS10_PEDANTIC
pub fn badName() void {}

pub fn main() void {
    badName();
}

// expect-rule: TS13_BOOLEAN_SPLIT
pub fn main() void {
    const ready = true;
    const healthy = true;
    const synced = true;

    if (ready and healthy and synced) {
        return;
    }
}

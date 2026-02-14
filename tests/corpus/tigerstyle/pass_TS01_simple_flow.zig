pub fn main() void {
    const Mode = enum {
        boot,
        run,
    };
    const mode: Mode = .run;
    switch (mode) {
        .boot => {},
        .run => {},
    }
}

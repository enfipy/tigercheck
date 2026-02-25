const Flow = struct {
    fn parse_request() void {}

    fn handle_control() void {
        parse_request();
    }

    fn handle_data() void {
        parse_request();
    }

    fn run() void {
        handle_control();
        handle_data();
    }
};

pub fn main() void {
    Flow.run();
}

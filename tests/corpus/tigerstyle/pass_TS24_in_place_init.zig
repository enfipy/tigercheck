const LargePacket = struct {
    header: [32]u8,
    body: [64]u8,
};

fn build_packet(out_packet: *LargePacket) void {
    out_packet.* = .{
        .header = [_]u8{0} ** 32,
        .body = [_]u8{0} ** 64,
    };
}

fn consume_packet(packet: *const LargePacket) void {
    _ = packet;
}

pub fn main() void {
    var packet: LargePacket = undefined;
    build_packet(&packet);
    consume_packet(&packet);
}

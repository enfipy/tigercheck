const LargePacket = struct {
    header: [32]u8,
    body: [64]u8,
};

fn build_packet() LargePacket {
    return .{
        .header = [_]u8{0} ** 32,
        .body = [_]u8{0} ** 64,
    };
}

fn consume_packet(packet: *const LargePacket) void {
    _ = packet;
}

pub fn main() void {
    const packet = build_packet();
    consume_packet(&packet);
}

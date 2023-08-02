const std = @import("std");
const block_states = @import("block_states.zig");
const packed_longs = @import("packed_longs.zig");
const chunk_nbt = @import("chunk_nbt.zig");
const varint = @import("varint.zig");

pub fn serializePaletted(writer: anytype, states: block_states.BlockStates, chunk: chunk_nbt.BlockStates_NBT) !void {
    var buf: [5]u8 = undefined;
    if (chunk.data == null) {
        try writer.writeByte(0);
        var palette_value = palette(states, chunk.palette[0]).?;
        try writer.writeAll(varint.writeVarInt(palette_value, &buf));
        try writer.writeAll(varint.writeVarInt(0, &buf));
        return;
    }

    var ceil = try std.math.ceilPowerOfTwo(u31, @as(u31, @intCast(chunk.palette.len)));
    if (ceil < 16) ceil = 16;

    try writer.writeByte(15);
    try writer.writeAll(varint.writeVarInt(1024, &buf));
    for (0..1024) |v| {
        var x: u64 = 0;
        for (0..4) |w| {
            x <<= 15;
            var value: u64 = packed_longs.getBit(@ctz(ceil), @ptrCast(chunk.data.?), v * 4 + (3 - w));
            x |= @as(u16, @intCast(palette(states, chunk.palette[value]).?));
        }

        try writer.writeIntBig(u64, x);
    }
}

fn palette(states: block_states.BlockStates, block: chunk_nbt.Block_NBT) ?u31 {
    var block_state_opt = states.get(block.Name);
    if (block_state_opt == null) return null;

    state: for (block_state_opt.?.states) |state| {
        var it = state.properties.iterator();
        while (it.next()) |kv| {
            if (block.Properties) |p| {
                const value = p.get(kv.key_ptr.*);
                if (value == null or !std.mem.eql(u8, value.?, kv.value_ptr.*)) {
                    continue :state;
                }
            }
        }

        return state.id;
    }

    return null;
}

const std = @import("std");

const SEGMENT_BITS: u32 = 0x7F;
const CONTINUE_BIT: u32 = 0x80;

pub fn readVarInt(buf: []u8) !u32 {
    var fixed = std.io.fixedBufferStream(buf);
    return readVarIntReader(fixed.reader());
}

pub fn readVarIntReader(buf: anytype) !u32 {
    var value: u32 = 0;
    var position: u32 = 0;
    var currentByte: u8 = undefined;

    var index: usize = 0;

    while (true) {
        currentByte = buf.readByte() catch return error.Eof;
        index += 1;
        value |= @as(u32, @intCast((currentByte & SEGMENT_BITS))) << @intCast(position);

        if ((currentByte & CONTINUE_BIT) == 0) break;

        position += 7;

        if (position >= 32) return error.VarIntTooBig;
    }

    return value;
}

pub fn writeVarInt(value: u32, buf: *[5]u8) []u8 {
    var value2 = value;

    var index: usize = 0;
    var slice = buf;
    while (true) {
        if ((value2 & ~SEGMENT_BITS) == 0) {
            slice[index] = @intCast(value2);
            index += 1;
            return slice[0..index];
        }

        slice[index] = @intCast(((value2 & SEGMENT_BITS) | CONTINUE_BIT));
        index += 1;

        value2 = value2 >> 7;
    }

    return slice[0..index];
}

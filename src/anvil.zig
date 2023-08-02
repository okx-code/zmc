const std = @import("std");
const chunk_nbt = @import("chunk_nbt.zig");
const nbt = @import("nbt.zig");
const lz = @import("zlib.zig");

pub const LocationTableEntry = struct {
    offset: u24,
    length: u8,
};

pub const AnvilRegion = struct {
    file_handle: std.os.fd_t,
    location_table: [1024]LocationTableEntry = undefined,
    timestamp_table: [1024]u32 = undefined,

    pub fn load(self: *AnvilRegion) !void {
        const stream = std.fs.File{ .handle = self.file_handle };
        var reader = stream.reader();

        for (0..1024) |i| {
            var offset = try reader.readIntBig(u24);
            var length = try reader.readIntBig(u8);

            self.location_table[i] = .{ .offset = offset, .length = length };
        }

        for (0..1024) |i| {
            var timestamp = try reader.readIntBig(u32);

            self.timestamp_table[i] = timestamp;
        }
    }

    // todo add arena allocator
    pub fn loadChunk(self: AnvilRegion, zlib: *lz.Zlib, allocator: std.mem.Allocator, arena_allocator: std.mem.Allocator, x: u5, z: u5) !?chunk_nbt.Chunk_NBT {
        const stream = std.fs.File{ .handle = self.file_handle };
        var location = self.location_table[@as(usize, x) + @as(usize, z) * 32];
        if (location.offset == 0 and location.length == 0) {
            return null;
        }

        try stream.seekTo(location.offset * 4096);

        var reader = stream.reader();

        var length = try reader.readIntBig(u32);
        var compression_type = try reader.readIntBig(u8);
        if (compression_type != 2) return error.NotZlib;

        var list = try std.ArrayListUnmanaged(u8).initCapacity(allocator, length);
        defer list.deinit(allocator);

        try zlib.inflate(reader, list.writer(allocator));

        var timer2 = try std.time.Timer.start();
        defer std.log.info("parsed in {d}μs", .{timer2.read() / 1000});
        return try nbt.parse(chunk_nbt.Chunk_NBT, arena_allocator, list.items);
    }
};

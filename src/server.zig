const std = @import("std");

const World = @import("world.zig").World;
const anvil = @import("anvil.zig");
const block_states = @import("block_states.zig");
const chunk_nbt = @import("chunk_nbt.zig");
const event_loop = @import("event_loop.zig");
const packet_builder = @import("packet_builder.zig");
const packets = @import("packets.zig");
const paletted_container = @import("paletted_container.zig");
const varint = @import("varint.zig");
const zlib = @import("zlib.zig");
const player = @import("player.zig");

const heightmap = @embedFile("heightmap");

pub const Server = struct {
    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    states: block_states.BlockStates,
    chunks: []chunk_nbt.Chunk_NBT,
    players: std.ArrayListUnmanaged(player.Player),

    chunk_allocator: std.heap.ArenaAllocator,

    pub fn init(allocator: std.mem.Allocator, states: block_states.BlockStates) !Server {
        var arena = std.heap.ArenaAllocator.init(allocator);

        const fd: std.os.fd_t = try std.os.open("src/r.mca", std.os.O.RDONLY, 0);
        var region: anvil.AnvilRegion = .{ .file_handle = fd };
        try region.load();

        var lz = zlib.Zlib.init(&arena.allocator());
        defer lz.deinit();

        // todo fix memory leak here
        var chunk_allocator = std.heap.ArenaAllocator.init(allocator);
        var array = std.ArrayListUnmanaged(chunk_nbt.Chunk_NBT){};
        for (0..8) |x| {
            for (0..8) |z| {
                if (region.loadChunk(&lz, allocator, chunk_allocator.allocator(), @intCast(x), @intCast(z)) catch continue) |chunk| {
                    try array.append(chunk_allocator.allocator(), chunk);
                }
            }
        }

        return .{
            .allocator = allocator,
            .arena = arena,
            .states = states,
            .chunks = try array.toOwnedSlice(chunk_allocator.allocator()),
            .chunk_allocator = chunk_allocator,
            .players = std.ArrayListUnmanaged(player.Player){},
        };
    }

    pub fn deinit(self: *Server) void {
        self.players.deinit(self.allocator);
        self.arena.deinit();
        self.chunk_allocator.deinit();
    }

    pub fn tick(self: *Server) !void {
        _ = self.arena.reset(.{ .retain_with_limit = 10_000_000 });
        //self.world.tick(self);
    }

    pub fn handle(self: *Server, packet: packets.ServerboundPacket) !void {
        _ = self.arena.reset(.{ .retain_with_limit = 10_000_000 });
        switch (packet.type) {
            .Play => try self.play(packet.player, packet.queue),
            .Pos => |p| try self.move(packet.player, packet.queue, p),
            else => unreachable,
        }
    }

    pub fn play(self: *Server, player_id: usize, packet_queue: *std.atomic.Queue([]u8)) !void {
        const arena_allocator = self.arena.allocator();
        std.debug.print("hello from play {d}\n", .{player_id});

        try self.players.ensureTotalCapacity(self.allocator, player_id + 1);
        self.players.expandToCapacity();
        self.players.items[player_id] = .{ .pos = .{ .x = 0, .y = 0, .z = 0 }, .sent_pos = .{ .x = 0, .y = 0, .z = 0 } };

        var pkt_builder = packet_builder.PacketBuilder{ .arena_allocator = arena_allocator, .allocator = self.allocator };
        errdefer pkt_builder.deinit();
        var pkt = pkt_builder.writer();

        for (self.chunks) |chunk| {
            try pkt.writeByte(0x24); // packet id
            try pkt.writeIntBig(u32, @as(u32, @intCast(chunk.xPos)));
            try pkt.writeIntBig(u32, @as(u32, @intCast(chunk.zPos)));
            try pkt.writeAll(heightmap);

            var datapkt = std.ArrayListUnmanaged(u8){};
            for (0..24) |i| {
                try datapkt.appendSlice(arena_allocator, &[_]u8{ 0x7f, 0xff }); // "non air blocks"

                //try datapkt.append(arena_allocator, 0); // palette - bits per entry
                //try datapkt.append(arena_allocator, 0x00); // stone
                //try datapkt.append(arena_allocator, 0); // data array length

                const chunk_states = chunk.sections[i].block_states;
                try paletted_container.serializePaletted(datapkt.writer(arena_allocator), self.states, chunk_states);

                try datapkt.append(arena_allocator, 0); // palette - bits per entry
                try datapkt.append(arena_allocator, 0x01); // idk biome
                try datapkt.append(arena_allocator, 0); // data array length
            }

            var lenbuf: [5]u8 = undefined;
            try pkt.writeAll(varint.writeVarInt(@intCast(datapkt.items.len), &lenbuf));
            try pkt.writeAll(datapkt.items);

            try pkt.writeByte(0); // block entities

            try pkt.writeByte(1); // sky light mask
            try pkt.writeIntBig(u64, (1 << 26) - 1); // sky light mask
            try pkt.writeByte(0); // block sky light mask
            try pkt.writeByte(0); // empty sky light mask
            try pkt.writeByte(0); // empty block light mask
            try pkt.writeByte(26); // sky light array count
            for (0..26) |_| {
                try pkt.writeAll(varint.writeVarInt(2048, &lenbuf));
                for (0..2048) |_| {
                    try pkt.writeByte(0xFF);
                }
            }
            try pkt.writeByte(0); // block light array count

            try pkt_builder.finish();

            try pkt.writeByte(0x27); // packet id
            try pkt.writeAll(varint.writeVarInt(@intCast(chunk.xPos), &lenbuf));
            try pkt.writeAll(varint.writeVarInt(@intCast(chunk.zPos), &lenbuf));

            try pkt.writeByte(1); // sky light mask
            try pkt.writeIntBig(u64, (1 << 26) - 1); // sky light mask
            try pkt.writeByte(0); // block sky light mask
            try pkt.writeByte(0); // empty sky light mask
            try pkt.writeByte(0); // empty block light mask
            try pkt.writeByte(26); // sky light array count
            for (0..26) |_| {
                try pkt.writeAll(varint.writeVarInt(2048, &lenbuf));
                for (0..2048) |_| {
                    try pkt.writeByte(0xFF);
                }
            }
            try pkt.writeByte(0); // block light array count

            try pkt_builder.finish();
        }

        // Set Default Spawn Position
        try pkt.writeByte(0x50);

        var pos: u64 = 0;
        try pkt.writeAll(&std.mem.toBytes(std.mem.nativeToBig(u64, pos)));
        try pkt.writeAll(&[_]u8{ 0, 0, 0, 0 });

        try pkt_builder.finish();

        // Synchronize Player Position
        try pkt.writeByte(0x3C);

        var x: f64 = 16;
        var y: f64 = 300;
        var z: f64 = 0;
        var yaw: f32 = 0;
        var pitch: f32 = 0;

        var flags: u8 = 0x1 | 0x2 | 0x4 | 0x8 | 0x10;

        try pkt.writeAll(&std.mem.toBytes(std.mem.nativeToBig(u64, @as(u64, @bitCast(x)))));
        try pkt.writeAll(&std.mem.toBytes(std.mem.nativeToBig(u64, @as(u64, @bitCast(y)))));
        try pkt.writeAll(&std.mem.toBytes(std.mem.nativeToBig(u64, @as(u64, @bitCast(z)))));

        try pkt.writeAll(&std.mem.toBytes(std.mem.nativeToBig(u32, @as(u32, @bitCast(yaw)))));
        try pkt.writeAll(&std.mem.toBytes(std.mem.nativeToBig(u32, @as(u32, @bitCast(pitch)))));

        try pkt.writeByte(flags);
        try pkt.writeByte(0);

        try pkt_builder.finish();

        try pkt_builder.enqueue(packet_queue);
    }

    pub fn move(self: *Server, player_id: usize, packet_queue: *std.atomic.Queue([]u8), pos: packets.Pos) !void {
        const player_ptr = &self.players.items[player_id];

        // todo send centre chunk only if necessary
        const arena_allocator = self.arena.allocator();

        var lenbuf: [5]u8 = undefined;
        var cx: i32 = @intFromFloat(std.math.floor(pos.x / 16));
        var cy: i32 = @intFromFloat(std.math.floor(pos.y / 16));
        _ = cy;
        var cz: i32 = @intFromFloat(std.math.floor(pos.z / 16));

        var ocx: i32 = @intFromFloat(std.math.floor(player_ptr.pos.x / 16));
        var ocy: i32 = @intFromFloat(std.math.floor(player_ptr.pos.y / 16));
        _ = ocy;
        var ocz: i32 = @intFromFloat(std.math.floor(player_ptr.pos.z / 16));

        player_ptr.pos = .{ .x = pos.x, .y = pos.y, .z = pos.z };

        if (ocx != cx or ocz != cz) {
            var pkt_builder = packet_builder.PacketBuilder{ .arena_allocator = arena_allocator, .allocator = self.allocator };
            errdefer pkt_builder.deinit();
            var pkt = pkt_builder.writer();

            var timer = try std.time.Timer.start();
            for (self.chunks) |chunk| {
                try pkt.writeByte(0x24); // packet id
                std.debug.print("x{d}", .{chunk.xPos});
                try pkt.writeIntBig(u32, @as(u32, @intCast(chunk.xPos)));
                try pkt.writeIntBig(u32, @as(u32, @intCast(chunk.zPos)));
                try pkt.writeAll(heightmap);

                var datapkt = std.ArrayListUnmanaged(u8){};
                for (0..24) |i| {
                    try datapkt.appendSlice(arena_allocator, &[_]u8{ 0x7f, 0xff }); // "non air blocks"

                    const chunk_states = chunk.sections[i].block_states;
                    try paletted_container.serializePaletted(datapkt.writer(arena_allocator), self.states, chunk_states);

                    try datapkt.append(arena_allocator, 0); // palette - bits per entry
                    try datapkt.append(arena_allocator, 0x01); // idk biome
                    try datapkt.append(arena_allocator, 0); // data array length
                }

                try pkt.writeAll(varint.writeVarInt(@intCast(datapkt.items.len), &lenbuf));
                try pkt.writeAll(datapkt.items);

                try pkt.writeByte(0); // block entities

                try pkt.writeByte(0); // sky light mask
                try pkt.writeByte(0); // block sky light mask
                try pkt.writeByte(0); // empty sky light mask
                try pkt.writeByte(0); // empty block light mask
                try pkt.writeByte(0); // sky light array count
                try pkt.writeByte(0); // block light array count

                try pkt_builder.finish();
            }
            std.log.info("chunks in {d}μs", .{timer.read() / 1000});

            try pkt.writeByte(0x4E);
            try pkt.writeAll(varint.writeVarInt(@bitCast(cx), &lenbuf));
            try pkt.writeAll(varint.writeVarInt(@bitCast(cz), &lenbuf));
            try pkt_builder.finish();

            try pkt_builder.enqueue(packet_queue);
        }
    }
};

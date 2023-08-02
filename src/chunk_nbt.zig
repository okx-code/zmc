const std = @import("std");

pub const Chunk_NBT = struct {
    DataVersion: i32,
    xPos: i32,
    zPos: i32,
    yPos: i32,
    Status: []u8,
    LastUpdate: i64,
    sections: []Section_NBT,
    //block_entities
    //CarvingMasks
    Heightmaps: Heightmaps_NBT,
    //Lights
    //Entities
    //fluid_ticks
    //block_ticks
    //InhabitedTime
    //PostProcessing
    //structures
};

pub const Section_NBT = struct {
    Y: i8,
    block_states: BlockStates_NBT,
    //biomes:
    BlockLight: ?[2048]u8,
    SkyLight: ?[2048]u8,
};

//pub const @"minecraft:acacia_door" = struct {
//    facing: enum { north, south, west, east },
//    half: enum { upper, lower },
//    hinge: enum { left, right },
//    open: enum { true, false },
//    powered: enum { true, false },
//
//    pub fn state(self: @This()) u31 {
//        if (self.facing == .north and self.half == .upper and self.hinge == .left and self.open == .true and self.powered == .true) return 11873;
//        if (self.facing == .north and self.half == .upper and self.hinge == .left and self.open == .true and self.powered == .false) return 11874;
//    }
//};

pub const BlockStates_NBT = struct {
    palette: []Block_NBT,
    data: ?[]i64,
};

pub const Block_NBT = struct {
    Name: []u8,
    Properties: ?std.StringHashMapUnmanaged([]const u8),

    pub fn format(value: Block_NBT, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = options;
        _ = fmt;
        try writer.writeAll(value.Name);
        if (value.Properties) |properties| {
            var it = properties.iterator();
            while (it.next()) |i| {
                try writer.writeAll(";");
                try writer.writeAll(i.key_ptr.*);
                try writer.writeAll("=");
                try writer.writeAll(i.value_ptr.*);
            }
        }
    }
};

pub const Heightmaps_NBT = struct {
    MOTION_BLOCKING: [37]i64,
    MOTION_BLOCKING_NO_LEAVES: [37]i64,
    OCEAN_FLOOR: [37]i64,
    //OCEAN_FLOOR_WG: ?[37]i64,
    WORLD_SURFACE: [37]i64,
    //WORLD_SURFACE_WG: ?[37]i64,
};

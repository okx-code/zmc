const chunk_nbt = @import("chunk_nbt.zig");
const Server = @import("server.zig").Server;

pub const World = struct {
    chunks: []chunk_nbt.Chunk_NBT = undefined,

    pub fn tick(self: World, server: Server) !void {
        _ = server;
        _ = self;
    }
};

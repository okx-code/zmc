const std = @import("std");

pub const BlockStates = std.StringArrayHashMapUnmanaged(BlockState);

pub const BlockState = struct {
    properties: std.StringArrayHashMapUnmanaged([][]const u8),
    states: []State,
};

pub const State = struct {
    id: u31,
    default: bool = false,
    properties: std.StringArrayHashMapUnmanaged([]const u8),
};

pub fn parse(allocator: std.mem.Allocator, arena_allocator: std.mem.Allocator, json: []const u8) !BlockStates {
    const dynamic = try std.json.parseFromSliceLeaky(std.json.Value, arena_allocator, json, .{});

    var states = std.StringArrayHashMapUnmanaged(BlockState){};
    var it = dynamic.object.iterator();
    while (it.next()) |kv| {
        var jvalue = kv.value_ptr.*.object;

        var properties_map = std.StringArrayHashMapUnmanaged([][]const u8){};

        var properties_opt = jvalue.get("properties");
        if (properties_opt) |properties| {
            var pit = properties.object.iterator();
            while (pit.next()) |pkv| {
                var array: std.ArrayList(std.json.Value) = pkv.value_ptr.*.array;
                var str_array = try allocator.alloc([]const u8, array.items.len);

                for (array.items, 0..) |item, i| {
                    str_array[i] = try allocator.dupe(u8, item.string);
                }

                try properties_map.put(allocator, try allocator.dupe(u8, pkv.key_ptr.*), str_array);
            }
        }

        var states_opt = jvalue.get("states");
        if (states_opt == null) return error.InvalidBlockState;

        var block_states = states_opt.?.array;
        var block_states_list = try allocator.alloc(State, block_states.items.len);
        for (block_states.items, 0..) |block_state, i| {
            var block_state_object = block_state.object;

            var id_opt = block_state_object.get("id");
            var default_opt = block_state_object.get("default");
            var state_properties_opt = block_state_object.get("properties");

            if (id_opt == null) return error.InvalidBlockState;

            var state_properties_map = std.StringArrayHashMapUnmanaged([]const u8){};
            if (state_properties_opt) |state_properties| {
                var spit = state_properties.object.iterator();
                while (spit.next()) |spkv| {
                    try state_properties_map.put(allocator, try allocator.dupe(u8, spkv.key_ptr.*), try allocator.dupe(u8, spkv.value_ptr.*.string));
                }
            }

            var default = if (default_opt) |d| d.bool else false;

            block_states_list[i] = .{ .id = @intCast(id_opt.?.integer), .default = default, .properties = state_properties_map };
        }

        try states.put(allocator, try allocator.dupe(u8, kv.key_ptr.*), .{ .properties = properties_map, .states = block_states_list });
    }
    return states;
}

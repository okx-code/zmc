const std = @import("std");

const TAG = enum(u8) {
    End = 0,
    Byte = 1,
    Short = 2,
    Int = 3,
    Long = 4,
    Float = 5,
    Double = 6,
    Byte_Array = 7,
    String = 8,
    List = 9,
    Compound = 10,
    Int_Array = 11,
    Long_Array = 12,
};

const NbtError = error{
    RootTag,
    InvalidTag,
    InvalidType,
    InvalidSize,
    DuplicateField,
    FieldNotPresent,
    InvalidField,
};

const NbtAllErrors = NbtError || std.mem.Allocator.Error || error{EndOfStream};

/// Caller is responsible for freeing all slices that are members of this struct.
pub fn parse(comptime T: type, allocator: std.mem.Allocator, s: []const u8) !T {
    var stream = std.io.fixedBufferStream(s);
    var reader = stream.reader();

    const compound = try reader.readByte();
    if (compound != @intFromEnum(TAG.Compound)) return error.NBT;

    const len = try reader.readIntBig(u16);
    // root tag is usually empty, so this is not really necessary, but just for consistency
    stream.pos += len;

    return readCompound(T, allocator, &stream);
}

fn readCompound(comptime T: type, allocator: std.mem.Allocator, stream: *std.io.FixedBufferStream([]const u8)) !T {
    var value: T = undefined;

    var reader = stream.reader();

    if (T == void) { // void means "just skip over the tag, we don't care about the contents"
        while (true) {
            const tag = try getTag(try reader.readIntBig(u8));
            if (tag == .End) {
                break;
            }
            const len = try reader.readIntBig(u16);
            stream.pos += len;
            _ = try parseTag(void, tag, allocator, stream);
        }
        return;
    } else if (comptime std.mem.startsWith(u8, @typeName(T), "hash_map.HashMap")) { // dynamic compound keys
        var map = std.StringHashMapUnmanaged([]const u8){};
        while (true) {
            const tag = try getTag(try reader.readIntBig(u8));
            if (tag == .End) {
                break;
            }
            const len = try reader.readIntBig(u16);
            const name = stream.buffer[stream.pos .. stream.pos + len];
            stream.pos += len;

            try map.put(allocator, try allocator.dupe(u8, name), try parseTag([]u8, tag, allocator, stream));
        }
        return map;
    }

    comptime var typeInfo = @typeInfo(T);
    if (typeInfo != .Struct) return error.InvalidType;

    const structInfo: std.builtin.Type.Struct = typeInfo.Struct;
    var fields_seen = [_]bool{false} ** structInfo.fields.len;
    while (true) {
        const tag = try getTag(try reader.readIntBig(u8));
        if (tag == .End) {
            break;
        }

        const len = try reader.readIntBig(u16);
        const name = stream.buffer[stream.pos .. stream.pos + len];
        stream.pos += len;

        inline for (structInfo.fields, 0..) |field, i| {
            if (field.is_comptime) @compileError("comptime fields are not supported: " ++ @typeName(T) ++ "." ++ field.name);
            if (std.mem.eql(u8, field.name, name)) {
                if (fields_seen[i]) return error.DuplicateField;

                const fieldType = if (@typeInfo(field.type) == .Optional)
                    @typeInfo(field.type).Optional.child
                else
                    field.type;

                @field(value, field.name) = try parseTag(fieldType, tag, allocator, stream);
                fields_seen[i] = true;
                break;
            }
        } else {
            _ = try parseTag(void, tag, allocator, stream);
        }
    }

    inline for (fields_seen, 0..) |field, i| {
        if (!field) {
            if (@typeInfo(structInfo.fields[i].type) == .Optional) {
                @field(value, structInfo.fields[i].name) = null;
            } else {
                std.debug.print("missing field {s} in struct {any}\n", .{ std.fmt.comptimePrint("{s}", .{structInfo.fields[i].name}), T });
                return error.FieldNotPresent;
            }
        }
    }

    return value;
}

fn readList(comptime T: type, allocator: std.mem.Allocator, stream: *std.io.FixedBufferStream([]const u8)) !T {
    const reader = stream.reader();
    const tag = try getTag(try reader.readIntBig(u8));
    const length = try reader.readIntBig(i32);
    if (length < 0) return error.InvalidSize;

    if (T == void) {
        for (0..@intCast(length)) |_| {
            _ = try parseTag(void, tag, allocator, stream);
        }
        return;
    }

    comptime var child: type = undefined;
    var list: T = switch (@typeInfo(T)) {
        .Pointer => |ptrInfo| blk: {
            if (ptrInfo.size == .Slice) {
                child = ptrInfo.child;
                break :blk try allocator.alloc(ptrInfo.child, @intCast(length));
            } else {
                return error.InvalidField;
            }
        },
        .Array => |arrayInfo| blk: {
            child = arrayInfo.child;
            break :blk undefined;
        },
        else => return error.InvalidType,
    };

    if (list.len != length) return error.InvalidField;

    for (0..@intCast(length)) |i| {
        list[i] = try parseTag(child, tag, allocator, stream);
    }

    return list;
}

fn getTag(tag: u8) !TAG {
    if (tag >= 13) return error.InvalidTag;
    return @enumFromInt(tag);
}

fn parseTag(comptime T: type, tag: TAG, allocator: std.mem.Allocator, stream: *std.io.FixedBufferStream([]const u8)) NbtAllErrors!T {
    return switch (tag) {
        .End => return error.InvalidTag,
        .Byte => try int(T, i8, stream),
        .Short => try int(T, i16, stream),
        .Int => try int(T, i32, stream),
        .Long => try int(T, i64, stream),
        .Float => {
            if (@typeInfo(T) != .Float) return error.InvalidType;
            const value = try int(T, i32, stream);
            if (T == void) {
                return;
            } else {
                return @as(f32, @bitCast(value));
            }
        },
        .Double => {
            if (@typeInfo(T) != .Float) return error.InvalidType;
            const value = try int(T, i64, stream);
            if (T == void) {
                return;
            } else {
                return @as(f64, @bitCast(value));
            }
        },
        .Byte_Array => try array(T, i32, u8, allocator, stream),
        .String => try array(T, u16, u8, allocator, stream),
        .List => try readList(T, allocator, stream),
        .Compound => try readCompound(T, allocator, stream),
        .Int_Array => try array(T, i32, i32, allocator, stream),
        .Long_Array => try array(T, i32, i64, allocator, stream),
    };
}

fn int(comptime T: type, comptime Int: type, stream: *std.io.FixedBufferStream([]const u8)) !T {
    try comptime is_compatible(T, Int);

    const value = try stream.reader().readIntBig(Int);
    if (T == void) {
        return;
    } else {
        return value;
    }
}

fn is_compatible(comptime To: type, comptime From: type) !void {
    const to_type = @typeInfo(To);
    const from_type = @typeInfo(From);

    if (to_type == .Int) {
        if (from_type != .Int) return error.InvalidType;
        if (from_type.Int.bits > to_type.Int.bits) return error.InvalidType;
        if (from_type.Int.signedness != to_type.Int.signedness) return error.InvalidType;
    } else if (to_type == .Float) {
        if (from_type != .Float) return error.InvalidType;
        if (from_type.Float.bits > to_type.Float.bits) return error.InvalidType;
        if (from_type.Int.signedness != to_type.Int.signedness) return error.InvalidType;
    } else if (to_type != .Void) {
        return error.InvalidType;
    }
}

fn array(comptime T: type, comptime Size: type, comptime Value: type, allocator: std.mem.Allocator, stream: *std.io.FixedBufferStream([]const u8)) !T {
    const length = try stream.reader().readIntBig(Size);
    if (length < 0) return error.InvalidSize;

    if (T == void) {
        stream.pos += @as(usize, @intCast(length)) * (@typeInfo(Value).Int.bits / 8);
        return;
    }

    comptime var child: type = undefined;
    var list: T = switch (@typeInfo(T)) {
        .Pointer => |ptrInfo| blk: {
            if (ptrInfo.size == .Slice) {
                child = ptrInfo.child;
                break :blk try allocator.alloc(child, @intCast(length));
            } else {
                return error.InvalidField;
            }
        },
        .Array => |arrayInfo| blk: {
            child = arrayInfo.child;
            // todo fix this
            break :blk [_]child{0} ** arrayInfo.len;
        },
        else => return error.InvalidType,
    };

    try comptime is_compatible(child, Value);

    var reader = stream.reader();
    for (0..list.len) |i| {
        list[i] = try reader.readIntBig(Value);
    }

    return list;
}

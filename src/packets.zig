const std = @import("std");

pub const ServerboundPacket = struct {
    player: usize,
    queue: *std.atomic.Queue([]u8),
    type: ServerboundPacketType,
};

pub const ServerboundPacketType = union(enum) {
    Play: void,
    Pos: Pos,
    Rot: Rot,
    PosRot: PosRot,
};

pub const Pos = struct {
    x: f64,
    y: f64,
    z: f64,
};

pub const Rot = struct {
    yaw: f32,
    pitch: f32,
};

pub const PosRot = struct {
    pos: Pos,
    rot: Rot,
};

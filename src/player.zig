pub const Vec3 = struct {
    x: f64,
    y: f64,
    z: f64,
};

pub const Player = struct {
    pos: Vec3,
    sent_pos: Vec3,
};

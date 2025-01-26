const std = @import("std");
const mem = std.mem;
const crypto = std.crypto;

/// Salsa20 Constants
const sigma = "expand 32-byte k".*;
const tau = "expand 16-byte k".*;

/// Core Salsa20/HSalsa20 implementation
fn core(
    out: []u8,
    input: []const u8,
    key: []const u8,
    constant: []const u8,
    comptime h: bool, // true for HSalsa20
) void {
    std.debug.assert(input.len == 16);
    std.debug.assert(key.len == 32);
    std.debug.assert(constant.len == 16);
    std.debug.assert(out.len == if (h) 32 else 64);

    var state: [16]u32 = undefined;

    // Initialize state
    state[0] = std.mem.readInt(u32, constant[0..4], .little);
    state[5] = std.mem.readInt(u32, constant[4..8], .little);
    state[10] = std.mem.readInt(u32, constant[8..12], .little);
    state[15] = std.mem.readInt(u32, constant[12..16], .little);

    state[1] = std.mem.readInt(u32, key[0..4], .little);
    state[2] = std.mem.readInt(u32, key[4..8], .little);
    state[3] = std.mem.readInt(u32, key[8..12], .little);
    state[4] = std.mem.readInt(u32, key[12..16], .little);

    state[11] = std.mem.readInt(u32, key[16..20], .little);
    state[12] = std.mem.readInt(u32, key[20..24], .little);
    state[13] = std.mem.readInt(u32, key[24..28], .little);
    state[14] = std.mem.readInt(u32, key[28..32], .little);

    state[6] = std.mem.readInt(u32, input[0..4], .little);
    state[7] = std.mem.readInt(u32, input[4..8], .little);
    state[8] = std.mem.readInt(u32, input[8..12], .little);
    state[9] = std.mem.readInt(u32, input[12..16], .little);

    var working_state = state;

    // Salsa20 rounds
    comptime var rounds = 20;
    inline while (rounds > 0) : (rounds -= 2) {
        // Column rounds
        inline for ([4]usize{ 0, 4, 8, 12 }) |i| {
            working_state[i + 0] ^= std.math.rotl(u32, working_state[i + 1] +% working_state[i + 3], 7);
            working_state[i + 2] ^= std.math.rotl(u32, working_state[i + 0] +% working_state[i + 1], 9);
            working_state[i + 1] ^= std.math.rotl(u32, working_state[i + 2] +% working_state[i + 0], 13);
            working_state[i + 3] ^= std.math.rotl(u32, working_state[i + 1] +% working_state[i + 2], 18);
        }

        // Row rounds
        inline for ([4]usize{ 0, 1, 2, 3 }) |i| {
            const j = i * 4;
            working_state[j] ^= std.math.rotl(u32, working_state[(j + 1) % 16] +% working_state[(j + 3) % 16], 7);
            working_state[(j + 2) % 16] ^= std.math.rotl(u32, working_state[j] +% working_state[(j + 1) % 16], 9);
            working_state[(j + 1) % 16] ^= std.math.rotl(u32, working_state[(j + 2) % 16] +% working_state[j], 13);
            working_state[(j + 3) % 16] ^= std.math.rotl(u32, working_state[(j + 1) % 16] +% working_state[(j + 2) % 16], 18);
        }
    }

    // Final addition
    if (h) {
        // HSalsa20 output
        std.mem.writeInt(u32, out[0..4], working_state[0], .little);
        std.mem.writeInt(u32, out[4..8], working_state[5], .little);
        std.mem.writeInt(u32, out[8..12], working_state[10], .little);
        std.mem.writeInt(u32, out[12..16], working_state[15], .little);
        std.mem.writeInt(u32, out[16..20], working_state[6], .little);
        std.mem.writeInt(u32, out[20..24], working_state[7], .little);
        std.mem.writeInt(u32, out[24..28], working_state[8], .little);
        std.mem.writeInt(u32, out[28..32], working_state[9], .little);
    } else {
        // Salsa20 output
        for (0..16) |i| {
            const val = state[i] +% working_state[i];
            const bytes = @as(*[4]u8, @ptrCast(out[i * 4 .. i * 4 + 4]));
            std.mem.writeInt(u32, bytes, val, .little);
        }
    }
}

/// Public Salsa20 Core Function
pub fn salsa20(out: []u8, input: []const u8, key: []const u8) void {
    core(out, input, key, &sigma, false);
}

/// Public HSalsa20 Core Function
pub fn hsalsa20(out: []u8, input: []const u8, key: []const u8) void {
    core(out, input, key, &sigma, true);
}

test "Salsa20 Core Test Vector" {
    const key = [_]u8{0} ** 32;
    const input = [_]u8{0} ** 16;
    var out: [64]u8 = undefined;

    salsa20(&out, &input, &key);

    const expected = "9A97F65B9B4C721B960A672145FCA8D4E32E67F911461E3BE6B445ECF0806B5".*;
    try std.testing.expectEqualSlices(u8, &expected, out[0..32]);
}

test "HSalsa20 Test Vector" {
    const key = [_]u8{0} ** 32;
    const input = [_]u8{0} ** 16;
    var out: [32]u8 = undefined;

    hsalsa20(&out, &input, &key);

    const expected = "1B27556473E985D462CD51197A9A46C76009549EAC6474F206C4EE0844F68389".*;
    try std.testing.expectEqualSlices(u8, &expected, &out);
}

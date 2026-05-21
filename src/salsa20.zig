//! Salsa20 / HSalsa20 core permutation and the Salsa20 stream cipher.
//!
//! These are low-level building blocks: the stream cipher provides
//! confidentiality only. For authenticated encryption use `secretbox`.
const std = @import("std");

/// Salsa20 constant for a 256-bit key: the ASCII bytes of "expand 32-byte k".
const sigma = [16]u8{
    'e', 'x', 'p', 'a', 'n', 'd', ' ', '3',
    '2', '-', 'b', 'y', 't', 'e', ' ', 'k',
};

/// One Salsa20 quarter-round, applied in place to four words of the state.
///
/// `quarterround(y0,y1,y2,y3)` per the Salsa20 specification:
///   z1 = y1 ^ (y0 + y3) <<< 7
///   z2 = y2 ^ (z1 + y0) <<< 9
///   z3 = y3 ^ (z2 + z1) <<< 13
///   z0 = y0 ^ (z3 + z2) <<< 18
inline fn quarterRound(x: *[16]u32, a: usize, b: usize, c: usize, d: usize) void {
    x[b] ^= std.math.rotl(u32, x[a] +% x[d], 7);
    x[c] ^= std.math.rotl(u32, x[b] +% x[a], 9);
    x[d] ^= std.math.rotl(u32, x[c] +% x[b], 13);
    x[a] ^= std.math.rotl(u32, x[d] +% x[c], 18);
}

/// Builds the initial 16-word Salsa20 state from the constant, the 32-byte key
/// and the 16-byte input block (8-byte nonce ++ 8-byte counter).
fn initState(input: *const [16]u8, key: *const [32]u8) [16]u32 {
    var s: [16]u32 = undefined;
    s[0] = std.mem.readInt(u32, sigma[0..4], .little);
    s[5] = std.mem.readInt(u32, sigma[4..8], .little);
    s[10] = std.mem.readInt(u32, sigma[8..12], .little);
    s[15] = std.mem.readInt(u32, sigma[12..16], .little);

    s[1] = std.mem.readInt(u32, key[0..4], .little);
    s[2] = std.mem.readInt(u32, key[4..8], .little);
    s[3] = std.mem.readInt(u32, key[8..12], .little);
    s[4] = std.mem.readInt(u32, key[12..16], .little);
    s[11] = std.mem.readInt(u32, key[16..20], .little);
    s[12] = std.mem.readInt(u32, key[20..24], .little);
    s[13] = std.mem.readInt(u32, key[24..28], .little);
    s[14] = std.mem.readInt(u32, key[28..32], .little);

    s[6] = std.mem.readInt(u32, input[0..4], .little);
    s[7] = std.mem.readInt(u32, input[4..8], .little);
    s[8] = std.mem.readInt(u32, input[8..12], .little);
    s[9] = std.mem.readInt(u32, input[12..16], .little);
    return s;
}

/// Applies the 20-round Salsa20 permutation (10 column/row double-rounds) to
/// the working state in place.
fn permute(x: *[16]u32) void {
    var round: usize = 0;
    while (round < 10) : (round += 1) {
        // Column round.
        quarterRound(x, 0, 4, 8, 12);
        quarterRound(x, 5, 9, 13, 1);
        quarterRound(x, 10, 14, 2, 6);
        quarterRound(x, 15, 3, 7, 11);
        // Row round.
        quarterRound(x, 0, 1, 2, 3);
        quarterRound(x, 5, 6, 7, 4);
        quarterRound(x, 10, 11, 8, 9);
        quarterRound(x, 15, 12, 13, 14);
    }
}

/// Salsa20 core: produces one 64-byte keystream block from the 16-byte input
/// block (8-byte nonce ++ 8-byte counter) and the 32-byte key.
pub fn core(out: *[64]u8, input: *const [16]u8, key: *const [32]u8) void {
    const state = initState(input, key);
    var x = state;
    permute(&x);
    for (0..16) |i| {
        std.mem.writeInt(u32, out[i * 4 ..][0..4], x[i] +% state[i], .little);
    }
}

/// HSalsa20 core: derives a 32-byte subkey. Used by XSalsa20 to extend Salsa20
/// to a 24-byte nonce.
pub fn hsalsa20(out: *[32]u8, input: *const [16]u8, key: *const [32]u8) void {
    var x = initState(input, key);
    permute(&x);
    const words = [8]u32{ x[0], x[5], x[10], x[15], x[6], x[7], x[8], x[9] };
    for (words, 0..) |w, i| {
        std.mem.writeInt(u32, out[i * 4 ..][0..4], w, .little);
    }
}

/// Salsa20 stream cipher: XORs `msg` with the keystream produced from an
/// 8-byte nonce and a 32-byte key, writing `msg.len` bytes to `out`.
///
/// The same call decrypts. Provides confidentiality only — no authentication.
pub fn stream(out: []u8, msg: []const u8, nonce: *const [8]u8, key: *const [32]u8) void {
    std.debug.assert(out.len == msg.len);

    // Salsa20 input block: 8-byte nonce ++ 64-bit little-endian block counter.
    var input: [16]u8 = undefined;
    @memcpy(input[0..8], nonce);
    @memset(input[8..16], 0);

    var block: [64]u8 = undefined;
    var offset: usize = 0;
    while (offset < msg.len) : (offset += 64) {
        core(&block, &input, key);
        const n = @min(@as(usize, 64), msg.len - offset);
        for (0..n) |i| {
            out[offset + i] = msg[offset + i] ^ block[i];
        }
        // Advance the block counter (wrapping; messages never reach 2^64 blocks).
        const counter = std.mem.readInt(u64, input[8..16], .little);
        std.mem.writeInt(u64, input[8..16], counter +% 1, .little);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "HSalsa20 known-answer vector (NaCl tests/core1.c)" {
    // NaCl's HSalsa20 test: a fixed 32-byte key and an all-zero 16-byte input.
    const key = [32]u8{
        0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1,
        0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35, 0x0f, 0x25,
        0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33,
        0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16, 0x17, 0x42,
    };
    const input = [_]u8{0} ** 16;
    var out: [32]u8 = undefined;
    hsalsa20(&out, &input, &key);

    const expected = [32]u8{
        0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85, 0xd4,
        0x62, 0xcd, 0x51, 0x19, 0x7a, 0x9a, 0x46, 0xc7,
        0x60, 0x09, 0x54, 0x9e, 0xac, 0x64, 0x74, 0xf2,
        0x06, 0xc4, 0xee, 0x08, 0x44, 0xf6, 0x83, 0x89,
    };
    try testing.expectEqualSlices(u8, &expected, &out);
}

test "Salsa20 core equals the first keystream block" {
    var prng = std.Random.DefaultPrng.init(0x5a15a20c0123abcd);
    const rand = prng.random();
    var key: [32]u8 = undefined;
    var nonce: [8]u8 = undefined;
    rand.bytes(&key);
    rand.bytes(&nonce);

    var input: [16]u8 = undefined;
    @memcpy(input[0..8], &nonce);
    @memset(input[8..16], 0);
    var block: [64]u8 = undefined;
    core(&block, &input, &key);

    const zeros = [_]u8{0} ** 64;
    var keystream: [64]u8 = undefined;
    stream(&keystream, &zeros, &nonce, &key);

    try testing.expectEqualSlices(u8, &keystream, &block);
}

test "Salsa20 stream matches std.crypto across sizes (incl. multi-block)" {
    var prng = std.Random.DefaultPrng.init(0xabcdef0123456789);
    const rand = prng.random();
    const sizes = [_]usize{ 0, 1, 31, 63, 64, 65, 127, 128, 200, 1000 };
    for (sizes) |len| {
        var iter: usize = 0;
        while (iter < 32) : (iter += 1) {
            var key: [32]u8 = undefined;
            var nonce: [8]u8 = undefined;
            var msg: [1000]u8 = undefined;
            rand.bytes(&key);
            rand.bytes(&nonce);
            rand.bytes(msg[0..len]);

            var mine: [1000]u8 = undefined;
            var reference: [1000]u8 = undefined;
            stream(mine[0..len], msg[0..len], &nonce, &key);
            std.crypto.stream.salsa.Salsa20.xor(reference[0..len], msg[0..len], 0, key, nonce);
            try testing.expectEqualSlices(u8, reference[0..len], mine[0..len]);
        }
    }
}

test "Salsa20 stream round-trips" {
    var prng = std.Random.DefaultPrng.init(0x0011223344556677);
    const rand = prng.random();
    var key: [32]u8 = undefined;
    var nonce: [8]u8 = undefined;
    var msg: [333]u8 = undefined;
    rand.bytes(&key);
    rand.bytes(&nonce);
    rand.bytes(&msg);

    var ciphertext: [333]u8 = undefined;
    var plaintext: [333]u8 = undefined;
    stream(&ciphertext, &msg, &nonce, &key);
    stream(&plaintext, &ciphertext, &nonce, &key);
    try testing.expectEqualSlices(u8, &msg, &plaintext);
}

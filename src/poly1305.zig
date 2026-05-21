//! Poly1305 one-time message authenticator.
//!
//! Low-level building block. The authentication key is **one-time**: a given
//! 32-byte key must never authenticate more than one message. `secretbox` will
//! derive a fresh Poly1305 key per message from XSalsa20.
//!
//! This is a faithful port of TweetNaCl's `crypto_onetimeauth`, which evaluates
//! the polynomial modulo 2^130-5 using 17 base-256 limbs.
const std = @import("std");

/// Length of an authentication tag, in bytes.
pub const tag_length = 16;
/// Length of a Poly1305 key, in bytes.
pub const key_length = 32;

/// Carry constant for the final reduction (2^130-5 represented over 17 limbs,
/// negated).
const minusp = [17]u32{
    5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 252,
};

/// Adds `q` into `p` in place, where both are 17 base-256 limbs.
fn add(p: *[17]u32, q: *const [17]u32) void {
    var u: u32 = 0;
    for (0..17) |i| {
        u +%= p[i] +% q[i];
        p[i] = u & 255;
        u >>= 8;
    }
}

/// Computes the Poly1305 tag of `msg` under `key`, writing 16 bytes to `out`.
pub fn auth(out: *[tag_length]u8, msg: []const u8, key: *const [key_length]u8) void {
    var r = [_]u32{0} ** 17;
    var h = [_]u32{0} ** 17;
    var c: [17]u32 = undefined;
    var g: [17]u32 = undefined;
    var x: [17]u32 = undefined;
    // `r` and `h` carry key-derived secret state; wipe them on the way out.
    defer std.crypto.secureZero(u32, &r);
    defer std.crypto.secureZero(u32, &h);
    defer std.crypto.secureZero(u32, &c);
    defer std.crypto.secureZero(u32, &g);
    defer std.crypto.secureZero(u32, &x);

    // Load and clamp `r` (the first half of the key).
    for (0..16) |j| r[j] = key[j];
    r[3] &= 15;
    r[4] &= 252;
    r[7] &= 15;
    r[8] &= 252;
    r[11] &= 15;
    r[12] &= 252;
    r[15] &= 15;

    // Accumulate one 16-byte block at a time.
    var m = msg;
    while (m.len > 0) {
        @memset(&c, 0);
        var j: usize = 0;
        while (j < 16 and j < m.len) : (j += 1) c[j] = m[j];
        c[j] = 1; // high bit marking the end of the block
        m = m[j..];

        add(&h, &c);

        // h = (h * r) mod 2^130-5, schoolbook multiply over 17 limbs.
        for (0..17) |i| {
            x[i] = 0;
            for (0..17) |k| {
                x[i] +%= h[k] *% (if (k <= i) r[i - k] else 320 *% r[i + 17 - k]);
            }
        }
        h = x;

        // Carry-propagate, then fold the overflow above bit 130 back in (*5).
        var u: u32 = 0;
        for (0..16) |j2| {
            u +%= h[j2];
            h[j2] = u & 255;
            u >>= 8;
        }
        u +%= h[16];
        h[16] = u & 3;
        u = 5 *% (u >> 2);
        for (0..16) |j2| {
            u +%= h[j2];
            h[j2] = u & 255;
            u >>= 8;
        }
        u +%= h[16];
        h[16] = u;
    }

    // Final reduction: conditionally subtract p, in constant time.
    g = h;
    add(&h, &minusp);
    const mask: u32 = 0 -% (h[16] >> 7); // all-ones if the subtraction borrowed
    for (0..17) |j| h[j] ^= mask & (g[j] ^ h[j]);

    // Add `s` (the second half of the key) and emit the low 128 bits.
    for (0..16) |j| c[j] = key[j + 16];
    c[16] = 0;
    add(&h, &c);
    for (0..16) |j| out[j] = @truncate(h[j]);
}

/// Verifies a Poly1305 `tag` against `msg` and `key` in constant time.
pub fn verify(
    tag: *const [tag_length]u8,
    msg: []const u8,
    key: *const [key_length]u8,
) error{AuthFailed}!void {
    var computed: [tag_length]u8 = undefined;
    auth(&computed, msg, key);
    if (!std.crypto.timing_safe.eql([tag_length]u8, computed, tag.*)) {
        return error.AuthFailed;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "Poly1305 known-answer vector (RFC 8439 section 2.5.2)" {
    const key = [32]u8{
        0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
        0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
        0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
        0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b,
    };
    const msg = "Cryptographic Forum Research Group";
    const expected = [16]u8{
        0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6,
        0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9,
    };

    var tag: [16]u8 = undefined;
    auth(&tag, msg, &key);
    try testing.expectEqualSlices(u8, &expected, &tag);
    try verify(&expected, msg, &key);
}

test "Poly1305 matches std.crypto across sizes" {
    var prng = std.Random.DefaultPrng.init(0x901305c0ffee1234);
    const rand = prng.random();
    const sizes = [_]usize{ 0, 1, 15, 16, 17, 31, 32, 33, 64, 256, 1000 };
    for (sizes) |len| {
        var iter: usize = 0;
        while (iter < 32) : (iter += 1) {
            var key: [32]u8 = undefined;
            var msg: [1000]u8 = undefined;
            rand.bytes(&key);
            rand.bytes(msg[0..len]);

            var mine: [16]u8 = undefined;
            var reference: [16]u8 = undefined;
            auth(&mine, msg[0..len], &key);
            std.crypto.onetimeauth.Poly1305.create(&reference, msg[0..len], &key);
            try testing.expectEqualSlices(u8, &reference, &mine);
        }
    }
}

test "Poly1305 verify rejects tampered message, tag and key" {
    var prng = std.Random.DefaultPrng.init(0x0011223344556677);
    const rand = prng.random();
    var key: [32]u8 = undefined;
    var msg: [128]u8 = undefined;
    rand.bytes(&key);
    rand.bytes(&msg);

    var tag: [16]u8 = undefined;
    auth(&tag, &msg, &key);
    try verify(&tag, &msg, &key); // genuine tag verifies

    var tampered_msg = msg;
    tampered_msg[40] ^= 0x01;
    try testing.expectError(error.AuthFailed, verify(&tag, &tampered_msg, &key));

    var tampered_tag = tag;
    tampered_tag[7] ^= 0x80;
    try testing.expectError(error.AuthFailed, verify(&tampered_tag, &msg, &key));

    var wrong_key = key;
    wrong_key[0] ^= 0x01;
    try testing.expectError(error.AuthFailed, verify(&tag, &msg, &wrong_key));
}

//! hash — SHA-512.
//!
//! This is NaCl's `crypto_hash`: a faithful port of TweetNaCl's SHA-512,
//! presented in the canonical FIPS 180-4 form (a full 80-word message
//! schedule rather than TweetNaCl's rolling 16-word window — same output,
//! easier to audit against the spec).
//!
//! SHA-512 takes no key, so there is nothing to verify and no round-trip;
//! `sign` (Ed25519) will compose this primitive. SHA-512 is defined over
//! big-endian words, the one place this project departs from its otherwise
//! little-endian encoding.
const std = @import("std");

/// Length of a SHA-512 digest, in bytes.
pub const digest_length = 64;
/// SHA-512 absorbs the message in 128-byte blocks.
pub const block_length = 128;

/// Round constants: the first 64 bits of the fractional parts of the cube
/// roots of the first 80 primes (FIPS 180-4 §4.2.3).
const k = [80]u64{
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
};

/// Initial hash value: the first 64 bits of the fractional parts of the
/// square roots of the first 8 primes (FIPS 180-4 §5.3.5).
const iv = [8]u64{
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
};

// The six logical functions of FIPS 180-4 §4.1.3.
fn ch(x: u64, y: u64, z: u64) u64 {
    return (x & y) ^ (~x & z);
}
fn maj(x: u64, y: u64, z: u64) u64 {
    return (x & y) ^ (x & z) ^ (y & z);
}
fn bigSigma0(x: u64) u64 {
    return std.math.rotr(u64, x, 28) ^ std.math.rotr(u64, x, 34) ^ std.math.rotr(u64, x, 39);
}
fn bigSigma1(x: u64) u64 {
    return std.math.rotr(u64, x, 14) ^ std.math.rotr(u64, x, 18) ^ std.math.rotr(u64, x, 41);
}
fn smallSigma0(x: u64) u64 {
    return std.math.rotr(u64, x, 1) ^ std.math.rotr(u64, x, 8) ^ (x >> 7);
}
fn smallSigma1(x: u64) u64 {
    return std.math.rotr(u64, x, 19) ^ std.math.rotr(u64, x, 61) ^ (x >> 6);
}

/// Absorbs every whole 128-byte block of `blocks` into the eight-word `state`.
/// Any trailing partial block is ignored — the caller pads it first.
fn hashBlocks(state: *[8]u64, blocks: []const u8) void {
    var w: [80]u64 = undefined;
    var v: [8]u64 = undefined;
    // `w` and `v` are derived from the (possibly secret) message; wipe them.
    defer std.crypto.secureZero(u64, &w);
    defer std.crypto.secureZero(u64, &v);

    var off: usize = 0;
    while (off + block_length <= blocks.len) : (off += block_length) {
        const block = blocks[off..][0..block_length];

        // Message schedule: 16 big-endian words, then 64 more (FIPS 180-4 §6.4.2).
        for (0..16) |i| {
            w[i] = std.mem.readInt(u64, block[i * 8 ..][0..8], .big);
        }
        for (16..80) |i| {
            w[i] = smallSigma1(w[i - 2]) +% w[i - 7] +%
                smallSigma0(w[i - 15]) +% w[i - 16];
        }

        // 80 rounds of compression over the working variables a..h = v[0..8].
        v = state.*;
        for (0..80) |i| {
            const t1 = v[7] +% bigSigma1(v[4]) +% ch(v[4], v[5], v[6]) +% k[i] +% w[i];
            const t2 = bigSigma0(v[0]) +% maj(v[0], v[1], v[2]);
            v[7] = v[6];
            v[6] = v[5];
            v[5] = v[4];
            v[4] = v[3] +% t1;
            v[3] = v[2];
            v[2] = v[1];
            v[1] = v[0];
            v[0] = t1 +% t2;
        }

        for (0..8) |i| state[i] +%= v[i];
    }
}

/// Streaming SHA-512: `init` → one or more `update` → `final`. The one-shot
/// `hash` below is the common case; `sign` uses streaming to hash
/// concatenations like `R || pk || m` without materialising them.
pub const Hasher = struct {
    state: [8]u64,
    /// Buffered tail of the message, smaller than one block.
    buffer: [block_length]u8,
    buffer_len: usize,
    /// Total bytes absorbed so far — used to encode the length on `final`.
    total_bytes: u64,

    pub fn init() Hasher {
        return .{
            .state = iv,
            .buffer = undefined,
            .buffer_len = 0,
            .total_bytes = 0,
        };
    }

    /// Absorbs `msg` into the hash. Any whole 128-byte blocks are processed
    /// in-place; the trailing partial block is buffered for the next call or
    /// for `final`.
    pub fn update(self: *Hasher, msg: []const u8) void {
        self.total_bytes += msg.len;
        var i: usize = 0;
        // Top up the buffer first so the rest can stream whole blocks.
        if (self.buffer_len > 0) {
            const space = block_length - self.buffer_len;
            const take = @min(space, msg.len);
            @memcpy(self.buffer[self.buffer_len..][0..take], msg[0..take]);
            self.buffer_len += take;
            i = take;
            if (self.buffer_len == block_length) {
                hashBlocks(&self.state, &self.buffer);
                self.buffer_len = 0;
            }
        }
        // Absorb every whole block straight from `msg`, leaving any tail.
        const remaining = msg.len - i;
        const whole = remaining - (remaining % block_length);
        if (whole > 0) {
            hashBlocks(&self.state, msg[i..][0..whole]);
            i += whole;
        }
        if (i < msg.len) {
            const tail_len = msg.len - i;
            @memcpy(self.buffer[0..tail_len], msg[i..]);
            self.buffer_len = tail_len;
        }
    }

    /// Pads the tail and emits the digest. The Hasher is left in an
    /// implementation-defined state; call `wipe` before discarding.
    pub fn final(self: *Hasher, out: *[digest_length]u8) void {
        // Pad the tail (FIPS 180-4 §5.1.2): buffered bytes, a single 0x80,
        // zero padding, then the message length in bits as a big-endian
        // 128-bit integer. The 17 bytes of overhead spill into a second block
        // when the remainder leaves no room (112 bytes or more).
        var tail = [_]u8{0} ** (2 * block_length);
        defer std.crypto.secureZero(u8, &tail);
        @memcpy(tail[0..self.buffer_len], self.buffer[0..self.buffer_len]);
        tail[self.buffer_len] = 0x80;
        const tail_len: usize = if (self.buffer_len < block_length - 16)
            block_length
        else
            2 * block_length;
        std.mem.writeInt(u128, tail[tail_len - 16 ..][0..16], @as(u128, self.total_bytes) * 8, .big);
        hashBlocks(&self.state, tail[0..tail_len]);

        for (0..8) |i| {
            std.mem.writeInt(u64, out[i * 8 ..][0..8], self.state[i], .big);
        }
    }

    /// Wipes the running state — call before letting a Hasher go out of scope
    /// if it absorbed secret material.
    pub fn wipe(self: *Hasher) void {
        std.crypto.secureZero(u64, &self.state);
        std.crypto.secureZero(u8, &self.buffer);
    }
};

/// Computes the SHA-512 digest of `msg`, writing 64 bytes to `out`.
pub fn hash(out: *[digest_length]u8, msg: []const u8) void {
    var h = Hasher.init();
    defer h.wipe();
    h.update(msg);
    h.final(out);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "SHA-512 known-answer vector — \"abc\" (FIPS 180-4 §C.1)" {
    const expected = [64]u8{
        0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba,
        0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
        0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2,
        0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
        0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8,
        0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
        0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
        0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f,
    };
    var out: [64]u8 = undefined;
    hash(&out, "abc");
    try testing.expectEqualSlices(u8, &expected, &out);
}

test "SHA-512 known-answer vector — empty message (FIPS 180-4)" {
    // SHA-512("") — NIST CAVP / FIPS 180-4 zero-length vector.
    const expected = [64]u8{
        0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd,
        0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80, 0x07,
        0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc,
        0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce,
        0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0,
        0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f,
        0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81,
        0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e,
    };
    var out: [64]u8 = undefined;
    hash(&out, "");
    try testing.expectEqualSlices(u8, &expected, &out);
}

test "SHA-512 known-answer vector — 112-byte two-block message (FIPS 180-4 §C.2)" {
    // The two-block padding path: 112 message bytes force the length field
    // into a second block.
    const msg = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    const expected = [64]u8{
        0x8e, 0x95, 0x9b, 0x75, 0xda, 0xe3, 0x13, 0xda,
        0x8c, 0xf4, 0xf7, 0x28, 0x14, 0xfc, 0x14, 0x3f,
        0x8f, 0x77, 0x79, 0xc6, 0xeb, 0x9f, 0x7f, 0xa1,
        0x72, 0x99, 0xae, 0xad, 0xb6, 0x88, 0x90, 0x18,
        0x50, 0x1d, 0x28, 0x9e, 0x49, 0x00, 0xf7, 0xe4,
        0x33, 0x1b, 0x99, 0xde, 0xc4, 0xb5, 0x43, 0x3a,
        0xc7, 0xd3, 0x29, 0xee, 0xb6, 0xdd, 0x26, 0x54,
        0x5e, 0x96, 0xe5, 0x5b, 0x87, 0x4b, 0xe9, 0x09,
    };
    var out: [64]u8 = undefined;
    hash(&out, msg);
    try testing.expectEqualSlices(u8, &expected, &out);
}

test "SHA-512 matches std.crypto across sizes" {
    const Sha512 = std.crypto.hash.sha2.Sha512;
    var prng = std.Random.DefaultPrng.init(0x5a512c0ffee12345);
    const rand = prng.random();
    // Sizes spanning every padding case: empty, partial, the 111/112-byte
    // single/two-block boundary, exact blocks, and multi-block messages.
    const sizes = [_]usize{
        0,   1,   55,  56,  63,  64,  65,  111, 112,
        113, 127, 128, 129, 239, 240, 255, 256, 1000,
    };
    for (sizes) |len| {
        var iter: usize = 0;
        while (iter < 32) : (iter += 1) {
            var msg: [1000]u8 = undefined;
            rand.bytes(msg[0..len]);

            var mine: [64]u8 = undefined;
            var reference: [64]u8 = undefined;
            hash(&mine, msg[0..len]);
            Sha512.hash(msg[0..len], &reference, .{});
            try testing.expectEqualSlices(u8, &reference, &mine);
        }
    }
}

test "SHA-512 Hasher streaming equals one-shot, regardless of chunking" {
    var prng = std.Random.DefaultPrng.init(0x57a7e4_5ec0ffee);
    const rand = prng.random();
    // Sizes that exercise the buffer split logic — partial fills, exact
    // blocks, and the two-block padding boundary.
    const sizes = [_]usize{ 0, 1, 63, 64, 65, 111, 112, 127, 128, 200, 1000 };
    for (sizes) |len| {
        var iter: usize = 0;
        while (iter < 8) : (iter += 1) {
            var msg: [1000]u8 = undefined;
            rand.bytes(msg[0..len]);

            var one_shot: [64]u8 = undefined;
            hash(&one_shot, msg[0..len]);

            // Streaming with random chunk sizes — every chunking must agree.
            var h = Hasher.init();
            defer h.wipe();
            var pos: usize = 0;
            while (pos < len) {
                const chunk = @min(len - pos, rand.uintLessThan(usize, 200) + 1);
                h.update(msg[pos .. pos + chunk]);
                pos += chunk;
            }
            var streamed: [64]u8 = undefined;
            h.final(&streamed);
            try testing.expectEqualSlices(u8, &one_shot, &streamed);
        }
    }
}

test "SHA-512 is deterministic and reacts to single-bit changes" {
    var prng = std.Random.DefaultPrng.init(0x0011223344556677);
    const rand = prng.random();
    var msg: [200]u8 = undefined;
    rand.bytes(&msg);

    var a: [64]u8 = undefined;
    var b: [64]u8 = undefined;
    hash(&a, &msg);
    hash(&b, &msg);
    try testing.expectEqualSlices(u8, &a, &b); // same input, same digest

    var flipped = msg;
    flipped[99] ^= 0x01;
    hash(&b, &flipped);
    try testing.expect(!std.mem.eql(u8, &a, &b)); // one flipped bit changes it
}

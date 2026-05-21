//! X25519 — Diffie-Hellman scalar multiplication on Curve25519.
//!
//! Low-level building block: `box` (public-key authenticated encryption) will
//! compose this with `secretbox`. Faithful port of TweetNaCl's
//! `crypto_scalarmult`, which works in the field 2^255-19 using 16 limbs of
//! radix 2^16.
const std = @import("std");

/// A Curve25519 field element: 16 limbs, radix 2^16, stored signed so that
/// intermediate sums and products do not overflow an i64.
const Gf = [16]i64;

const gf_zero: Gf = [_]i64{0} ** 16;

/// The Curve25519 constant a24 = 121665, in field-element form.
const gf_121665: Gf = [16]i64{ 0xdb41, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

/// Base-point u-coordinate (u = 9).
const base_point: [32]u8 = [_]u8{9} ++ [_]u8{0} ** 31;

fn add(o: *Gf, a: *const Gf, b: *const Gf) void {
    for (0..16) |i| o[i] = a[i] + b[i];
}

fn sub(o: *Gf, a: *const Gf, b: *const Gf) void {
    for (0..16) |i| o[i] = a[i] - b[i];
}

/// Carries each limb back toward 16-bit range, folding any overflow above
/// bit 255 back in (2^256 ≡ 38 mod 2^255-19).
fn carry(o: *Gf) void {
    for (0..16) |i| {
        o[i] += 1 << 16;
        const c = o[i] >> 16;
        if (i < 15) {
            o[i + 1] += c - 1;
        } else {
            o[0] += 38 * (c - 1);
        }
        o[i] -= c << 16;
    }
}

/// Field multiplication: o = a * b mod 2^255-19.
fn mul(o: *Gf, a: *const Gf, b: *const Gf) void {
    var t = [_]i64{0} ** 31;
    for (0..16) |i| {
        for (0..16) |j| {
            t[i + j] += a[i] * b[j];
        }
    }
    for (0..15) |i| t[i] += 38 * t[i + 16];
    for (0..16) |i| o[i] = t[i];
    carry(o);
    carry(o);
}

/// Field squaring: o = a^2.
fn sq(o: *Gf, a: *const Gf) void {
    mul(o, a, a);
}

/// Constant-time conditional swap of `p` and `q` when `bit` is 1.
fn swap(p: *Gf, q: *Gf, bit: i64) void {
    const mask = ~(bit - 1); // all-ones when bit == 1, zero when bit == 0
    for (0..16) |i| {
        const t = mask & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

/// Deserialises a 32-byte little-endian u-coordinate into a field element.
fn unpack(o: *Gf, n: *const [32]u8) void {
    for (0..16) |i| {
        o[i] = @as(i64, n[2 * i]) + (@as(i64, n[2 * i + 1]) << 8);
    }
    o[15] &= 0x7fff;
}

/// Fully reduces a field element mod 2^255-19 and serialises it little-endian.
fn pack(o: *[32]u8, n: *const Gf) void {
    var t: Gf = n.*;
    carry(&t);
    carry(&t);
    carry(&t);
    for (0..2) |_| {
        var m: Gf = undefined;
        m[0] = t[0] - 0xffed;
        for (1..15) |i| {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        const b = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        swap(&t, &m, 1 - b); // keep the reduced value, in constant time
    }
    for (0..16) |i| {
        o[2 * i] = @intCast(t[i] & 0xff);
        o[2 * i + 1] = @intCast((t[i] >> 8) & 0xff);
    }
}

/// Field inversion via Fermat's little theorem: o = i^(2^255-21).
fn invert(o: *Gf, in: *const Gf) void {
    var t: Gf = in.*;
    var a: i32 = 253;
    while (a >= 0) : (a -= 1) {
        sq(&t, &t);
        if (a != 2 and a != 4) mul(&t, &t, in);
    }
    o.* = t;
}

/// Computes the X25519 shared secret `out` = `scalar` · `point`.
///
/// Both arguments are 32-byte little-endian values; `out` receives the
/// resulting u-coordinate. The same operation is key agreement and, with the
/// base point, public-key derivation (see `scalarmultBase`).
pub fn scalarmult(out: *[32]u8, scalar: *const [32]u8, point: *const [32]u8) void {
    // Clamp the scalar (RFC 7748).
    var z: [32]u8 = scalar.*;
    z[0] &= 248;
    z[31] = (z[31] & 127) | 64;

    var x: Gf = undefined;
    unpack(&x, point);

    var a: Gf = gf_zero;
    var b: Gf = x;
    var c: Gf = gf_zero;
    var d: Gf = gf_zero;
    var e: Gf = undefined;
    var f: Gf = undefined;
    a[0] = 1;
    d[0] = 1;

    defer {
        std.crypto.secureZero(u8, &z);
        std.crypto.secureZero(i64, &a);
        std.crypto.secureZero(i64, &b);
        std.crypto.secureZero(i64, &c);
        std.crypto.secureZero(i64, &d);
        std.crypto.secureZero(i64, &e);
        std.crypto.secureZero(i64, &f);
        std.crypto.secureZero(i64, &x);
    }

    // Montgomery ladder over scalar bits 254..0.
    var i: usize = 255;
    while (i > 0) {
        i -= 1;
        const r: i64 = @intCast((z[i >> 3] >> @as(u3, @intCast(i & 7))) & 1);
        swap(&a, &b, r);
        swap(&c, &d, r);
        add(&e, &a, &c);
        sub(&a, &a, &c);
        add(&c, &b, &d);
        sub(&b, &b, &d);
        sq(&d, &e);
        sq(&f, &a);
        mul(&a, &c, &a);
        mul(&c, &b, &e);
        add(&e, &a, &c);
        sub(&a, &a, &c);
        sq(&b, &a);
        sub(&c, &d, &f);
        mul(&a, &c, &gf_121665);
        add(&a, &a, &d);
        mul(&c, &c, &a);
        mul(&a, &d, &f);
        mul(&d, &b, &x);
        sq(&b, &e);
        swap(&a, &b, r);
        swap(&c, &d, r);
    }

    invert(&c, &c);
    mul(&a, &a, &c);
    pack(out, &a);
}

/// Computes the X25519 public key `out` = `scalar` · base point.
pub fn scalarmultBase(out: *[32]u8, scalar: *const [32]u8) void {
    scalarmult(out, scalar, &base_point);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "X25519 scalarmult — RFC 7748 section 5.2 vector 1" {
    const scalar = [32]u8{
        0xa5, 0x46, 0xe3, 0x6b, 0xf0, 0x52, 0x7c, 0x9d,
        0x3b, 0x16, 0x15, 0x4b, 0x82, 0x46, 0x5e, 0xdd,
        0x62, 0x14, 0x4c, 0x0a, 0xc1, 0xfc, 0x5a, 0x18,
        0x50, 0x6a, 0x22, 0x44, 0xba, 0x44, 0x9a, 0xc4,
    };
    const point = [32]u8{
        0xe6, 0xdb, 0x68, 0x67, 0x58, 0x30, 0x30, 0xdb,
        0x35, 0x94, 0xc1, 0xa4, 0x24, 0xb1, 0x5f, 0x7c,
        0x72, 0x66, 0x24, 0xec, 0x26, 0xb3, 0x35, 0x3b,
        0x10, 0xa9, 0x03, 0xa6, 0xd0, 0xab, 0x1c, 0x4c,
    };
    const expected = [32]u8{
        0xc3, 0xda, 0x55, 0x37, 0x9d, 0xe9, 0xc6, 0x90,
        0x8e, 0x94, 0xea, 0x4d, 0xf2, 0x8d, 0x08, 0x4f,
        0x32, 0xec, 0xcf, 0x03, 0x49, 0x1c, 0x71, 0xf7,
        0x54, 0xb4, 0x07, 0x55, 0x77, 0xa2, 0x85, 0x52,
    };
    var out: [32]u8 = undefined;
    scalarmult(&out, &scalar, &point);
    try testing.expectEqualSlices(u8, &expected, &out);
}

test "X25519 — RFC 7748 section 6.1 Diffie-Hellman" {
    const alice_secret = [32]u8{
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
        0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
        0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
        0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
    };
    const alice_public = [32]u8{
        0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54,
        0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a,
        0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4,
        0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a,
    };
    const bob_secret = [32]u8{
        0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b,
        0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e, 0xe6,
        0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd,
        0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb,
    };
    const bob_public = [32]u8{
        0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4,
        0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
        0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d,
        0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f,
    };
    const shared = [32]u8{
        0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1,
        0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35, 0x0f, 0x25,
        0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33,
        0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16, 0x17, 0x42,
    };

    var out: [32]u8 = undefined;

    // Public keys derive from the base point.
    scalarmultBase(&out, &alice_secret);
    try testing.expectEqualSlices(u8, &alice_public, &out);
    scalarmultBase(&out, &bob_secret);
    try testing.expectEqualSlices(u8, &bob_public, &out);

    // Both parties reach the same shared secret.
    scalarmult(&out, &alice_secret, &bob_public);
    try testing.expectEqualSlices(u8, &shared, &out);
    scalarmult(&out, &bob_secret, &alice_public);
    try testing.expectEqualSlices(u8, &shared, &out);
}

test "X25519 scalarmult matches std.crypto" {
    var prng = std.Random.DefaultPrng.init(0x25519c0ffee12345);
    const rand = prng.random();
    var iter: usize = 0;
    while (iter < 100) : (iter += 1) {
        var scalar: [32]u8 = undefined;
        var point: [32]u8 = undefined;
        rand.bytes(&scalar);
        rand.bytes(&point);

        var mine: [32]u8 = undefined;
        scalarmult(&mine, &scalar, &point);
        const theirs = try std.crypto.dh.X25519.scalarmult(scalar, point);
        try testing.expectEqualSlices(u8, &theirs, &mine);
    }
}

test "X25519 scalarmultBase matches std.crypto" {
    var prng = std.Random.DefaultPrng.init(0xba5ef00d12345678);
    const rand = prng.random();
    var iter: usize = 0;
    while (iter < 100) : (iter += 1) {
        var scalar: [32]u8 = undefined;
        rand.bytes(&scalar);

        var mine: [32]u8 = undefined;
        scalarmultBase(&mine, &scalar);
        const theirs = try std.crypto.dh.X25519.scalarmult(scalar, base_point);
        try testing.expectEqualSlices(u8, &theirs, &mine);
    }
}

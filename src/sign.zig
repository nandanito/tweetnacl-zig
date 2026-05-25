//! sign — Ed25519 digital signatures.
//!
//! This is NaCl's `crypto_sign`: a deterministic Schnorr-style signature
//! over the twisted Edwards curve "edwards25519" (Bernstein–Duif–Lange–
//! Schwabe–Yang, "High-speed high-security signatures", 2011). Wire-compatible
//! with TweetNaCl, tweetnacl-js, and `std.crypto.sign.Ed25519` — a 32-byte
//! public key, a 64-byte secret key (32-byte seed ++ public key) and a
//! 64-byte signature (R ++ S).
//!
//! Two API shapes are provided. The "attached" variant — NaCl's native form
//! and the one TweetNaCl exposes — concatenates the signature with the
//! message and verifies the pair atomically: `sign` writes
//! `signature_length + msg.len` bytes, `open` returns the plaintext only after
//! authentication. The "detached" variant separates signature from message,
//! matching `std.crypto.sign.Ed25519` and most modern libraries.
//!
//! The signing scalar — and thus the per-message nonce — is derived
//! deterministically from `SHA-512(secret_key) ++ message` (RFC 8032 §5.1.6),
//! so signing the same message with the same key yields the same signature
//! and does not depend on any external randomness.
//!
//! Ed25519 verification is permissive — any RFC 8032-conformant signature is
//! accepted, including those produced for low-order or otherwise pathological
//! public keys. This matches TweetNaCl and `std.crypto.sign.Ed25519`.
const std = @import("std");
const hash_mod = @import("hash.zig");

/// Public-key length in bytes.
pub const public_key_length = 32;
/// Secret-key length in bytes (seed ++ public key).
pub const secret_key_length = 64;
/// Seed length in bytes — the high-entropy half of the secret key.
pub const seed_length = 32;
/// Signature length in bytes.
pub const signature_length = 64;

// ---------------------------------------------------------------------------
// Field arithmetic over GF(2^255 - 19) — 16 limbs of radix 2^16.
// ---------------------------------------------------------------------------
//
// Sign uses the same prime field as X25519 but a different curve (twisted
// Edwards rather than Montgomery), so the field-element layout and the
// per-limb operations are duplicated here verbatim from `scalarmult.zig`. The
// two primitives stay self-contained for audit; a future refactor may share
// them through a private module if a third caller appears.

/// A field element: 16 limbs, radix 2^16, signed so intermediate sums and
/// products do not overflow an i64.
const Gf = [16]i64;

const gf_zero: Gf = [_]i64{0} ** 16;
const gf_one: Gf = blk: {
    var e: Gf = [_]i64{0} ** 16;
    e[0] = 1;
    break :blk e;
};

/// Edwards curve parameter d (`-121665/121666 mod p`).
const D: Gf = [16]i64{
    0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070,
    0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203,
};
/// 2 · d, precomputed for the Edwards addition formula.
const D2: Gf = [16]i64{
    0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0,
    0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406,
};
/// Base-point coordinates B = (Bx, By).
const Bx: Gf = [16]i64{
    0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c,
    0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169,
};
const By: Gf = [16]i64{
    0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
    0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
};
/// Square root of -1 mod p (used to pick the correct y in `unpackneg`).
const sqrt_m1: Gf = [16]i64{
    0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43,
    0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83,
};

/// The group order L = 2^252 + 27742317777372353535851937790883648493 — least
/// significant byte first (RFC 8032 §5.1).
const L: [32]u8 = [_]u8{
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0x10,
};

fn feAdd(o: *Gf, a: *const Gf, b: *const Gf) void {
    for (0..16) |i| o[i] = a[i] + b[i];
}

fn feSub(o: *Gf, a: *const Gf, b: *const Gf) void {
    for (0..16) |i| o[i] = a[i] - b[i];
}

/// Carries each limb back toward 16-bit range, folding any overflow above
/// bit 255 back in (2^256 ≡ 38 mod 2^255-19).
fn feCarry(o: *Gf) void {
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

fn feMul(o: *Gf, a: *const Gf, b: *const Gf) void {
    var t = [_]i64{0} ** 31;
    for (0..16) |i| {
        for (0..16) |j| {
            t[i + j] += a[i] * b[j];
        }
    }
    for (0..15) |i| t[i] += 38 * t[i + 16];
    for (0..16) |i| o[i] = t[i];
    feCarry(o);
    feCarry(o);
}

fn feSquare(o: *Gf, a: *const Gf) void {
    feMul(o, a, a);
}

/// Constant-time conditional swap of `p` and `q` when `bit` is 1.
fn feSelect(p: *Gf, q: *Gf, bit: u8) void {
    const mask: i64 = ~(@as(i64, bit) - 1); // all-ones when bit == 1, zero when bit == 0
    for (0..16) |i| {
        const t = mask & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

fn feUnpack(o: *Gf, n: *const [32]u8) void {
    for (0..16) |i| {
        o[i] = @as(i64, n[2 * i]) + (@as(i64, n[2 * i + 1]) << 8);
    }
    o[15] &= 0x7fff;
}

/// Fully reduces `n` mod 2^255-19 and serialises it little-endian to `o`.
fn fePack(o: *[32]u8, n: *const Gf) void {
    var t: Gf = n.*;
    feCarry(&t);
    feCarry(&t);
    feCarry(&t);
    for (0..2) |_| {
        var m: Gf = undefined;
        m[0] = t[0] - 0xffed;
        for (1..15) |i| {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        const b: u8 = @intCast((m[15] >> 16) & 1);
        m[14] &= 0xffff;
        feSelect(&t, &m, 1 - b); // keep the reduced value, in constant time
    }
    for (0..16) |i| {
        o[2 * i] = @intCast(t[i] & 0xff);
        o[2 * i + 1] = @intCast((t[i] >> 8) & 0xff);
    }
}

/// 1 if the canonical packing of `a` differs from `b`, else 0. Returned as an
/// i32 to keep the result branch-free at call sites.
fn feNeq(a: *const Gf, b: *const Gf) i32 {
    var c: [32]u8 = undefined;
    var d: [32]u8 = undefined;
    fePack(&c, a);
    fePack(&d, b);
    // crypto_verify_32 — constant-time compare; we only need pass/fail here.
    return @intFromBool(!std.crypto.timing_safe.eql([32]u8, c, d));
}

/// Parity (low bit of the canonical encoding) of a field element.
fn feParity(a: *const Gf) u8 {
    var d: [32]u8 = undefined;
    fePack(&d, a);
    return d[0] & 1;
}

/// Multiplicative inverse via Fermat's little theorem: o = i^(p-2) mod p.
fn feInvert(o: *Gf, in: *const Gf) void {
    var c: Gf = in.*;
    var a: i32 = 253;
    while (a >= 0) : (a -= 1) {
        feSquare(&c, &c);
        if (a != 2 and a != 4) feMul(&c, &c, in);
    }
    o.* = c;
}

/// o = i^((p-5)/8). Used to extract a square root in `unpackneg`.
fn fePow2523(o: *Gf, in: *const Gf) void {
    var c: Gf = in.*;
    var a: i32 = 250;
    while (a >= 0) : (a -= 1) {
        feSquare(&c, &c);
        if (a != 1) feMul(&c, &c, in);
    }
    o.* = c;
}

// ---------------------------------------------------------------------------
// Edwards-curve group operations on edwards25519, using extended coordinates
// (X, Y, Z, T) with the invariant x = X/Z, y = Y/Z, x·y = T/Z (Hisil et al.,
// "Twisted Edwards curves revisited", Asiacrypt 2008).
// ---------------------------------------------------------------------------

const Point = [4]Gf;

/// Point addition p ← p + q on the twisted Edwards curve. Uses the dedicated
/// addition formula from §3.1 of the Hisil et al. paper, valid for any two
/// points on the curve and free of exceptional cases (the curve has no point
/// of order 2 with both coordinates rational, so the formula does not need a
/// separate doubling case).
fn pointAdd(p: *Point, q: *const Point) void {
    var a: Gf = undefined;
    var b: Gf = undefined;
    var c: Gf = undefined;
    var d: Gf = undefined;
    var t: Gf = undefined;
    var e: Gf = undefined;
    var f: Gf = undefined;
    var g: Gf = undefined;
    var h: Gf = undefined;

    feSub(&a, &p[1], &p[0]);
    feSub(&t, &q[1], &q[0]);
    feMul(&a, &a, &t);
    feAdd(&b, &p[0], &p[1]);
    feAdd(&t, &q[0], &q[1]);
    feMul(&b, &b, &t);
    feMul(&c, &p[3], &q[3]);
    feMul(&c, &c, &D2);
    feMul(&d, &p[2], &q[2]);
    feAdd(&d, &d, &d);
    feSub(&e, &b, &a);
    feSub(&f, &d, &c);
    feAdd(&g, &d, &c);
    feAdd(&h, &b, &a);
    feMul(&p[0], &e, &f);
    feMul(&p[1], &h, &g);
    feMul(&p[2], &g, &f);
    feMul(&p[3], &e, &h);
}

/// Constant-time conditional swap of two points.
fn pointSelect(p: *Point, q: *Point, bit: u8) void {
    for (0..4) |i| feSelect(&p[i], &q[i], bit);
}

/// Serialises a point as the 32-byte compressed Edwards encoding: 255 bits of
/// y, with the sign of x packed into the high bit.
fn pointPack(out: *[32]u8, p: *const Point) void {
    var zi: Gf = undefined;
    var tx: Gf = undefined;
    var ty: Gf = undefined;
    feInvert(&zi, &p[2]);
    feMul(&tx, &p[0], &zi);
    feMul(&ty, &p[1], &zi);
    fePack(out, &ty);
    out[31] ^= feParity(&tx) << 7;
}

/// Decompresses a 32-byte Ed25519 point to its **negation**. Returns
/// `error.InvalidEncoding` if `enc` does not encode a curve point.
///
/// Verification computes `S·B - h·A` to compare against R. Storing `-A`
/// up front lets us write that as a sum and reuse the addition formula.
fn pointUnpackNeg(r: *Point, enc: *const [32]u8) error{InvalidEncoding}!void {
    var t: Gf = undefined;
    var chk: Gf = undefined;
    var num: Gf = undefined;
    var den: Gf = undefined;
    var den2: Gf = undefined;
    var den4: Gf = undefined;
    var den6: Gf = undefined;

    r[2] = gf_one;
    feUnpack(&r[1], enc);
    feSquare(&num, &r[1]); // y^2
    feMul(&den, &num, &D); // d·y^2
    feSub(&num, &num, &r[2]); // y^2 - 1
    feAdd(&den, &r[2], &den); // 1 + d·y^2

    // Compute x = sqrt((y^2 - 1) / (1 + d·y^2)) using the standard trick:
    //   x = (y^2 - 1) · (1 + d·y^2)^((p-5)/8)
    // and then adjust by sqrt(-1) if needed (RFC 8032 §5.1.3 step 4).
    feSquare(&den2, &den);
    feSquare(&den4, &den2);
    feMul(&den6, &den4, &den2);
    feMul(&t, &den6, &num);
    feMul(&t, &t, &den);
    fePow2523(&t, &t);
    feMul(&t, &t, &num);
    feMul(&t, &t, &den);
    feMul(&t, &t, &den);
    feMul(&r[0], &t, &den);

    feSquare(&chk, &r[0]);
    feMul(&chk, &chk, &den);
    if (feNeq(&chk, &num) != 0) feMul(&r[0], &r[0], &sqrt_m1);

    feSquare(&chk, &r[0]);
    feMul(&chk, &chk, &den);
    if (feNeq(&chk, &num) != 0) return error.InvalidEncoding;

    // Negate when the parity of x doesn't match the sign bit in `enc[31]`.
    // The encoding ends up with the OPPOSITE sign, hence "unpackneg".
    if (feParity(&r[0]) == (enc[31] >> 7)) feSub(&r[0], &gf_zero, &r[0]);

    feMul(&r[3], &r[0], &r[1]);
}

/// Constant-time scalar multiplication: p ← s · q, with s read MSB-first.
/// Uses the standard double-and-add ladder with a cswap to hide the bit value.
fn pointScalarmult(p: *Point, q: *const Point, s: *const [32]u8) void {
    var qmut: Point = q.*;
    p[0] = gf_zero;
    p[1] = gf_one;
    p[2] = gf_one;
    p[3] = gf_zero;

    var i: usize = 256;
    while (i > 0) {
        i -= 1;
        const b: u8 = (s[i >> 3] >> @as(u3, @intCast(i & 7))) & 1;
        pointSelect(p, &qmut, b);
        pointAdd(&qmut, p);
        pointAdd(p, p);
        pointSelect(p, &qmut, b);
    }
}

/// Convenience: p ← s · B, where B is the Ed25519 base point.
fn pointScalarbase(p: *Point, s: *const [32]u8) void {
    var b: Point = undefined;
    b[0] = Bx;
    b[1] = By;
    b[2] = gf_one;
    feMul(&b[3], &Bx, &By);
    pointScalarmult(p, &b, s);
}

// ---------------------------------------------------------------------------
// Scalar reduction modulo the group order L.
// ---------------------------------------------------------------------------

/// Barrett-style reduction of a 64-byte little-endian integer `x` modulo L,
/// writing the 32-byte result to `r`. `x` is destroyed.
///
/// L < 2^253, so the inputs we feed in here — products of two reduced
/// scalars plus another scalar, all at most ~2^509 — fit in 64 limbs. The
/// outer loop nibbles 8-bit chunks off the top, subtracting an appropriate
/// shift of L; the inner loops re-canonicalise the limbs.
fn modL(r: *[32]u8, x: *[64]i64) void {
    var carry: i64 = 0;
    var i: usize = 63;
    while (i >= 32) : (i -= 1) {
        carry = 0;
        var j: usize = i - 32;
        while (j < i - 12) : (j += 1) {
            x[j] += carry - 16 * x[i] * @as(i64, L[j - (i - 32)]);
            carry = (x[j] + 128) >> 8;
            x[j] -= carry << 8;
        }
        x[j] += carry;
        x[i] = 0;
    }
    carry = 0;
    for (0..32) |j| {
        x[j] += carry - (x[31] >> 4) * @as(i64, L[j]);
        carry = x[j] >> 8;
        x[j] &= 255;
    }
    for (0..32) |j| {
        x[j] -= carry * @as(i64, L[j]);
    }
    for (0..32) |k| {
        x[k + 1] += x[k] >> 8;
        r[k] = @intCast(x[k] & 0xff);
    }
}

/// Reduces a 64-byte little-endian integer in place to 32 bytes, modulo L.
fn reduceModL(r: *[64]u8) void {
    var x: [64]i64 = undefined;
    for (0..64) |i| x[i] = @as(i64, r[i]);
    @memset(r, 0);
    modL(r[0..32], &x);
    std.crypto.secureZero(i64, &x);
}

// ---------------------------------------------------------------------------
// Public API.
// ---------------------------------------------------------------------------

/// An Ed25519 key pair. The secret key is the 32-byte seed followed by the
/// 32-byte public key — the layout TweetNaCl uses, so the bytes are wire-
/// compatible with `std.crypto.sign.Ed25519` and tweetnacl-js.
pub const KeyPair = struct {
    public_key: [public_key_length]u8,
    secret_key: [secret_key_length]u8,

    /// Wipes the secret key. The public key is not secret and is left intact.
    pub fn wipe(self: *KeyPair) void {
        std.crypto.secureZero(u8, &self.secret_key);
    }
};

/// Derives the key pair for a given 32-byte seed.
pub fn keyPairFromSeed(seed: *const [seed_length]u8) KeyPair {
    var kp: KeyPair = undefined;
    @memcpy(kp.secret_key[0..seed_length], seed);

    // a = clamp(SHA-512(seed)[0..32]) — the signing scalar (RFC 8032 §5.1.5).
    var d: [64]u8 = undefined;
    defer std.crypto.secureZero(u8, &d);
    hash_mod.hash(&d, seed);
    d[0] &= 248;
    d[31] &= 127;
    d[31] |= 64;

    // Public key A = a · B.
    var p: Point = undefined;
    pointScalarbase(&p, d[0..32]);
    pointPack(&kp.public_key, &p);

    // Copy A into the second half of the secret key.
    @memcpy(kp.secret_key[seed_length..], &kp.public_key);
    return kp;
}

/// Generates a fresh key pair, drawing the seed from `io`'s CSPRNG.
pub fn keyPair(io: std.Io) KeyPair {
    var seed: [seed_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &seed);
    io.random(&seed);
    return keyPairFromSeed(&seed);
}

/// Computes the 64-byte signature of `msg` under `secret_key`, writing it to
/// `sig`. Deterministic: the same `(secret_key, msg)` always yields the same
/// signature (RFC 8032 §5.1.6).
fn signRaw(sig: *[signature_length]u8, msg: []const u8, secret_key: *const [secret_key_length]u8) void {
    // d = SHA-512(seed). a = clamp(d[0..32]); prefix = d[32..64] (the
    // "signing prefix" that diversifies r between keys).
    var d: [64]u8 = undefined;
    defer std.crypto.secureZero(u8, &d);
    hash_mod.hash(&d, secret_key[0..seed_length]);
    d[0] &= 248;
    d[31] &= 127;
    d[31] |= 64;

    // r = SHA-512(prefix || msg), reduced mod L. r is the per-signature
    // nonce; its derivation from prefix||msg is what makes signing
    // deterministic and the nonce uniformly distributed.
    var r_hash: [64]u8 = undefined;
    defer std.crypto.secureZero(u8, &r_hash);
    {
        var hh = hash_mod.Hasher.init();
        defer hh.wipe();
        hh.update(d[32..64]);
        hh.update(msg);
        hh.final(&r_hash);
    }
    reduceModL(&r_hash);

    // R = r · B; write its 32-byte compressed encoding into sig[0..32].
    var R: Point = undefined;
    pointScalarbase(&R, r_hash[0..32]);
    pointPack(sig[0..32], &R);

    // h = SHA-512(R || A || msg), reduced mod L. A is in the second half of
    // the secret key — the layout's whole point is that we don't recompute it.
    var h: [64]u8 = undefined;
    defer std.crypto.secureZero(u8, &h);
    {
        var hh = hash_mod.Hasher.init();
        defer hh.wipe();
        hh.update(sig[0..32]);
        hh.update(secret_key[seed_length..]);
        hh.update(msg);
        hh.final(&h);
    }
    reduceModL(&h);

    // S = (r + h · a) mod L. Computed in a 64-limb scratchpad fed to modL.
    var x: [64]i64 = [_]i64{0} ** 64;
    defer std.crypto.secureZero(i64, &x);
    for (0..32) |i| x[i] = @as(i64, r_hash[i]);
    for (0..32) |i| {
        for (0..32) |j| {
            x[i + j] += @as(i64, h[i]) * @as(i64, d[j]);
        }
    }
    modL(sig[32..64], &x);
}

/// Attached sign (NaCl form): writes the 64-byte signature followed by
/// `msg.len` bytes of plaintext to `out`, for a total of `msg.len +
/// signature_length` bytes.
pub fn sign(out: []u8, msg: []const u8, secret_key: *const [secret_key_length]u8) void {
    std.debug.assert(out.len == msg.len + signature_length);
    var sig: [signature_length]u8 = undefined;
    signRaw(&sig, msg, secret_key);
    @memcpy(out[0..signature_length], &sig);
    @memcpy(out[signature_length..], msg);
}

/// Detached sign: writes only the 64-byte signature.
pub fn signDetached(sig: *[signature_length]u8, msg: []const u8, secret_key: *const [secret_key_length]u8) void {
    signRaw(sig, msg, secret_key);
}

/// Verifies a 64-byte detached signature against `msg` and `public_key`.
/// Returns `error.AuthFailed` if the signature does not authenticate.
pub fn verifyDetached(
    sig: *const [signature_length]u8,
    msg: []const u8,
    public_key: *const [public_key_length]u8,
) error{AuthFailed}!void {
    // Decompress -A; an invalid public key cannot authenticate any message.
    var neg_a: Point = undefined;
    pointUnpackNeg(&neg_a, public_key) catch return error.AuthFailed;

    // h = SHA-512(R || A || msg), reduced mod L.
    var h: [64]u8 = undefined;
    defer std.crypto.secureZero(u8, &h);
    {
        var hh = hash_mod.Hasher.init();
        defer hh.wipe();
        hh.update(sig[0..32]);
        hh.update(public_key);
        hh.update(msg);
        hh.final(&h);
    }
    reduceModL(&h);

    // Compute R' = S·B + h·(-A) = S·B - h·A and compare its encoding to R.
    var p: Point = undefined;
    var q: Point = undefined;
    pointScalarmult(&p, &neg_a, h[0..32]);
    pointScalarbase(&q, sig[32..64]);
    pointAdd(&p, &q);
    var t: [32]u8 = undefined;
    pointPack(&t, &p);

    if (!std.crypto.timing_safe.eql([32]u8, t, sig[0..32].*)) return error.AuthFailed;
}

/// Attached open (NaCl form): verifies and unwraps a signed message. `signed`
/// is the 64-byte signature followed by the message; on success, the
/// `signed.len - signature_length` message bytes are written to `out`.
///
/// Returns `error.AuthFailed` — without writing any plaintext — if the
/// signature does not authenticate.
pub fn open(
    out: []u8,
    signed: []const u8,
    public_key: *const [public_key_length]u8,
) error{AuthFailed}!void {
    if (signed.len < signature_length) return error.AuthFailed;
    const msg = signed[signature_length..];
    std.debug.assert(out.len == msg.len);

    const sig: *const [signature_length]u8 = signed[0..signature_length];
    try verifyDetached(sig, msg, public_key);
    @memcpy(out, msg);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

// RFC 8032 §7.1 test vector 1 — empty message.
const rfc8032_test1_seed = [32]u8{
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
    0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
    0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
};
const rfc8032_test1_pk = [32]u8{
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
    0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
    0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
};
const rfc8032_test1_sig = [64]u8{
    0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72,
    0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82, 0x8a,
    0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74,
    0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49, 0x01, 0x55,
    0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac,
    0xc6, 0x1e, 0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b,
    0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24,
    0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b,
};

// RFC 8032 §7.1 test vector 2 — single-byte message 0x72.
const rfc8032_test2_seed = [32]u8{
    0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda,
    0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e, 0x0f,
    0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24,
    0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb,
};
const rfc8032_test2_pk = [32]u8{
    0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a,
    0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b, 0x7e, 0xbc,
    0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c,
    0xc0, 0xcd, 0x55, 0xf1, 0x2a, 0xf4, 0x66, 0x0c,
};
const rfc8032_test2_msg = [_]u8{0x72};
const rfc8032_test2_sig = [64]u8{
    0x92, 0xa0, 0x09, 0xa9, 0xf0, 0xd4, 0xca, 0xb8,
    0x72, 0x0e, 0x82, 0x0b, 0x5f, 0x64, 0x25, 0x40,
    0xa2, 0xb2, 0x7b, 0x54, 0x16, 0x50, 0x3f, 0x8f,
    0xb3, 0x76, 0x22, 0x23, 0xeb, 0xdb, 0x69, 0xda,
    0x08, 0x5a, 0xc1, 0xe4, 0x3e, 0x15, 0x99, 0x6e,
    0x45, 0x8f, 0x36, 0x13, 0xd0, 0xf1, 0x1d, 0x8c,
    0x38, 0x7b, 0x2e, 0xae, 0xb4, 0x30, 0x2a, 0xee,
    0xb0, 0x0d, 0x29, 0x16, 0x12, 0xbb, 0x0c, 0x00,
};

// RFC 8032 §7.1 test vector 3 — message 0xaf 0x82.
const rfc8032_test3_seed = [32]u8{
    0xc5, 0xaa, 0x8d, 0xf4, 0x3f, 0x9f, 0x83, 0x7b,
    0xed, 0xb7, 0x44, 0x2f, 0x31, 0xdc, 0xb7, 0xb1,
    0x66, 0xd3, 0x85, 0x35, 0x07, 0x6f, 0x09, 0x4b,
    0x85, 0xce, 0x3a, 0x2e, 0x0b, 0x44, 0x58, 0xf7,
};
const rfc8032_test3_pk = [32]u8{
    0xfc, 0x51, 0xcd, 0x8e, 0x62, 0x18, 0xa1, 0xa3,
    0x8d, 0xa4, 0x7e, 0xd0, 0x02, 0x30, 0xf0, 0x58,
    0x08, 0x16, 0xed, 0x13, 0xba, 0x33, 0x03, 0xac,
    0x5d, 0xeb, 0x91, 0x15, 0x48, 0x90, 0x80, 0x25,
};
const rfc8032_test3_msg = [_]u8{ 0xaf, 0x82 };
const rfc8032_test3_sig = [64]u8{
    0x62, 0x91, 0xd6, 0x57, 0xde, 0xec, 0x24, 0x02,
    0x48, 0x27, 0xe6, 0x9c, 0x3a, 0xbe, 0x01, 0xa3,
    0x0c, 0xe5, 0x48, 0xa2, 0x84, 0x74, 0x3a, 0x44,
    0x5e, 0x36, 0x80, 0xd7, 0xdb, 0x5a, 0xc3, 0xac,
    0x18, 0xff, 0x9b, 0x53, 0x8d, 0x16, 0xf2, 0x90,
    0xae, 0x67, 0xf7, 0x60, 0x98, 0x4d, 0xc6, 0x59,
    0x4a, 0x7c, 0x15, 0xe9, 0x71, 0x6e, 0xd2, 0x8d,
    0xc0, 0x27, 0xbe, 0xce, 0xea, 0x1e, 0xc4, 0x0a,
};

test "Ed25519 keyPairFromSeed derives the RFC 8032 §7.1 public keys" {
    const vectors = [_]struct { seed: [32]u8, pk: [32]u8 }{
        .{ .seed = rfc8032_test1_seed, .pk = rfc8032_test1_pk },
        .{ .seed = rfc8032_test2_seed, .pk = rfc8032_test2_pk },
        .{ .seed = rfc8032_test3_seed, .pk = rfc8032_test3_pk },
    };
    for (vectors) |v| {
        const kp = keyPairFromSeed(&v.seed);
        try testing.expectEqualSlices(u8, &v.pk, &kp.public_key);
        try testing.expectEqualSlices(u8, &v.seed, kp.secret_key[0..32]);
        try testing.expectEqualSlices(u8, &v.pk, kp.secret_key[32..64]);
    }
}

test "Ed25519 detached sign + verify — RFC 8032 §7.1 vectors" {
    const Vec = struct {
        seed: [32]u8,
        pk: [32]u8,
        msg: []const u8,
        sig: [64]u8,
    };
    const vectors = [_]Vec{
        .{ .seed = rfc8032_test1_seed, .pk = rfc8032_test1_pk, .msg = &.{}, .sig = rfc8032_test1_sig },
        .{ .seed = rfc8032_test2_seed, .pk = rfc8032_test2_pk, .msg = &rfc8032_test2_msg, .sig = rfc8032_test2_sig },
        .{ .seed = rfc8032_test3_seed, .pk = rfc8032_test3_pk, .msg = &rfc8032_test3_msg, .sig = rfc8032_test3_sig },
    };
    for (vectors) |v| {
        const kp = keyPairFromSeed(&v.seed);
        var sig: [signature_length]u8 = undefined;
        signDetached(&sig, v.msg, &kp.secret_key);
        try testing.expectEqualSlices(u8, &v.sig, &sig);
        try verifyDetached(&v.sig, v.msg, &kp.public_key);
    }
}

test "Ed25519 attached sign + open — RFC 8032 §7.1 vector 2 round-trips" {
    const kp = keyPairFromSeed(&rfc8032_test2_seed);

    var signed: [rfc8032_test2_msg.len + signature_length]u8 = undefined;
    sign(&signed, &rfc8032_test2_msg, &kp.secret_key);
    try testing.expectEqualSlices(u8, &rfc8032_test2_sig, signed[0..signature_length]);
    try testing.expectEqualSlices(u8, &rfc8032_test2_msg, signed[signature_length..]);

    var opened: [rfc8032_test2_msg.len]u8 = undefined;
    try open(&opened, &signed, &kp.public_key);
    try testing.expectEqualSlices(u8, &rfc8032_test2_msg, &opened);
}

test "Ed25519 matches std.crypto.sign.Ed25519 across sizes" {
    const StdEd = std.crypto.sign.Ed25519;
    var prng = std.Random.DefaultPrng.init(0xed25519_c0ffee01);
    const rand = prng.random();
    // Sizes spanning short, single-block, two-block, and multi-block messages.
    const sizes = [_]usize{ 0, 1, 31, 32, 63, 64, 65, 127, 128, 129, 256, 1000 };
    for (sizes) |len| {
        var iter: usize = 0;
        while (iter < 8) : (iter += 1) {
            var seed: [32]u8 = undefined;
            var msg: [1000]u8 = undefined;
            rand.bytes(&seed);
            rand.bytes(msg[0..len]);

            const kp_mine = keyPairFromSeed(&seed);
            const kp_std = try StdEd.KeyPair.generateDeterministic(seed);

            // Public keys agree byte-for-byte.
            try testing.expectEqualSlices(u8, &kp_std.public_key.bytes, &kp_mine.public_key);

            // Our signature matches the audited one (Ed25519 is deterministic).
            var mine: [signature_length]u8 = undefined;
            signDetached(&mine, msg[0..len], &kp_mine.secret_key);
            const reference = try kp_std.sign(msg[0..len], null);
            try testing.expectEqualSlices(u8, &reference.toBytes(), &mine);

            // verifyDetached accepts the audited signature.
            try verifyDetached(&reference.toBytes(), msg[0..len], &kp_mine.public_key);

            // std.crypto accepts our signature.
            const sig_obj = StdEd.Signature.fromBytes(mine);
            try sig_obj.verify(msg[0..len], kp_std.public_key);
        }
    }
}

test "Ed25519 keyPair generates a working pair" {
    const io = std.testing.io;
    var kp = keyPair(io);
    defer kp.wipe();

    const msg = "freshly generated Ed25519 keys round-trip";
    var sig: [signature_length]u8 = undefined;
    signDetached(&sig, msg, &kp.secret_key);
    try verifyDetached(&sig, msg, &kp.public_key);

    // The public-key half of the secret key matches the derived public key.
    try testing.expectEqualSlices(u8, &kp.public_key, kp.secret_key[32..64]);

    // And the same seed redrives the same public key (the secret-key layout
    // is `seed || pk`).
    const seed: *const [seed_length]u8 = kp.secret_key[0..seed_length];
    const kp2 = keyPairFromSeed(seed);
    try testing.expectEqualSlices(u8, &kp.public_key, &kp2.public_key);
    try testing.expectEqualSlices(u8, &kp.secret_key, &kp2.secret_key);
}

test "Ed25519 verifyDetached rejects forgeries" {
    var prng = std.Random.DefaultPrng.init(0xdead_ed25519_5678);
    const rand = prng.random();
    var seed: [32]u8 = undefined;
    var msg: [96]u8 = undefined;
    rand.bytes(&seed);
    rand.bytes(&msg);
    const kp = keyPairFromSeed(&seed);

    var sig: [signature_length]u8 = undefined;
    signDetached(&sig, &msg, &kp.secret_key);
    try verifyDetached(&sig, &msg, &kp.public_key); // baseline: a genuine signature verifies

    {
        var bad = sig;
        bad[3] ^= 0x01; // flip a bit in R
        try testing.expectError(error.AuthFailed, verifyDetached(&bad, &msg, &kp.public_key));
    }
    {
        var bad = sig;
        bad[40] ^= 0x01; // flip a bit in S
        try testing.expectError(error.AuthFailed, verifyDetached(&bad, &msg, &kp.public_key));
    }
    {
        var bad_msg = msg;
        bad_msg[10] ^= 0x80;
        try testing.expectError(error.AuthFailed, verifyDetached(&sig, &bad_msg, &kp.public_key));
    }
    {
        // Wrong (but valid) public key — generate a fresh key pair and use its pk.
        var other_seed: [32]u8 = undefined;
        rand.bytes(&other_seed);
        const other_kp = keyPairFromSeed(&other_seed);
        try testing.expectError(error.AuthFailed, verifyDetached(&sig, &msg, &other_kp.public_key));
    }
    {
        // Public key that does not decode to a curve point. The Ed25519
        // encoding embeds y in the low 255 bits and constrains y < p; a y of
        // all 0xFF lies above p, but more importantly the resulting (x, y)
        // pair fails the curve equation. unpackneg returns InvalidEncoding,
        // which surfaces as error.AuthFailed.
        const bad_pk = [_]u8{0xff} ** 32;
        try testing.expectError(error.AuthFailed, verifyDetached(&sig, &msg, &bad_pk));
    }
}

test "Ed25519 open rejects forgeries and short input" {
    var prng = std.Random.DefaultPrng.init(0xbad_ed_25519_def0);
    const rand = prng.random();
    var seed: [32]u8 = undefined;
    var msg: [64]u8 = undefined;
    rand.bytes(&seed);
    rand.bytes(&msg);
    const kp = keyPairFromSeed(&seed);

    var signed: [msg.len + signature_length]u8 = undefined;
    sign(&signed, &msg, &kp.secret_key);

    var opened: [msg.len]u8 = undefined;
    try open(&opened, &signed, &kp.public_key); // genuine

    {
        var bad = signed;
        bad[20] ^= 0x01; // flip a bit in the signature
        try testing.expectError(error.AuthFailed, open(&opened, &bad, &kp.public_key));
    }
    {
        var bad = signed;
        bad[signature_length + 5] ^= 0x80; // flip a bit in the message
        try testing.expectError(error.AuthFailed, open(&opened, &bad, &kp.public_key));
    }
    {
        // Anything shorter than the signature cannot authenticate.
        try testing.expectError(error.AuthFailed, open(opened[0..0], signed[0..32], &kp.public_key));
    }
}

test "Ed25519 is deterministic" {
    // Two signatures over the same (key, message) must be byte-equal — the
    // nonce is derived from the message, not random.
    var seed: [32]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0xde7_e2_5519_d05);
    prng.random().bytes(&seed);
    const kp = keyPairFromSeed(&seed);

    const msg = "Ed25519 signatures are deterministic by construction";
    var sig_a: [signature_length]u8 = undefined;
    var sig_b: [signature_length]u8 = undefined;
    signDetached(&sig_a, msg, &kp.secret_key);
    signDetached(&sig_b, msg, &kp.secret_key);
    try testing.expectEqualSlices(u8, &sig_a, &sig_b);
}

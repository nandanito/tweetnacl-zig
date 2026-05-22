//! box — Curve25519-XSalsa20-Poly1305 public-key authenticated encryption.
//!
//! This is NaCl's `crypto_box`: it encrypts a message so that only the holder
//! of the recipient's secret key can read it, and authenticates it so the
//! recipient knows it came from the holder of the sender's secret key. Output
//! is wire-compatible with TweetNaCl and tweetnacl-js — a 16-byte Poly1305
//! tag followed by the ciphertext.
//!
//! `box` is the composition of X25519 key agreement with `secretbox`. The two
//! parties first derive a shared key with `beforenm`; that key then drives the
//! exact XSalsa20-Poly1305 construction `secretbox` uses. `seal` / `open` do
//! both steps at once. When several messages travel between the same pair of
//! keys, derive the shared key once and reuse it via `sealAfternm` /
//! `openAfternm` — this skips the scalar multiplication on every message.
//!
//! A low-order ("weak") public key would collapse the shared key to a fixed,
//! publicly-known value; `beforenm` / `seal` / `open` reject one with
//! `error.WeakPublicKey` before deriving anything.
//!
//! As with `secretbox`, a `(key, nonce)` pair must never be reused; the
//! 24-byte nonce is large enough to be chosen at random.
const std = @import("std");
const salsa20 = @import("salsa20.zig");
const scalarmult = @import("scalarmult.zig");
const secretbox = @import("secretbox.zig");

/// Public-key length in bytes.
pub const public_key_length = 32;
/// Secret-key length in bytes.
pub const secret_key_length = 32;
/// Precomputed-shared-key length in bytes (it is a `secretbox` key).
pub const shared_key_length = 32;
/// Nonce length in bytes.
pub const nonce_length = 24;
/// Size difference between a sealed box and its plaintext (the tag length).
pub const overhead = secretbox.overhead;

/// Returned when a public key is a low-order Curve25519 point. Scalar
/// multiplication with such a key collapses to the all-zero output regardless
/// of the secret scalar, which would derive a fixed, publicly-known shared
/// key — so `beforenm`, `seal` and `open` reject it. (libsodium and
/// `std.crypto.nacl.Box` reject this case too; TweetNaCl itself does not.)
pub const WeakPublicKeyError = error{WeakPublicKey};

/// HSalsa20 is keyed with a 16-byte all-zero nonce when hashing the raw X25519
/// output into the shared key (NaCl's `crypto_box_beforenm`).
const zero_nonce: [16]u8 = [_]u8{0} ** 16;

/// An X25519 key pair. The secret key is the raw 32 random bytes — clamping
/// happens inside scalar multiplication, per NaCl convention — and the public
/// key is `secret_key · basepoint`.
pub const KeyPair = struct {
    public_key: [public_key_length]u8,
    secret_key: [secret_key_length]u8,

    /// Wipes the secret key. The public key is not secret and is left intact.
    pub fn wipe(self: *KeyPair) void {
        std.crypto.secureZero(u8, &self.secret_key);
    }
};

/// Derives the key pair for a given 32-byte secret key.
pub fn keyPairFromSecretKey(secret_key: *const [secret_key_length]u8) KeyPair {
    var kp: KeyPair = .{ .public_key = undefined, .secret_key = secret_key.* };
    scalarmult.scalarmultBase(&kp.public_key, &kp.secret_key);
    return kp;
}

/// Generates a fresh key pair, drawing the secret key from `io`'s CSPRNG.
pub fn keyPair(io: std.Io) KeyPair {
    var kp: KeyPair = undefined;
    io.random(&kp.secret_key);
    scalarmult.scalarmultBase(&kp.public_key, &kp.secret_key);
    return kp;
}

/// Computes the precomputed shared key for a `(peer public key, own secret
/// key)` pair: `HSalsa20(0, X25519(secret_key, public_key))`.
///
/// Both parties of a conversation arrive at the same shared key — sender from
/// `(recipient_public, sender_secret)`, recipient from `(sender_public,
/// recipient_secret)`. Reuse it with `sealAfternm` / `openAfternm`.
///
/// Returns `error.WeakPublicKey` if `public_key` is a low-order point.
pub fn beforenm(
    shared_key: *[shared_key_length]u8,
    public_key: *const [public_key_length]u8,
    secret_key: *const [secret_key_length]u8,
) WeakPublicKeyError!void {
    // X25519 Diffie-Hellman, then HSalsa20 to whiten the raw curve point into
    // a uniformly-distributed symmetric key.
    var dh: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &dh);
    scalarmult.scalarmult(&dh, secret_key, public_key);

    // A low-order public key forces the X25519 output to all-zero whatever the
    // secret scalar is; hashing that would yield a fixed, publicly-known
    // shared key. Reject it before deriving anything. The OR-reduce keeps the
    // lone branch off any secret — the outcome depends only on `public_key`.
    var nonzero: u8 = 0;
    for (dh) |b| nonzero |= b;
    if (nonzero == 0) return error.WeakPublicKey;

    salsa20.hsalsa20(shared_key, &zero_nonce, &dh);
}

/// Encrypts and authenticates `msg` with a precomputed shared key, writing
/// `msg.len + overhead` bytes to `out`: a 16-byte tag followed by ciphertext.
pub fn sealAfternm(
    out: []u8,
    msg: []const u8,
    nonce: *const [nonce_length]u8,
    shared_key: *const [shared_key_length]u8,
) void {
    secretbox.seal(out, msg, nonce, shared_key);
}

/// Verifies and decrypts a box sealed with a precomputed shared key. `boxed`
/// is a 16-byte tag followed by ciphertext; `out` receives
/// `boxed.len - overhead` plaintext bytes.
///
/// Returns `error.AuthFailed` — without writing any plaintext — if
/// authentication fails.
pub fn openAfternm(
    out: []u8,
    boxed: []const u8,
    nonce: *const [nonce_length]u8,
    shared_key: *const [shared_key_length]u8,
) error{AuthFailed}!void {
    return secretbox.open(out, boxed, nonce, shared_key);
}

/// Encrypts and authenticates `msg` for `recipient_public_key`, from the
/// holder of `sender_secret_key`. Writes `msg.len + overhead` bytes to `out`:
/// a 16-byte tag followed by ciphertext.
///
/// Returns `error.WeakPublicKey` — without writing `out` — if
/// `recipient_public_key` is a low-order point.
pub fn seal(
    out: []u8,
    msg: []const u8,
    nonce: *const [nonce_length]u8,
    recipient_public_key: *const [public_key_length]u8,
    sender_secret_key: *const [secret_key_length]u8,
) WeakPublicKeyError!void {
    var shared_key: [shared_key_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &shared_key);
    try beforenm(&shared_key, recipient_public_key, sender_secret_key);
    sealAfternm(out, msg, nonce, &shared_key);
}

/// Verifies and decrypts a box addressed to the holder of
/// `recipient_secret_key`, sent by the holder of `sender_public_key`. `boxed`
/// is a 16-byte tag followed by ciphertext; `out` receives
/// `boxed.len - overhead` plaintext bytes.
///
/// Returns — without writing any plaintext — `error.WeakPublicKey` if
/// `sender_public_key` is a low-order point, or `error.AuthFailed` if
/// authentication fails.
pub fn open(
    out: []u8,
    boxed: []const u8,
    nonce: *const [nonce_length]u8,
    sender_public_key: *const [public_key_length]u8,
    recipient_secret_key: *const [secret_key_length]u8,
) (WeakPublicKeyError || error{AuthFailed})!void {
    var shared_key: [shared_key_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &shared_key);
    try beforenm(&shared_key, sender_public_key, recipient_secret_key);
    return openAfternm(out, boxed, nonce, &shared_key);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

// Alice's secret key and Bob's public key — NaCl `tests/box.c`, identical to
// the alice/bob values in RFC 7748 §6.1.
const alice_sk = [32]u8{
    0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
    0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
    0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
    0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
};
const bob_pk = [32]u8{
    0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4,
    0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
    0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d,
    0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f,
};
// Bob's secret key — RFC 7748 §6.1; `bob_pk` is its public key.
const bob_sk = [32]u8{
    0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b,
    0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e, 0xe6,
    0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd,
    0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb,
};

test "box beforenm — NaCl tests/box.c shared key (secretbox firstkey)" {
    // crypto_box_beforenm(alice_sk, bob_pk) is the 32-byte "firstkey" used as
    // the key in NaCl `tests/secretbox.c` — a published cross-test vector.
    const firstkey = [32]u8{
        0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85, 0xd4,
        0x62, 0xcd, 0x51, 0x19, 0x7a, 0x9a, 0x46, 0xc7,
        0x60, 0x09, 0x54, 0x9e, 0xac, 0x64, 0x74, 0xf2,
        0x06, 0xc4, 0xee, 0x08, 0x44, 0xf6, 0x83, 0x89,
    };

    var shared: [32]u8 = undefined;
    try beforenm(&shared, &bob_pk, &alice_sk);
    try testing.expectEqualSlices(u8, &firstkey, &shared);

    // The recipient derives the identical key from the opposite pair, and
    // Alice's public key is recovered from her secret key.
    const alice_pk = keyPairFromSecretKey(&alice_sk).public_key;
    try beforenm(&shared, &alice_pk, &bob_sk);
    try testing.expectEqualSlices(u8, &firstkey, &shared);
}

test "box seal — NaCl tests/box.c known-answer vector" {
    const nonce = [24]u8{
        0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73,
        0xcd, 0x62, 0xbd, 0xa8, 0x75, 0xfc, 0x73, 0xd6,
        0x82, 0x19, 0xe0, 0x03, 0x6b, 0x7a, 0x0b, 0x37,
    };
    // NaCl `tests/box.c` message — its 32-byte ZEROBYTES prefix dropped, as
    // tweetnacl-js does; this leaves the 131-byte plaintext.
    const msg = [131]u8{
        0xbe, 0x07, 0x5f, 0xc5, 0x3c, 0x81, 0xf2, 0xd5,
        0xcf, 0x14, 0x13, 0x16, 0xeb, 0xeb, 0x0c, 0x7b,
        0x52, 0x28, 0xc5, 0x2a, 0x4c, 0x62, 0xcb, 0xd4,
        0x4b, 0x66, 0x84, 0x9b, 0x64, 0x24, 0x4f, 0xfc,
        0xe5, 0xec, 0xba, 0xaf, 0x33, 0xbd, 0x75, 0x1a,
        0x1a, 0xc7, 0x28, 0xd4, 0x5e, 0x6c, 0x61, 0x29,
        0x6c, 0xdc, 0x3c, 0x01, 0x23, 0x35, 0x61, 0xf4,
        0x1d, 0xb6, 0x6c, 0xce, 0x31, 0x4a, 0xdb, 0x31,
        0x0e, 0x3b, 0xe8, 0x25, 0x0c, 0x46, 0xf0, 0x6d,
        0xce, 0xea, 0x3a, 0x7f, 0xa1, 0x34, 0x80, 0x57,
        0xe2, 0xf6, 0x55, 0x6a, 0xd6, 0xb1, 0x31, 0x8a,
        0x02, 0x4a, 0x83, 0x8f, 0x21, 0xaf, 0x1f, 0xde,
        0x04, 0x89, 0x77, 0xeb, 0x48, 0xf5, 0x9f, 0xfd,
        0x49, 0x24, 0xca, 0x1c, 0x60, 0x90, 0x2e, 0x52,
        0xf0, 0xa0, 0x89, 0xbc, 0x76, 0x89, 0x70, 0x40,
        0xe0, 0x82, 0xf9, 0x37, 0x76, 0x38, 0x48, 0x64,
        0x5e, 0x07, 0x05,
    };
    // Expected output: NaCl `tests/box.c` ciphertext `c` with its 16-byte
    // BOXZEROBYTES prefix dropped — the 16-byte tag followed by ciphertext.
    const expected = [131 + overhead]u8{
        0xf3, 0xff, 0xc7, 0x70, 0x3f, 0x94, 0x00, 0xe5,
        0x2a, 0x7d, 0xfb, 0x4b, 0x3d, 0x33, 0x05, 0xd9,
        0x8e, 0x99, 0x3b, 0x9f, 0x48, 0x68, 0x12, 0x73,
        0xc2, 0x96, 0x50, 0xba, 0x32, 0xfc, 0x76, 0xce,
        0x48, 0x33, 0x2e, 0xa7, 0x16, 0x4d, 0x96, 0xa4,
        0x47, 0x6f, 0xb8, 0xc5, 0x31, 0xa1, 0x18, 0x6a,
        0xc0, 0xdf, 0xc1, 0x7c, 0x98, 0xdc, 0xe8, 0x7b,
        0x4d, 0xa7, 0xf0, 0x11, 0xec, 0x48, 0xc9, 0x72,
        0x71, 0xd2, 0xc2, 0x0f, 0x9b, 0x92, 0x8f, 0xe2,
        0x27, 0x0d, 0x6f, 0xb8, 0x63, 0xd5, 0x17, 0x38,
        0xb4, 0x8e, 0xee, 0xe3, 0x14, 0xa7, 0xcc, 0x8a,
        0xb9, 0x32, 0x16, 0x45, 0x48, 0xe5, 0x26, 0xae,
        0x90, 0x22, 0x43, 0x68, 0x51, 0x7a, 0xcf, 0xea,
        0xbd, 0x6b, 0xb3, 0x73, 0x2b, 0xc0, 0xe9, 0xda,
        0x99, 0x83, 0x2b, 0x61, 0xca, 0x01, 0xb6, 0xde,
        0x56, 0x24, 0x4a, 0x9e, 0x88, 0xd5, 0xf9, 0xb3,
        0x79, 0x73, 0xf6, 0x22, 0xa4, 0x3d, 0x14, 0xa6,
        0x59, 0x9b, 0x1f, 0x65, 0x4c, 0xb4, 0x5a, 0x74,
        0xe3, 0x55, 0xa5,
    };

    var boxed: [msg.len + overhead]u8 = undefined;
    try seal(&boxed, &msg, &nonce, &bob_pk, &alice_sk);
    try testing.expectEqualSlices(u8, &expected, &boxed);

    // And the recipient recovers the plaintext from the opposite key pair.
    const alice_pk = keyPairFromSecretKey(&alice_sk).public_key;
    var opened: [msg.len]u8 = undefined;
    try open(&opened, &boxed, &nonce, &alice_pk, &bob_sk);
    try testing.expectEqualSlices(u8, &msg, &opened);
}

test "box keyPair derives the matching X25519 public key" {
    // basepoint u = 9; `keyPairFromSecretKey` must agree with std's X25519.
    const basepoint = [_]u8{9} ++ [_]u8{0} ** 31;
    var prng = std.Random.DefaultPrng.init(0xb0c5_1337_cafe_d00d);
    const rand = prng.random();
    var iter: usize = 0;
    while (iter < 64) : (iter += 1) {
        var sk: [32]u8 = undefined;
        rand.bytes(&sk);
        const kp = keyPairFromSecretKey(&sk);
        try testing.expectEqualSlices(u8, &sk, &kp.secret_key);
        const expected = try std.crypto.dh.X25519.scalarmult(sk, basepoint);
        try testing.expectEqualSlices(u8, &expected, &kp.public_key);
    }

    // A randomly generated pair round-trips a message, and re-deriving from
    // its secret key reproduces the same public key.
    const io = std.testing.io;
    const sender = keyPair(io);
    const recipient = keyPair(io);
    try testing.expectEqualSlices(
        u8,
        &recipient.public_key,
        &keyPairFromSecretKey(&recipient.secret_key).public_key,
    );

    var nonce: [24]u8 = undefined;
    io.random(&nonce);
    const message = "generated key pairs interoperate";
    var boxed: [message.len + overhead]u8 = undefined;
    try seal(&boxed, message, &nonce, &recipient.public_key, &sender.secret_key);
    var opened: [message.len]u8 = undefined;
    try open(&opened, &boxed, &nonce, &sender.public_key, &recipient.secret_key);
    try testing.expectEqualSlices(u8, message, &opened);
}

test "box beforenm matches std.crypto.nacl.Box.createSharedSecret" {
    var prng = std.Random.DefaultPrng.init(0x5ec2_b07b_ef02_e123);
    const rand = prng.random();
    var iter: usize = 0;
    while (iter < 100) : (iter += 1) {
        var sk_a: [32]u8 = undefined;
        var sk_b: [32]u8 = undefined;
        rand.bytes(&sk_a);
        rand.bytes(&sk_b);
        const pk_b = keyPairFromSecretKey(&sk_b).public_key;

        var mine: [32]u8 = undefined;
        try beforenm(&mine, &pk_b, &sk_a);
        const theirs = try std.crypto.nacl.Box.createSharedSecret(pk_b, sk_a);
        try testing.expectEqualSlices(u8, &theirs, &mine);
    }
}

test "box seal matches std.crypto.nacl.Box across sizes" {
    const StdBox = std.crypto.nacl.Box;
    var prng = std.Random.DefaultPrng.init(0xb0c5_5ea1_ed00_1234);
    const rand = prng.random();
    const sizes = [_]usize{ 0, 1, 16, 31, 32, 33, 63, 64, 65, 127, 128, 200, 1000 };
    for (sizes) |len| {
        var iter: usize = 0;
        while (iter < 16) : (iter += 1) {
            var sk_a: [32]u8 = undefined;
            var sk_b: [32]u8 = undefined;
            var nonce: [24]u8 = undefined;
            var msg: [1000]u8 = undefined;
            rand.bytes(&sk_a);
            rand.bytes(&sk_b);
            rand.bytes(&nonce);
            rand.bytes(msg[0..len]);
            const pk_b = keyPairFromSecretKey(&sk_b).public_key;

            var mine: [1000 + overhead]u8 = undefined;
            var reference: [1000 + overhead]u8 = undefined;
            try seal(mine[0 .. len + overhead], msg[0..len], &nonce, &pk_b, &sk_a);
            try StdBox.seal(reference[0 .. len + overhead], msg[0..len], nonce, pk_b, sk_a);
            try testing.expectEqualSlices(u8, reference[0 .. len + overhead], mine[0 .. len + overhead]);
        }
    }
}

test "box round-trips, including the afternm path" {
    var prng = std.Random.DefaultPrng.init(0x0ce4_11ca_b0bf_eed1);
    const rand = prng.random();
    var sk_a: [32]u8 = undefined;
    var sk_b: [32]u8 = undefined;
    var nonce: [24]u8 = undefined;
    var msg: [300]u8 = undefined;
    rand.bytes(&sk_a);
    rand.bytes(&sk_b);
    rand.bytes(&nonce);
    rand.bytes(&msg);
    const pk_a = keyPairFromSecretKey(&sk_a).public_key;
    const pk_b = keyPairFromSecretKey(&sk_b).public_key;

    // One-shot seal / open.
    var boxed: [300 + overhead]u8 = undefined;
    try seal(&boxed, &msg, &nonce, &pk_b, &sk_a);
    var opened: [300]u8 = undefined;
    try open(&opened, &boxed, &nonce, &pk_a, &sk_b);
    try testing.expectEqualSlices(u8, &msg, &opened);

    // The afternm path with a precomputed key produces an identical box and
    // opens it the same way.
    var shared: [shared_key_length]u8 = undefined;
    try beforenm(&shared, &pk_b, &sk_a);
    var boxed_afternm: [300 + overhead]u8 = undefined;
    sealAfternm(&boxed_afternm, &msg, &nonce, &shared);
    try testing.expectEqualSlices(u8, &boxed, &boxed_afternm);

    var shared_recipient: [shared_key_length]u8 = undefined;
    try beforenm(&shared_recipient, &pk_a, &sk_b);
    var opened_afternm: [300]u8 = undefined;
    try openAfternm(&opened_afternm, &boxed_afternm, &nonce, &shared_recipient);
    try testing.expectEqualSlices(u8, &msg, &opened_afternm);
}

test "box interoperates with std.crypto.nacl.Box both ways" {
    const StdBox = std.crypto.nacl.Box;
    var prng = std.Random.DefaultPrng.init(0xa11c_eb0b_face_0717);
    const rand = prng.random();
    var sk_a: [32]u8 = undefined;
    var sk_b: [32]u8 = undefined;
    var nonce: [24]u8 = undefined;
    var msg: [128]u8 = undefined;
    rand.bytes(&sk_a);
    rand.bytes(&sk_b);
    rand.bytes(&nonce);
    rand.bytes(&msg);
    const pk_a = keyPairFromSecretKey(&sk_a).public_key;
    const pk_b = keyPairFromSecretKey(&sk_b).public_key;

    // open() must accept what std sealed for the recipient.
    var std_boxed: [128 + overhead]u8 = undefined;
    try StdBox.seal(&std_boxed, &msg, nonce, pk_b, sk_a);
    var opened: [128]u8 = undefined;
    try open(&opened, &std_boxed, &nonce, &pk_a, &sk_b);
    try testing.expectEqualSlices(u8, &msg, &opened);

    // std must accept and open what seal() produced.
    var boxed: [128 + overhead]u8 = undefined;
    try seal(&boxed, &msg, &nonce, &pk_b, &sk_a);
    var std_opened: [128]u8 = undefined;
    try StdBox.open(&std_opened, &boxed, nonce, pk_a, sk_b);
    try testing.expectEqualSlices(u8, &msg, &std_opened);
}

test "box open rejects tampering" {
    var prng = std.Random.DefaultPrng.init(0xdead_b0c5_1234_5678);
    const rand = prng.random();
    var sk_a: [32]u8 = undefined;
    var sk_b: [32]u8 = undefined;
    var nonce: [24]u8 = undefined;
    var msg: [96]u8 = undefined;
    rand.bytes(&sk_a);
    rand.bytes(&sk_b);
    rand.bytes(&nonce);
    rand.bytes(&msg);
    const pk_a = keyPairFromSecretKey(&sk_a).public_key;
    const pk_b = keyPairFromSecretKey(&sk_b).public_key;

    var boxed: [96 + overhead]u8 = undefined;
    try seal(&boxed, &msg, &nonce, &pk_b, &sk_a);

    var opened: [96]u8 = undefined;
    try open(&opened, &boxed, &nonce, &pk_a, &sk_b); // a genuine box opens

    {
        var bad = boxed;
        bad[3] ^= 0x01; // flip a tag byte
        try testing.expectError(error.AuthFailed, open(&opened, &bad, &nonce, &pk_a, &sk_b));
    }
    {
        var bad = boxed;
        bad[overhead + 10] ^= 0x80; // flip a ciphertext byte
        try testing.expectError(error.AuthFailed, open(&opened, &bad, &nonce, &pk_a, &sk_b));
    }
    {
        var bad_nonce = nonce;
        bad_nonce[0] ^= 0x01;
        try testing.expectError(error.AuthFailed, open(&opened, &boxed, &bad_nonce, &pk_a, &sk_b));
    }
    {
        var bad_pk = pk_a; // wrong sender public key → wrong shared key
        bad_pk[0] ^= 0x01;
        try testing.expectError(error.AuthFailed, open(&opened, &boxed, &nonce, &bad_pk, &sk_b));
    }
    {
        // Wrong recipient secret key → wrong shared key. Byte 16 is perturbed
        // because scalar clamping discards the low 3 bits of byte 0 and the
        // top 2 of byte 31 — flipping a cleared bit there would be a no-op.
        var bad_sk = sk_b;
        bad_sk[16] ^= 0x01;
        try testing.expectError(error.AuthFailed, open(&opened, &boxed, &nonce, &pk_a, &bad_sk));
    }
    {
        // A box shorter than the tag cannot authenticate.
        try testing.expectError(error.AuthFailed, open(opened[0..0], boxed[0..8], &nonce, &pk_a, &sk_b));
    }
    {
        // openAfternm with the wrong precomputed key also fails.
        var bad_shared: [shared_key_length]u8 = undefined;
        try beforenm(&bad_shared, &pk_a, &sk_b);
        bad_shared[0] ^= 0x01;
        try testing.expectError(error.AuthFailed, openAfternm(&opened, &boxed, &nonce, &bad_shared));
    }
}

test "box rejects weak (low-order) public keys" {
    // Scalar multiplication with any of these Curve25519 u-coordinates
    // collapses to the all-zero output regardless of the secret scalar, so the
    // shared key would be a fixed, publicly-known value. `beforenm`, `seal`
    // and `open` must reject them. Set drawn from libsodium's blacklist;
    // `std.crypto.nacl.Box` rejects this case too.
    const weak_keys = [_][32]u8{
        [_]u8{0} ** 32, // u = 0  (order 4)
        [_]u8{1} ++ [_]u8{0} ** 31, // u = 1  (order 4)
        [32]u8{ // order 8
            0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae,
            0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a,
            0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd,
            0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00,
        },
        [32]u8{ // order 8
            0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24,
            0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b,
            0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86,
            0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57,
        },
        [_]u8{0xec} ++ [_]u8{0xff} ** 30 ++ [_]u8{0x7f}, // p - 1  (order 2)
    };

    var prng = std.Random.DefaultPrng.init(0x0bad_b0c5_0bad_b0c5);
    const rand = prng.random();
    var sk: [32]u8 = undefined;
    var nonce: [24]u8 = undefined;
    rand.bytes(&sk);
    rand.bytes(&nonce);
    const valid_pk = keyPairFromSecretKey(&sk).public_key;
    const msg = "weak public keys must be rejected";

    for (weak_keys) |weak| {
        // beforenm rejects a weak key on either side of the agreement.
        var shared: [shared_key_length]u8 = undefined;
        try testing.expectError(error.WeakPublicKey, beforenm(&shared, &weak, &sk));

        // seal refuses to encrypt to a weak recipient key.
        var boxed: [msg.len + overhead]u8 = undefined;
        try testing.expectError(error.WeakPublicKey, seal(&boxed, msg, &nonce, &weak, &sk));

        // open refuses a weak claimed sender key. The box itself is genuine,
        // so the rejection is attributable to the key, not the ciphertext.
        try seal(&boxed, msg, &nonce, &valid_pk, &sk);
        var opened: [msg.len]u8 = undefined;
        try testing.expectError(error.WeakPublicKey, open(&opened, &boxed, &nonce, &weak, &sk));
    }
}

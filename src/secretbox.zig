//! secretbox — XSalsa20-Poly1305 authenticated encryption (symmetric).
//!
//! This is NaCl's `crypto_secretbox`: it encrypts a message and attaches a
//! Poly1305 tag so that any tampering is detected on open. Output is
//! wire-compatible with TweetNaCl and tweetnacl-js — a 16-byte tag followed
//! by the ciphertext.
//!
//! A `(key, nonce)` pair must never be reused for two messages. The 24-byte
//! nonce is large enough to be chosen at random.
const std = @import("std");
const salsa20 = @import("salsa20.zig");
const poly1305 = @import("poly1305.zig");

/// Key length in bytes.
pub const key_length = 32;
/// Nonce length in bytes.
pub const nonce_length = 24;
/// Size difference between a sealed box and its plaintext (the tag length).
pub const overhead = 16;

/// XSalsa20 keystream state for one (nonce, key): the derived Salsa20 subkey,
/// the running 16-byte input block, and keystream block 0.
const Keystream = struct {
    subkey: [32]u8,
    input: [16]u8,
    block0: [64]u8,

    /// The one-time Poly1305 key is the first 32 bytes of the keystream.
    fn polyKey(self: *const Keystream) *const [32]u8 {
        return self.block0[0..32];
    }

    fn wipe(self: *Keystream) void {
        std.crypto.secureZero(u8, &self.subkey);
        std.crypto.secureZero(u8, &self.block0);
    }
};

/// Derives the XSalsa20 subkey and generates keystream block 0.
fn beginKeystream(nonce: *const [nonce_length]u8, key: *const [key_length]u8) Keystream {
    var ks: Keystream = undefined;
    salsa20.hsalsa20(&ks.subkey, nonce[0..16], key);
    @memcpy(ks.input[0..8], nonce[16..24]);
    @memset(ks.input[8..16], 0);
    salsa20.core(&ks.block0, &ks.input, &ks.subkey);
    return ks;
}

/// XORs `src` into `dst` with the keystream, writing `src.len` bytes.
/// `dst` must be at least `src.len` long — the slice indexing inside is the
/// length contract, and a short `dst` triggers a slice-bounds panic in
/// safety-checked builds. The message keystream begins at byte 32 — block
/// 0's first 32 bytes are reserved for the Poly1305 key. Symmetric: this
/// both encrypts and decrypts.
fn xorMessage(ks: *Keystream, dst: []u8, src: []const u8) void {
    // First (up to) 32 bytes: the second half of keystream block 0.
    const head = @min(@as(usize, 32), src.len);
    for (0..head) |i| dst[i] = src[i] ^ ks.block0[32 + i];

    // Remaining bytes: full keystream blocks 1, 2, ...
    var block: [64]u8 = undefined;
    defer std.crypto.secureZero(u8, &block);
    var offset: usize = 32;
    var counter: u64 = 1;
    while (offset < src.len) : ({
        offset += 64;
        counter += 1;
    }) {
        std.mem.writeInt(u64, ks.input[8..16], counter, .little);
        salsa20.core(&block, &ks.input, &ks.subkey);
        const n = @min(@as(usize, 64), src.len - offset);
        for (0..n) |i| dst[offset + i] = src[offset + i] ^ block[i];
    }
}

/// Encrypts and authenticates `msg`, writing `msg.len + overhead` bytes to
/// `out`: a 16-byte tag followed by the ciphertext. `out` must be exactly
/// that long — a shorter slice triggers a slice-bounds panic in
/// safety-checked builds.
pub fn seal(
    out: []u8,
    msg: []const u8,
    nonce: *const [nonce_length]u8,
    key: *const [key_length]u8,
) void {
    var ks = beginKeystream(nonce, key);
    defer ks.wipe();

    const ciphertext = out[overhead..][0..msg.len];
    xorMessage(&ks, ciphertext, msg);
    poly1305.auth(out[0..overhead], ciphertext, ks.polyKey());
}

/// Verifies and decrypts a sealed box. `boxed` is a 16-byte tag followed by
/// ciphertext; `out` receives `boxed.len - overhead` plaintext bytes.
///
/// Returns `error.AuthFailed` — without writing any plaintext — if
/// authentication fails.
pub fn open(
    out: []u8,
    boxed: []const u8,
    nonce: *const [nonce_length]u8,
    key: *const [key_length]u8,
) error{AuthFailed}!void {
    if (boxed.len < overhead) return error.AuthFailed;
    const ciphertext = boxed[overhead..];

    var ks = beginKeystream(nonce, key);
    defer ks.wipe();

    // Authenticate before releasing any plaintext.
    try poly1305.verify(boxed[0..overhead], ciphertext, ks.polyKey());
    // `out` must have length `boxed.len - overhead`; a shorter slice
    // triggers a slice-bounds panic in safety-checked builds.
    xorMessage(&ks, out[0..ciphertext.len], ciphertext);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "secretbox seal matches std.crypto.nacl across sizes" {
    const StdBox = std.crypto.nacl.SecretBox;
    var prng = std.Random.DefaultPrng.init(0x5ec701b0c0ffee42);
    const rand = prng.random();
    const sizes = [_]usize{ 0, 1, 16, 31, 32, 33, 63, 64, 65, 200, 1000 };
    for (sizes) |len| {
        var iter: usize = 0;
        while (iter < 24) : (iter += 1) {
            var key: [32]u8 = undefined;
            var nonce: [24]u8 = undefined;
            var msg: [1000]u8 = undefined;
            rand.bytes(&key);
            rand.bytes(&nonce);
            rand.bytes(msg[0..len]);

            var mine: [1000 + overhead]u8 = undefined;
            var reference: [1000 + overhead]u8 = undefined;
            seal(mine[0 .. len + overhead], msg[0..len], &nonce, &key);
            StdBox.seal(reference[0 .. len + overhead], msg[0..len], nonce, key);
            try testing.expectEqualSlices(u8, reference[0 .. len + overhead], mine[0 .. len + overhead]);
        }
    }
}

test "secretbox round-trips" {
    var prng = std.Random.DefaultPrng.init(0x0011223344556677);
    const rand = prng.random();
    var key: [32]u8 = undefined;
    var nonce: [24]u8 = undefined;
    var msg: [300]u8 = undefined;
    rand.bytes(&key);
    rand.bytes(&nonce);
    rand.bytes(&msg);

    var boxed: [300 + overhead]u8 = undefined;
    seal(&boxed, &msg, &nonce, &key);

    var opened: [300]u8 = undefined;
    try open(&opened, &boxed, &nonce, &key);
    try testing.expectEqualSlices(u8, &msg, &opened);
}

test "secretbox interoperates with std.crypto.nacl both ways" {
    const StdBox = std.crypto.nacl.SecretBox;
    var prng = std.Random.DefaultPrng.init(0xa11ce0b0bcafe123);
    const rand = prng.random();
    var key: [32]u8 = undefined;
    var nonce: [24]u8 = undefined;
    var msg: [128]u8 = undefined;
    rand.bytes(&key);
    rand.bytes(&nonce);
    rand.bytes(&msg);

    // open() must accept what std sealed.
    var std_boxed: [128 + overhead]u8 = undefined;
    StdBox.seal(&std_boxed, &msg, nonce, key);
    var opened: [128]u8 = undefined;
    try open(&opened, &std_boxed, &nonce, &key);
    try testing.expectEqualSlices(u8, &msg, &opened);

    // std must accept what seal() produced.
    var boxed: [128 + overhead]u8 = undefined;
    seal(&boxed, &msg, &nonce, &key);
    var std_opened: [128]u8 = undefined;
    try StdBox.open(&std_opened, &boxed, nonce, key);
    try testing.expectEqualSlices(u8, &msg, &std_opened);
}

test "secretbox open rejects tampering" {
    var prng = std.Random.DefaultPrng.init(0xdeadbeef12345678);
    const rand = prng.random();
    var key: [32]u8 = undefined;
    var nonce: [24]u8 = undefined;
    var msg: [96]u8 = undefined;
    rand.bytes(&key);
    rand.bytes(&nonce);
    rand.bytes(&msg);

    var boxed: [96 + overhead]u8 = undefined;
    seal(&boxed, &msg, &nonce, &key);

    var opened: [96]u8 = undefined;
    try open(&opened, &boxed, &nonce, &key); // a genuine box opens

    {
        var bad = boxed;
        bad[3] ^= 0x01; // flip a tag byte
        try testing.expectError(error.AuthFailed, open(&opened, &bad, &nonce, &key));
    }
    {
        var bad = boxed;
        bad[overhead + 10] ^= 0x80; // flip a ciphertext byte
        try testing.expectError(error.AuthFailed, open(&opened, &bad, &nonce, &key));
    }
    {
        var bad_nonce = nonce;
        bad_nonce[0] ^= 0x01;
        try testing.expectError(error.AuthFailed, open(&opened, &boxed, &bad_nonce, &key));
    }
    {
        var bad_key = key;
        bad_key[0] ^= 0x01;
        try testing.expectError(error.AuthFailed, open(&opened, &boxed, &nonce, &bad_key));
    }
    {
        // A box shorter than the tag cannot authenticate.
        try testing.expectError(error.AuthFailed, open(opened[0..0], boxed[0..8], &nonce, &key));
    }
}

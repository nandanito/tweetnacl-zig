//! SHA-512 hashing with hash.
//!
//! hash computes a fixed 64-byte digest of a message. It takes no key, so —
//! unlike secretbox or box — there is nothing to seal or open: a digest is a
//! one-way fingerprint. The same input always yields the same digest, and
//! changing a single bit changes it completely.
const std = @import("std");
const nacl = @import("tweetnacl_zig");

pub fn main() void {
    const message = "hash: a SHA-512 digest.";

    var digest: [nacl.hash.digest_length]u8 = undefined;
    nacl.hash.hash(&digest, message);

    std.debug.print("message: {s}\n", .{message});
    std.debug.print("sha-512: {s}\n", .{std.fmt.bytesToHex(digest, .lower)[0..]});

    // Flipping one bit of the input produces an unrecognisably different
    // digest — the avalanche property a hash function must have.
    var tweaked = message.*;
    tweaked[0] ^= 0x01;
    nacl.hash.hash(&digest, &tweaked);
    std.debug.print("1 bit changed: {s}\n", .{std.fmt.bytesToHex(digest, .lower)[0..]});
}

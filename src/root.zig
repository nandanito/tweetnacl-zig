//! tweetnacl-zig — a minimal, auditable Zig port of TweetNaCl.
//!
//! `secretbox` and `box` provide authenticated encryption — symmetric and
//! public-key respectively — `hash` is SHA-512, and `sign` is Ed25519
//! signatures. The building-block ciphers, MAC and scalar multiplication are
//! available under `lowlevel`.

pub const secretbox = @import("secretbox.zig");
pub const box = @import("box.zig");
pub const hash = @import("hash.zig");
pub const sign = @import("sign.zig");
pub const lowlevel = @import("lowlevel.zig");

// Pull every module's `test` blocks into `zig build test`.
test {
    _ = @import("secretbox.zig");
    _ = @import("box.zig");
    _ = @import("hash.zig");
    _ = @import("sign.zig");
    _ = @import("lowlevel.zig");
}

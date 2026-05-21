//! tweetnacl-zig — a minimal, auditable Zig port of TweetNaCl.
//!
//! `secretbox` provides authenticated encryption. The remaining high-level
//! primitives (`box`, `sign`, `hash`) are on the roadmap; the building-block
//! ciphers and MAC are available under `lowlevel`.

pub const secretbox = @import("secretbox.zig");
pub const lowlevel = @import("lowlevel.zig");

// Pull every module's `test` blocks into `zig build test`.
test {
    _ = @import("secretbox.zig");
    _ = @import("lowlevel.zig");
}

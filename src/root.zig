//! tweetnacl-zig — a minimal, auditable Zig port of TweetNaCl.
//!
//! High-level authenticated primitives (`secretbox`, `box`, `sign`, `hash`)
//! are on the roadmap. Until they land, the building-block stream ciphers are
//! available under `lowlevel`.

pub const lowlevel = @import("lowlevel.zig");

// Pull every module's `test` blocks into `zig build test`.
test {
    _ = @import("lowlevel.zig");
}

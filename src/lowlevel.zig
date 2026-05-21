//! Low-level cryptographic primitives.
//!
//! These provide confidentiality only. For authenticated encryption, prefer
//! the high-level `secretbox` / `box` APIs (roadmap).
pub const salsa20 = @import("salsa20.zig");
pub const xsalsa20 = @import("xsalsa20.zig");

// Pull every primitive's `test` blocks into `zig build test`.
test {
    _ = salsa20;
    _ = xsalsa20;
}

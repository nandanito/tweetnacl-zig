//! Low-level cryptographic primitives.
//!
//! These provide confidentiality or key agreement only. For authenticated
//! encryption, prefer the high-level `secretbox` / `box` APIs.
pub const salsa20 = @import("salsa20.zig");
pub const xsalsa20 = @import("xsalsa20.zig");
pub const poly1305 = @import("poly1305.zig");
pub const scalarmult = @import("scalarmult.zig");

// Pull every primitive's `test` blocks into `zig build test`.
test {
    _ = salsa20;
    _ = xsalsa20;
    _ = poly1305;
    _ = scalarmult;
}

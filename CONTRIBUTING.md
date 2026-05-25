# Contributing

Thanks for your interest. tweetnacl-zig is security-sensitive code; the bar for
correctness and test coverage is deliberately high. Please read this before
opening a pull request.

## Prerequisites

- Zig **0.16.0**. The project tracks the latest stable release, and CI pins
  this version.

## Everyday commands

```sh
zig build                 # build the static library
zig build test            # run the full test suite
zig fmt --check .         # verify formatting (CI enforces this)
zig fmt .                 # apply formatting
zig build salsa20_demo    # build and run an example (also: xsalsa20_demo)
```

Run one file or filter by test name while iterating:

```sh
zig test src/salsa20.zig
zig test src/salsa20.zig --test-filter "round-trip"
```

Before pushing, run the suite in **every optimize mode** — some bug classes
(uninitialized memory, integer overflow) only surface in specific modes:

```sh
for m in Debug ReleaseSafe ReleaseFast ReleaseSmall; do
  zig build test -Doptimize=$m
done
```

## Project layout

See [ARCHITECTURE.md](ARCHITECTURE.md). In short: high-level authenticated APIs
at the top level, building-block primitives under `lowlevel`, each primitive
composed from the one below it.

## Adding a primitive

1. Implement it in `src/<name>.zig`, following the API conventions in
   ARCHITECTURE.md (array pointers for fixed-size buffers, allocation-free,
   constant-time, `error{AuthFailed}` for authentication failures).
2. Re-export it from `src/lowlevel.zig` (or `src/root.zig` for a high-level
   API) **and** add `_ = <name>;` to that file's `test` block — otherwise its
   tests will not run.
3. Add tests meeting the coverage bar below.
4. `zig fmt .`, run the suite in all optimize modes, then open the PR.

## Test coverage bar

A primitive is not "done" until it has all of:

- [ ] **At least one official Known-Answer Test** — vectors from NaCl's
      `tests/`, the relevant RFC (7748 / 8032 / 8439), or tweetnacl-js.
- [ ] **A differential test against `std.crypto`** over many random inputs and
      sizes.
- [ ] **A round-trip test** (encrypt/decrypt, or sign/verify).
- [ ] **A negative test** for every `open` / verify path — tampered input must
      return `error.AuthFailed`.
- [ ] **An edge-size sweep** including a length that crosses a block boundary
      (0, 1, 63, 64, 65, 127, 128, …).
- [ ] **Green in all four optimize modes.**

### Known-Answer-Test conventions

- Store expected values as **byte arrays** (`[N]u8{ 0x.., ... }`), never as hex
  string literals. Comparing a hex string against binary output is a silent
  length/content mismatch — this exact mistake hid a real bug in the project's
  first commits.
- Cite the source of every vector in a comment (e.g. `// NaCl tests/core1.c`).
- When a KAT fails but the differential test against `std.crypto` passes at
  the same input size, trust the audited oracle and suspect the KAT — the
  expected byte array is probably miscopied. Paste the digest from the test
  output back into the array and re-run. (The SHA-512 §C.2 vector caught
  exactly this mistake on its way in.)

### Differential testing

`std.crypto` ships audited Salsa20, Poly1305, X25519, Ed25519 and SHA-512. Use
the matching primitive (`std.crypto.stream.salsa`, `std.crypto.nacl`, …) as an
oracle: push thousands of random inputs through both implementations and assert
equality. This catches what fixed vectors miss — see the existing tests in
`src/salsa20.zig` for the pattern.

## Security rules

- **Constant time.** No branch or array index may depend on secret data.
  Compare secrets with `std.crypto.timing_safe`.
- **Wipe secrets.** Zero stack-resident key material with
  `std.crypto.secureZero` (use `defer`).
- **No `assert` for input validation** — it is compiled out in release builds.
  Enforce contracts with the type system instead.

## Code style

- `zig fmt` is the authority; CI rejects unformatted code.
- Match the surrounding comment density. Explain *why*, and cite the
  specification for non-obvious cryptographic steps.

## Pull request checklist

- [ ] `zig build test` green in all four optimize modes.
- [ ] `zig fmt --check .` clean.
- [ ] New code meets the test coverage bar above.
- [ ] Known-Answer-Test sources cited in comments.
- [ ] No new secret-dependent branches or indexing; secrets wiped.

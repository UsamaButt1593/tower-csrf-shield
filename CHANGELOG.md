## Changelog

- **`v0.1.1`, 2026-10-07** — Re-verified against rustc/cargo 1.99.0 with updated
  dependency versions (`tower-sessions 0.14`, `tower 0.5`, etc. — see
  `Cargo.toml`). Documented the duplicate-`tower-sessions`-version failure
  mode that can cause every request to 500 after a dependency bump.
- **`v0.1.0`, 2026-09-28** — Initial release, verified against rustc/cargo 1.75.0.

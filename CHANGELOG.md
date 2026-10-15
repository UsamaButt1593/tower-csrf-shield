## Changelog

- **`v0.1.2`, 2026-10-06** — Fixed: the layer could not be applied to an axum `Router`
  (`Router::layer`), nor could handlers extract the request. The service
  used to hand its inner service a wrapper body type (`MaybeBufferedBody`);
  it now always passes the *same* `Request<ReqBody>` it received, rebuilding
  a buffered form body via `ReqBody::from(bytes)`. **Breaking:**
  `MaybeBufferedBody` is removed, and `ReqBody` must now implement
  `From<Bytes>` (axum's `Body` does). Handlers read the token with
  `Extension<CsrfToken>`; they never see a different request type.
- **`v0.1.1`, 2026-10-07** — Re-verified against rustc/cargo 1.99.0 with updated
  dependency versions (`tower-sessions 0.14`, `tower 0.5`, etc. — see
  `Cargo.toml`). Documented the duplicate-`tower-sessions`-version failure
  mode that can cause every request to 500 after a dependency bump.
- **`v0.1.0`, 2026-09-28** — Initial release, verified against rustc/cargo 1.75.0.

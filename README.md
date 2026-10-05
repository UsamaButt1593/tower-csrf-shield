# tower-csrf-shield

CSRF protection as a [`tower`](https://docs.rs/tower) [`Layer`](https://docs.rs/tower/latest/tower/trait.Layer.html).

- **Three patterns, one API shape**: synchronizer (session-backed), double-submit
  (`Naive` or `Hmac`), and hybrid (cookie+form double-check, then `HmacOnly` or
  session-backed, the latter with an optional HMAC pre-check). See
  [`src/lib.rs`](src/lib.rs) and each pattern's module docs for the full
  picture of how they work and differ.
- **State every detail explicitly.** There are no silent defaults for
  security-relevant choices — cookie attributes, transport, sub-approach,
  regeneration policy, and origin checking are all required inputs, either
  through the fluent builder or by constructing a pattern's `*Config`
  directly.
- **Invalid combinations don't compile.** Each pattern and sub-approach is
  its own type; a builder only exposes the methods that make sense for the
  state it's already in (there is no `.hmac_secret()` on a naive
  double-submit builder, no `.session_key()` on a double-submit builder, and
  `HttpOnly` is never a setting you can touch at all — see _Compile-time
  guarantees_ below).
- **Immutable once built**, cheap to clone, and works with
  [`tower_sessions`](https://docs.rs/tower-sessions) for the patterns that
  need a session.

## Install

```toml
[dependencies]
tower-csrf-shield = { path = "." } # or a git/registry dependency, once published
```

## Quick start

```rust
use tower_csrf_shield::{CookieConfig, CookieSameSite, CsrfLayerBuilder, RegenerateToken};

let layer = CsrfLayerBuilder::new()
    .double_submit()
    .cookie(CookieConfig::standard("csrf", CookieSameSite::Lax, true))
    .submit_via_form_field("csrf_token")
    .naive()
    .regenerate_token(RegenerateToken::PerSession)
    .skip_origin_check()
    .build();
```

Apply it with `tower::ServiceBuilder::layer(..)` or, in axum, `Router::layer(..)`.
In your handler, pull the current token out of the request extensions (axum:
`Extension<CsrfToken>`) and render it into a hidden form field under the name
you configured — that's the one step this crate leaves to you, since it has
no opinion on your templating. Everything else (issuing, verifying,
rotating, setting `Set-Cookie`) happens automatically.

Run `cargo run --example basic_usage` for a walkthrough of all three
patterns, including a rejected forgery for each.

## Choosing a pattern

| Pattern                 | Token lives in   | Client sends it via  | Needs `tower_sessions`? | No server-side storage?            |
| ----------------------- | ---------------- | -------------------- | ----------------------- | ---------------------------------- |
| `Synchronizer`          | a `Session`      | form field           | yes                     | no                                 |
| `DoubleSubmit<Naive>`   | cookie           | cookie + form/header | no                      | yes                                |
| `DoubleSubmit<Hmac>`    | cookie           | cookie + form/header | no                      | yes                                |
| `Hybrid<HmacOnlyStage>` | cookie           | cookie + form        | no                      | yes                                |
| `Hybrid<SessionStage>`  | cookie + session | cookie + form        | yes                     | no (optional HMAC pre-check first) |

If you already run server-side sessions, `Synchronizer` is the simplest
correct choice. If you don't want any server-side CSRF state at all,
`DoubleSubmit<Hmac>` or `Hybrid<HmacOnlyStage>` are fully stateless (the
token is self-verifying via HMAC + an embedded expiry). `Hybrid<SessionStage>`
is for when you want the session as the final authority but also want to
reject obviously-forged requests _before_ paying for a session-store round
trip — see the hybrid pattern's module docs for exactly how that ordering is
guaranteed.

`DoubleSubmit<Naive>` has no signing at all: it is exactly as strong as
"can the attacker read or set cookies for your domain?" — fine against
classic cross-site request forgery, not against cookie injection. Reach for
`Hmac` if that's a threat you care about.

## `RegenerateToken`

Controls when a new token is issued, independent of which pattern you use:

- `PerSession` (default): one token until it's replaced for some other
  reason. Simplest for clients — nothing to coordinate.
- `PerUse`: a new token after every successful unsafe-method request.
  Limits how long a leaked token stays useful, at the cost of clients
  needing to pick up the next token from each response.
- `PerRequest`: a new token on _every_ request, including safe ones. Rarely
  worth the client-side complexity (concurrent requests race on which token
  is current) — documented mainly for completeness.

## Origin checking

Optional, checked only on unsafe methods, and **fails closed**: if enabled
and the `Origin` header is missing, the request is rejected. This is
independent of CORS — configuring `CORSLayer` (or equivalent) to allow
credentialed cross-origin requests is entirely your responsibility and
outside this crate's scope; this check only constrains which origins may
complete a _state-changing request against this layer_, not which origins
may read your responses.

## Compile-time guarantees

A few examples of what won't compile, and why — these are enforced as
`compile_fail` doctests in [`src/lib.rs`](src/lib.rs) so they can't silently
regress:

```rust,compile_fail
// No such method: HMAC configuration doesn't exist on the naive path.
CsrfLayerBuilder::new()
    .double_submit()
    .cookie(CookieConfig::standard("csrf", CookieSameSite::Lax, true))
    .submit_via_form_field("csrf_token")
    .naive()
    .hmac(HmacConfig::new(b"secret", Duration::from_secs(1)));
```

```rust,compile_fail
// `.done()` only exists once every required field reads `Present`;
// `.form_field(..)` was never called here.
CsrfLayerBuilder::new()
    .synchronizer()
    .session_key("csrf")
    .done();
```

`CookieConfig` never exposes an `HttpOnly` setter at all (whether the cookie
ends up `HttpOnly` is fixed by which pattern uses it, not a choice you make),
and `CookieConfig::host_prefixed` hardcodes `Secure` and `Path=/` rather than
exposing settings that could contradict what the `__Host-` prefix requires.

## Limitations

- Form-field token transport only supports
  `application/x-www-form-urlencoded` bodies; multipart is out of scope
  (reading a field out of a multipart body without buffering the whole
  thing, or without being able to reconstruct it for downstream handlers, is
  a substantially bigger problem — use header transport, available on the
  double-submit pattern, if this matters to you).
- Origin checking looks at `Origin` only, never `Referer`.
- The rejection response carries no body explaining why (by design — see
  the crate docs on `CsrfError`); reasons are logged via `tracing` instead.

## Testing this crate

```sh
cargo test                       # unit + integration + doctests
cargo run --example basic_usage  # end-to-end walkthrough
```

The integration tests (`tests/`) drive real `tower_sessions` + `tower-csrf-shield`
stacks through a tiny in-process "browser," including a call-counting
session store used specifically to prove that the hybrid pattern's HMAC
pre-check runs — and rejects — _before_ the session store is ever consulted.

## Verified toolchain and dependency versions

This crate was built and its full test suite run against **rustc/cargo
1.75.0**, with the dependency versions pinned in `Cargo.toml` (all ordinary
minimum-version requirements — Cargo will use a newer compatible
patch/minor release automatically — except `time`, pinned exactly for the
reason noted inline in `Cargo.toml`). `hmac`, `sha2`, `rand`, and `base64`
are pinned to specific _major_ lines because their next major releases
change APIs this crate calls directly, not merely as a toolchain
workaround, so bumping those deliberately (and adjusting `src/crypto.rs`
accordingly) is a real decision, not just a version-number edit.

If your toolchain is newer than 1.75, everything here should build as-is;
newer patch/minor releases of `tower`, `tower-sessions`, `http`,
`http-body(-util)`, `cookie`, `async-trait`, and `tracing` are expected to
keep working, since nothing in this crate depends on very recent additions
to any of them — but they haven't been individually re-verified by me
beyond what `Cargo.toml`'s ranges already pin.

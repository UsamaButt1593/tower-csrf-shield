//! Zero-sized type-state markers used by every builder in this crate to
//! track, at compile time, whether a required field has been supplied yet.
//! A builder method that fills a required field is only defined in an
//! `impl` block generic over `Missing` for that slot, so calling it twice —
//! or calling `.build()`/`.done()` before every slot reads `Present` —
//! simply does not compile.

/// A required builder field has not yet been set.
#[derive(Debug, Clone, Copy, Default)]
pub struct Missing;

/// A required builder field has been set.
#[derive(Debug, Clone, Copy, Default)]
pub struct Present;

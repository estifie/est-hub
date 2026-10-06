# Contributing

## Setup

Rust 1.89 or newer. `rust-toolchain.toml` pins the exact toolchain;
rustup picks it up automatically.

```sh
git config core.hooksPath .githooks   # pre-commit: fmt; pre-push: clippy + tests
cargo test                            # everything should pass before you start
```

## Gates

CI runs the same gates on every push and pull request:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo doc --no-deps                   # with RUSTDOCFLAGS="-D warnings" in CI
```

`cargo deny check` and `cargo audit` also run in CI. Dependencies are
the vetted minimum (`aes-gcm`, `base64`, `zeroize`, `est-core`): a new
one needs justification in the PR and must pass the `deny.toml`
review (MIT/Apache-2.0 only).

## Tests

The suite is hermetic: conformance runs against the committed vectors
in `tests/vectors/` (regenerated only by the vendored
`make_vectors.py`), and no test touches the Keychain. Tests that need
a key take an explicit one (`seal_with`/`unseal_with`).

## Commits and PRs

- Conventional Commits: `feat:`, `fix:`, `docs:`, `refactor:`,
  `test:`, `chore:`. Scope when it helps (`feat(store): …`).
- One logical change per commit; `main` stays releasable.
- PRs squash-merge with a changelog-worthy title and add a
  `CHANGELOG.md` entry under `[Unreleased]`.
- Public API needs doc comments (`missing_docs` warns locally and
  fails CI) and tests that pin the behavior.
- The store format is stable: any byte-level change needs a format
  version bump plan, migration notes, and new vectors — never a quiet
  edit.

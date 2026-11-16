[![Crates.io](https://img.shields.io/crates/v/pulldown-cmark-to-cmark)](https://crates.io/crates/pulldown-cmark-to-cmark) ![Rust](https://github.com/Byron/pulldown-cmark-to-cmark/workflows/Rust/badge.svg)

A utility library which translates [`Event`][pdcm-event] back to markdown. It's the prerequisite for writing markdown filters which can work as [mdbook-preprocessors][mdbook-prep].

The workspace adopts upstream 23.0.1, retaining its edition, lint and instrumentation conventions and the local reference-label, table-code and blank-line regression cases. The serializer receives the parser flags explicitly; it rejects invalid event streams or source ranges instead of silently changing their meaning. Source spellings are retained only when parsing them produces equivalent events. Inside a table, that comparison reads a code span's pipes as the caller's table-code adaptation does, literal and with their backslashes kept: the block validator reconciles each such span at the exact output range the renderer wrote it, masks its pipes before reparsing a synthesized block, and still validates every surrounding event. After a refusal, `State::pending_source_start` gives the source offset of the buffered block, so a caller can name its line.

### How to use · `sec:packagespulldowncmarktocmarkreadmemd:how-to-use`

Please have a look at the [`stupicat`-example][sc-example] for a complete tour of the API, or have a look at the [api-docs][api].

It's easiest to get this library into your `Cargo.toml` using `cargo-add`:

```
cargo add pulldown-cmark-to-cmark
```

### Supported Rust Versions · `sec:packagespulldowncmarktocmarkreadmemd:supported-rust-versions`

This adopted package uses the workspace Rust version and edition. Its release group remains independent at tier 1.

### Friends of this project · `sec:packagespulldowncmarktocmarkreadmemd:friends-of-this-project`

- [**termbook**](https://github.com/Byron/termbook)
  - A runner for `mdbooks` to keep your documentation tested.
- [**Share Secrets Safely**](https://github.com/Byron/share-secrets-safely)
  - share secrets within teams to avoid plain-text secrets from day one

### Maintenance Guide · `sec:packagespulldowncmarktocmarkreadmemd:maintenance-guide`

#### Making a new release · `sec:packagespulldowncmarktocmarkreadmemd:making-a-new-release`

- **Assure all documentation is up-to-date and tests are green**
- update the `version` in `Cargo.toml` and `git commit`
- run `cargo release --no-dev-version`

[pdcm-event]: https://docs.rs/pulldown-cmark/latest/pulldown_cmark/enum.Event.html
[mdbook-prep]: https://rust-lang.github.io/mdBook/for_developers/preprocessors.html
[sc-example]: https://github.com/Byron/pulldown-cmark-to-cmark/blob/76667725b61be24890fbdfed5e7ecdb4c1ad1dc8/examples/stupicat.rs#L21
[api]: https://docs.rs/crate/pulldown-cmark-to-cmark

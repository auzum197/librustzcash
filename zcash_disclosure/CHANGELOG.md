# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Initial crate.

### Added
- `zcash_disclosure::Disclosure`, with `encode` and `decode` for the `zdisc` string
  and enforcement of its canonical form.
- `zcash_disclosure::discover`, `discover_sapling` and `discover_action`, which list
  the outputs a set of viewing keys can disclose.
- `zcash_disclosure::verify`, `verify_sapling_output` and `verify_action`, which check
  Items against a transaction or a single output.
- `zcash_disclosure::set`, for Disclosure sets with one Disclosure per line.

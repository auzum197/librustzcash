# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Initial crate.

### Added
- `zcash_disclosure::Disclosure`, with `encode` and `decode` for the unsigned (`zdu`)
  and signed (`zds`) string classes and enforcement of their canonical form.
- `zcash_disclosure::discover`, `discover_sapling` and `discover_action`, which list
  the outputs a set of viewing keys can disclose.
- `zcash_disclosure::prepare_sapling_spend`, `prepare_sapling_address_owner` and
  `PendingDisclosure`, which produce a signed Disclosure.
- `zcash_disclosure::prepare_orchard_spend`, `prepare_ironwood_spend`,
  `prepare_transparent_input` and `prepare_orchard_address_owner`, which are
  placeholders that panic.
- `zcash_disclosure::verify`, `verify_sapling_output`, `verify_action`,
  `verify_spend_signer` and `verify_address_owner_signer`, which check Items against
  a transaction or a single output or spend.
- `zcash_disclosure::set`, for Disclosure sets with one Disclosure per line.

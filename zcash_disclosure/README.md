# zcash_disclosure

Shielded note disclosures for Zcash. A Disclosure is a `zdisc` string that lets any
holder decrypt and check a chosen set of Sapling, Orchard or Ironwood outputs of one
transaction: the value, the receiver address and the memo. A watch-only wallet produces
it from full viewing keys. No spending key is involved.

The crate encodes and decodes Disclosures, lists the outputs of a transaction that a set
of viewing keys can disclose, and verifies a Disclosure against the transaction it
covers. [SPEC.md](SPEC.md) is the draft specification it implements, including the
properties a verified Item guarantees and the ones it does not.

## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.

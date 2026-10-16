# Original development corpus

The five Phase 1A programs are retained with category annotations. Seven original
Phase 1B programs extend the public development set. Other Phase 1B programs stay
in the separate private repository; this tree does not identify them.

All original code and tests use the repository's MIT license. No third-party
implementation was copied. The SHA implementations follow the mathematical
specification in [FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf).
RC4 tests use the initial 128-bit stream from the 40-bit-key vector in
[RFC 6229, section 2](https://www.rfc-editor.org/rfc/rfc6229#section-2).
SHA expected digests were independently computed with Python's OpenSSL-backed
`hashlib` for empty input, `abc`, and padding/block boundaries. They test one-shot
and chunked updates. These source-native tests are distinct from verifier fixtures.

`make -C corpus/tierA/<program> test` runs active checks even with `NDEBUG`.
Native compilation and execution belong inside the pinned compiler sandbox.
`alth corpus lint --phase 1b` checks categories and parameter roles.

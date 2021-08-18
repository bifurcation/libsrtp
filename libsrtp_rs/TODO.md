TODO
====

* [X] Validate RTP packet parsing
* [X] Stream cipher interface with seeking
* [X] RTCP packet parsing
* [X] Validate RTCP packet parsing
* [X] Finish SRTP protect / unprotect
* [ ] Implement SRTCP protect / unprotect
* [X] User data
* [X] Event handler
* [ ] Debug logging
* [ ] Short-tag GCM modes
* [X] Use `Rc<T>` instead of `Box<T>` for crypto objects
* [ ] Remove 'as' conversions
* [ ] Build with `no_std` when crypto library supports
* [ ] Run `clippy` and implement suggestions
* [ ] type SrtpResult<T> = Result<T, Error>
* [ ] Replicate all C tests in Rust
* [ ] Re-enable C interfaces for everything-but-SRTP; pass tests
* [ ] Enable C interface for SRTP; pass tests
* [ ] Crypto library agility (and integration into CMake)
* [ ] OpenSSL support
* [ ] mBedTLS support

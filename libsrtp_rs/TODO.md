TODO
====

* [X] Validate RTP packet parsing
* [X] Stream cipher interface with seeking
* [X] RTCP packet parsing
* [X] Validate RTCP packet parsing
* [X] Finish SRTP protect / unprotect
* [X] Implement SRTCP protect / unprotect
* [X] User data
* [X] Event handler
* [X] Use `Rc<T>` instead of `Box<T>` for crypto objects
* [X] SRTP and SRTCP validation
* [X] Convert all hex literals to use `hex!()`
* [X] Instead of SsrcType, make Ssrc an enum
* [X] Re-enable C interfaces for everything-but-SRTP; pass tests
* [X] Enable C interface for SRTP; pass tests
* [ ] Replicate all C tests in Rust
* [ ] Debug logging
* [X] Gate C interface behind a feature
* [ ] Support for user data and event handlers in the C interface
* [ ] Remove 'as' conversions
* [ ] Build with `no_std` to the extent possible
* [ ] Run `clippy` and implement suggestions
* [ ] type SrtpResult<T> = Result<T, Error> 
* [ ] Crypto library agility (and integration into CMake)
* [ ] OpenSSL support
* [ ] mBedTLS support
* [ ] Use macros to clean up C interface code and make it safer
* [ ] Audit for `pub` 
* [ ] Clean up modularization


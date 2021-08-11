TODO
====

* [X] Validate RTP packet parsing
* [X] Stream cipher interface with seeking
* [X] RTCP packet parsing
* [ ] Validate RTCP packet parsing
* [ ] Finish SRTP protect / unprotect
* [ ] Complete SRTCP protect / unprotect
* [ ] User data
* [ ] Event handler
* [ ] Debug logging
* [ ] Short-tag GCM modes
* [X] Use `Rc<T>` instead of `Box<T>` for crypto objects
* [ ] Remove 'as' conversions
* [ ] Build with `no_std` when crypto library supports
* [ ] Run `clippy` and implement suggestions
* [ ] type SrtpResult<T> = Result<T, Error>
* [ ] Re-enable C interfaces for everything-but-SRTP; pass tests
* [ ] Enable C interface for SRTP; pass tests

TODO
====

* [X] Validate RTP packet parsing
* [X] Stream cipher interface with seeking
* [ ] RTCP packet parsing
* [ ] Validate RTCP packet parsing
* [ ] Complete SRTP protect / unprotect
* [ ] Complete SRTCP protect / unprotect
* [ ] User data
* [ ] Event handler
* [ ] Debug logging
* [ ] Short-tag GCM modes
* [ ] Use `Rc<T>` instead of `Box<T>` for crypto objects
* [ ] Remove 'as' conversions
* [ ] Build with `no_std` when crypto library supports
* [ ] Run `clippy` and implement suggestions
* [ ] type SrtpResult<T> = Result<T, Error>

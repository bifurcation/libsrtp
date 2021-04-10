pub enum Error {
    // TODO(RLB): During translation, we are promoting this as needed, to make sure we only end up with the set we need
    replay_fail = 9, // replay check failed (bad index)
    replay_old = 10, // replay check failed (index too old)
    key_expired = 15, // can't use key any more

                     /*
                     fail = 1,           // unspecified failure
                     bad_param = 2,      // unsupported parameter
                     alloc_fail = 3,     // couldn't allocate memory
                     dealloc_fail = 4,   // couldn't deallocate properly
                     init_fail = 5,      // couldn't initialize
                     terminus = 6,       // can't process as much data as requested
                     auth_fail = 7,      // authentication failure
                     cipher_fail = 8,    // cipher failure
                     algo_fail = 11,     // algorithm failed test routine
                     no_such_op = 12,    // unsupported operation
                     no_ctx = 13,        // no appropriate context found
                     cant_check = 14,    // unable to perform desired validation
                     socket_err = 16,    // error in use of socket
                     signal_err = 17,    // error in use POSIX signals
                     nonce_bad = 18,     // nonce check failed
                     read_fail = 19,     // couldn't read data
                     write_fail = 20,    // couldn't write data
                     parse_err = 21,     // error parsing data
                     encode_err = 22,    // error encoding data
                     semaphore_err = 23, // error while using semaphores
                     pfkey_err = 24,     // error while using pfkey
                     bad_mki = 25,       // error MKI present in packet is invalid
                     pkt_idx_old = 26,   // packet index is too old to consider
                     pkt_idx_adv = 27,   // packet index advanced, reset needed
                     */
}


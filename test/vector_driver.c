/*
 * srtp_driver.c
 *
 * a test driver for libSRTP
 *
 * David A. McGrew
 * Cisco Systems, Inc.
 */
/*
 *
 * Copyright (c) 2001-2017, Cisco Systems, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 *   Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer in the documentation and/or other materials provided
 *   with the distribution.
 *
 *   Neither the name of the Cisco Systems, Inc. nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <string.h>   /* for memcpy()          */
#include <time.h>     /* for clock()           */
#include <stdlib.h>   /* for malloc(), free()  */
#include <stdio.h>    /* for print(), fflush() */
#include "getopt_s.h" /* for local getopt()    */

#include "srtp_priv.h"
#include "util.h"

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#elif defined HAVE_WINSOCK2_H
#include <winsock2.h>
#endif

#define PRINT_REFERENCE_PACKET 1

srtp_err_status_t srtp_validate_encrypted_extensions_headers(void);

#ifdef GCM
srtp_err_status_t srtp_validate_encrypted_extensions_headers_gcm(void);
#endif

extern const srtp_policy_t aes_256_hmac_policy;
srtp_err_status_t srtcp_test(const srtp_policy_t *policy, int mki_index);

void log_handler(srtp_log_level_t level, const char *msg, void *data)
{
    char level_char = '?';
    switch (level) {
    case srtp_log_level_error:
        level_char = 'e';
        break;
    case srtp_log_level_warning:
        level_char = 'w';
        break;
    case srtp_log_level_info:
        level_char = 'i';
        break;
    case srtp_log_level_debug:
        level_char = 'd';
        break;
    }
    printf("SRTP-LOG [%c]: %s\n", level_char, msg);
}

/*
 * The policy_array and invalid_policy_array are null-terminated arrays of
 * policy structs. They is declared at the end of this file.
 */

extern const srtp_policy_t *policy_array[];
extern const srtp_policy_t *invalid_policy_array[];

/* the wildcard_policy is declared below; it has a wildcard ssrc */

extern const srtp_policy_t wildcard_policy;

/*
 * mod_driver debug module - debugging module for this test driver
 *
 * we use the crypto_kernel debugging system in this driver, which
 * makes the interface uniform and increases portability
 */

srtp_debug_module_t mod_driver = {
    1,       /* debugging is off by default */
    "driver" /* printable name for module   */
};

int main(int argc, char *argv[])
{
    int q;
    unsigned do_timing_test = 0;
    unsigned do_rejection_test = 0;
    unsigned do_codec_timing = 0;
    unsigned do_validation = 0;
    unsigned do_list_mods = 0;
    unsigned do_log_stdout = 0;
    srtp_err_status_t status;

    /*
     * verify that the compiler has interpreted the header data
     * structure srtp_hdr_t correctly
     */
    if (sizeof(srtp_hdr_t) != 12) {
        printf("error: srtp_hdr_t has incorrect size"
               "(size is %ld bytes, expected 12)\n",
               (long)sizeof(srtp_hdr_t));
        exit(1);
    }

    /* initialize srtp library */
    status = srtp_init();
    if (status) {
        printf("error: srtp init failed with error code %d\n", status);
        exit(1);
    }

    /*  load srtp_driver debug module */
    status = srtp_crypto_kernel_load_debug_module(&mod_driver);
    if (status) {
        printf("error: load of srtp_driver debug module failed "
               "with error code %d\n",
               status);
        exit(1);
    }

    /*  log to stdout */
    status = srtp_install_log_handler(log_handler, NULL);
    if (status) {
        printf("error: install log handler failed\n");
        exit(1);
    }

#if 0
    // Test normal SRTP
    printf("testing srtp_protect and srtp_unprotect against "
           "reference packet with encrypted extensions headers\n");
    if (srtp_validate_encrypted_extensions_headers() == srtp_err_status_ok)
        printf("passed\n\n");
    else {
        printf("failed\n");
        exit(1);
    }
#endif

#if 0
#ifdef GCM
    // Test with GCM
    printf("testing srtp_protect and srtp_unprotect against "
           "reference packet with encrypted extension headers (GCM)\n");
    if (srtp_validate_encrypted_extensions_headers_gcm() ==
        srtp_err_status_ok) {
        printf("passed\n\n");
    } else {
        printf("failed\n");
        exit(1);
    }
#endif
#endif

    // Test SRTCP
    printf("testing srtp_protect_rtcp and srtp_unprotect_rtcp\n");
    const srtp_policy_t *policy = &aes_256_hmac_policy;
    if (srtcp_test(policy, 0) == srtp_err_status_ok) {
                printf("passed\n\n");
            } else {
                printf("failed\n");
                exit(1);
            }

    return 0;
}

/*
 * Test vectors taken from RFC 6904, Appendix A
 */
srtp_err_status_t srtp_validate_encrypted_extensions_headers()
{
    // clang-format off
    unsigned char test_key_ext_headers[30] = {
        0xe1, 0xf9, 0x7a, 0x0d, 0x3e, 0x01, 0x8b, 0xe0,
        0xd6, 0x4f, 0xa3, 0x2c, 0x06, 0xde, 0x41, 0x39,
        0x0e, 0xc6, 0x75, 0xad, 0x49, 0x8a, 0xfe, 0xeb,
        0xb6, 0x96, 0x0b, 0x3a, 0xab, 0xe6
    };
    uint8_t srtp_plaintext_ref[56] = {
        0x90, 0x0f, 0x12, 0x34, 0xde, 0xca, 0xfb, 0xad,
        0xca, 0xfe, 0xba, 0xbe, 0xBE, 0xDE, 0x00, 0x06,
        0x17, 0x41, 0x42, 0x73, 0xA4, 0x75, 0x26, 0x27,
        0x48, 0x22, 0x00, 0x00, 0xC8, 0x30, 0x8E, 0x46,
        0x55, 0x99, 0x63, 0x86, 0xB3, 0x95, 0xFB, 0x00,
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab
    };
    uint8_t srtp_plaintext[66] = {
        0x90, 0x0f, 0x12, 0x34, 0xde, 0xca, 0xfb, 0xad,
        0xca, 0xfe, 0xba, 0xbe, 0xBE, 0xDE, 0x00, 0x06,
        0x17, 0x41, 0x42, 0x73, 0xA4, 0x75, 0x26, 0x27,
        0x48, 0x22, 0x00, 0x00, 0xC8, 0x30, 0x8E, 0x46,
        0x55, 0x99, 0x63, 0x86, 0xB3, 0x95, 0xFB, 0x00,
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00
    };
    uint8_t srtp_ciphertext[66] = {
        0x90, 0x0f, 0x12, 0x34, 0xde, 0xca, 0xfb, 0xad,
        0xca, 0xfe, 0xba, 0xbe, 0xBE, 0xDE, 0x00, 0x06,
        0x17, 0x58, 0x8A, 0x92, 0x70, 0xF4, 0xE1, 0x5E,
        0x1C, 0x22, 0x00, 0x00, 0xC8, 0x30, 0x95, 0x46,
        0xA9, 0x94, 0xF0, 0xBC, 0x54, 0x78, 0x97, 0x00,
        0x4e, 0x55, 0xdc, 0x4c, 0xe7, 0x99, 0x78, 0xd8,
        0x8c, 0xa4, 0xd2, 0x15, 0x94, 0x9d, 0x24, 0x02,
        0x5a, 0x46, 0xb3, 0xca, 0x35, 0xc5, 0x35, 0xa8,
        0x91, 0xc7
    };
    // clang-format on

    srtp_t srtp_snd, srtp_recv;
    srtp_err_status_t status;
    int len;
    srtp_policy_t policy;
    int headers[3] = { 1, 3, 4 };

    /*
     * create a session with a single stream using the default srtp
     * policy and with the SSRC value 0xcafebabe
     */
    memset(&policy, 0, sizeof(policy));
    srtp_crypto_policy_set_rtp_default(&policy.rtp);
    srtp_crypto_policy_set_rtcp_default(&policy.rtcp);
    policy.ssrc.type = ssrc_specific;
    policy.ssrc.value = 0xcafebabe;
    policy.key = test_key_ext_headers;
    policy.deprecated_ekt = NULL;
    policy.window_size = 128;
    policy.allow_repeat_tx = 0;
    policy.enc_xtn_hdr = headers;
    policy.enc_xtn_hdr_count = sizeof(headers) / sizeof(headers[0]);
    policy.next = NULL;

    status = srtp_create(&srtp_snd, &policy);
    if (status)
        return status;

    /*
     * protect plaintext, then compare with ciphertext
     */
    len = sizeof(srtp_plaintext_ref);
    status = srtp_protect(srtp_snd, srtp_plaintext, &len);
    if (status || (len != sizeof(srtp_plaintext)))
        return srtp_err_status_fail;

    debug_print(mod_driver, "ciphertext:\n  %s",
                srtp_octet_string_hex_string(srtp_plaintext, len));
    debug_print(mod_driver, "ciphertext reference:\n  %s",
                srtp_octet_string_hex_string(srtp_ciphertext, len));

    if (srtp_octet_string_is_eq(srtp_plaintext, srtp_ciphertext, len))
        return srtp_err_status_fail;

    /*
     * create a receiver session context comparable to the one created
     * above - we need to do this so that the replay checking doesn't
     * complain
     */
    status = srtp_create(&srtp_recv, &policy);
    if (status)
        return status;

    /*
     * unprotect ciphertext, then compare with plaintext
     */
    status = srtp_unprotect(srtp_recv, srtp_ciphertext, &len);
    if (status) {
        return status;
    } else if (len != sizeof(srtp_plaintext_ref)) {
        return srtp_err_status_fail;
    }

    if (srtp_octet_string_is_eq(srtp_ciphertext, srtp_plaintext_ref, len))
        return srtp_err_status_fail;

    status = srtp_dealloc(srtp_snd);
    if (status)
        return status;

    status = srtp_dealloc(srtp_recv);
    if (status)
        return status;

    return srtp_err_status_ok;
}

#ifdef GCM

/*
 * Headers of test vectors taken from RFC 6904, Appendix A
 */
srtp_err_status_t srtp_validate_encrypted_extensions_headers_gcm()
{
    // clang-format off
    unsigned char test_key_ext_headers[30] = {
        0xe1, 0xf9, 0x7a, 0x0d, 0x3e, 0x01, 0x8b, 0xe0,
        0xd6, 0x4f, 0xa3, 0x2c, 0x06, 0xde, 0x41, 0x39,
        0x0e, 0xc6, 0x75, 0xad, 0x49, 0x8a, 0xfe, 0xeb,
        0xb6, 0x96, 0x0b, 0x3a, 0xab, 0xe6
    };
    uint8_t srtp_plaintext_ref[56] = {
        0x90, 0x0f, 0x12, 0x34, 0xde, 0xca, 0xfb, 0xad,
        0xca, 0xfe, 0xba, 0xbe, 0xBE, 0xDE, 0x00, 0x06,
        0x17, 0x41, 0x42, 0x73, 0xA4, 0x75, 0x26, 0x27,
        0x48, 0x22, 0x00, 0x00, 0xC8, 0x30, 0x8E, 0x46,
        0x55, 0x99, 0x63, 0x86, 0xB3, 0x95, 0xFB, 0x00,
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab
    };
    uint8_t srtp_plaintext[64] = {
        0x90, 0x0f, 0x12, 0x34, 0xde, 0xca, 0xfb, 0xad,
        0xca, 0xfe, 0xba, 0xbe, 0xBE, 0xDE, 0x00, 0x06,
        0x17, 0x41, 0x42, 0x73, 0xA4, 0x75, 0x26, 0x27,
        0x48, 0x22, 0x00, 0x00, 0xC8, 0x30, 0x8E, 0x46,
        0x55, 0x99, 0x63, 0x86, 0xB3, 0x95, 0xFB, 0x00,
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    uint8_t srtp_ciphertext[64] = {
        0x90, 0x0f, 0x12, 0x34, 0xde, 0xca, 0xfb, 0xad,
        0xca, 0xfe, 0xba, 0xbe, 0xBE, 0xDE, 0x00, 0x06,
        0x17, 0x12, 0xe0, 0x20, 0x5b, 0xfa, 0x94, 0x9b,
        0x1C, 0x22, 0x00, 0x00, 0xC8, 0x30, 0xbb, 0x46,
        0x73, 0x27, 0x78, 0xd9, 0x92, 0x9a, 0xab, 0x00,
        0x0e, 0xca, 0x0c, 0xf9, 0x5e, 0xe9, 0x55, 0xb2,
        0x6c, 0xd3, 0xd2, 0x88, 0xb4, 0x9f, 0x6c, 0xa9,
        0xf4, 0xb1, 0xb7, 0x59, 0x71, 0x9e, 0xb5, 0xbc
    };
    // clang-format on

    srtp_t srtp_snd, srtp_recv;
    srtp_err_status_t status;
    int len;
    srtp_policy_t policy;
    int headers[3] = { 1, 3, 4 };

    /*
     * create a session with a single stream using the default srtp
     * policy and with the SSRC value 0xcafebabe
     */
    memset(&policy, 0, sizeof(policy));
    srtp_crypto_policy_set_aes_gcm_128_8_auth(&policy.rtp);
    srtp_crypto_policy_set_aes_gcm_128_8_auth(&policy.rtcp);
    policy.ssrc.type = ssrc_specific;
    policy.ssrc.value = 0xcafebabe;
    policy.key = test_key_ext_headers;
    policy.deprecated_ekt = NULL;
    policy.window_size = 128;
    policy.allow_repeat_tx = 0;
    policy.enc_xtn_hdr = headers;
    policy.enc_xtn_hdr_count = sizeof(headers) / sizeof(headers[0]);
    policy.next = NULL;

    status = srtp_create(&srtp_snd, &policy);
    if (status)
        return status;

    /*
     * protect plaintext, then compare with ciphertext
     */
    len = sizeof(srtp_plaintext_ref);
    status = srtp_protect(srtp_snd, srtp_plaintext, &len);
    if (status || (len != sizeof(srtp_plaintext)))
        return srtp_err_status_fail;

    debug_print(mod_driver, "ciphertext:\n  %s",
                srtp_octet_string_hex_string(srtp_plaintext, len));
    debug_print(mod_driver, "ciphertext reference:\n  %s",
                srtp_octet_string_hex_string(srtp_ciphertext, len));

    if (srtp_octet_string_is_eq(srtp_plaintext, srtp_ciphertext, len))
        return srtp_err_status_fail;

    /*
     * create a receiver session context comparable to the one created
     * above - we need to do this so that the replay checking doesn't
     * complain
     */
    status = srtp_create(&srtp_recv, &policy);
    if (status)
        return status;

    /*
     * unprotect ciphertext, then compare with plaintext
     */
    status = srtp_unprotect(srtp_recv, srtp_ciphertext, &len);
    if (status) {
        return status;
    } else if (len != sizeof(srtp_plaintext_ref)) {
        return srtp_err_status_fail;
    }

    if (srtp_octet_string_is_eq(srtp_ciphertext, srtp_plaintext_ref, len))
        return srtp_err_status_fail;

    status = srtp_dealloc(srtp_snd);
    if (status)
        return status;

    status = srtp_dealloc(srtp_recv);
    if (status)
        return status;

    return srtp_err_status_ok;
}
#endif

// clang-format off
unsigned char test_256_key[46] = {
    0xf0, 0xf0, 0x49, 0x14, 0xb5, 0x13, 0xf2, 0x76,
    0x3a, 0x1b, 0x1f, 0xa1, 0x30, 0xf1, 0x0e, 0x29,
    0x98, 0xf6, 0xf6, 0xe4, 0x3e, 0x43, 0x09, 0xd1,
    0xe6, 0x22, 0xa0, 0xe3, 0x32, 0xb9, 0xf1, 0xb6,

    0x3b, 0x04, 0x80, 0x3d, 0xe5, 0x1e, 0xe7, 0xc9,
    0x64, 0x23, 0xab, 0x5b, 0x78, 0xd2
};

unsigned char test_256_key_2[46] = {
    0xe1, 0xf9, 0x7a, 0x0d, 0x3e, 0x01, 0x8b, 0xe0,
    0xd6, 0x4f, 0xa3, 0x2c, 0x06, 0xde, 0x41, 0x39,
    0x0e, 0xc6, 0x75, 0xad, 0x49, 0x8a, 0xfe, 0xeb,
    0xb6, 0x96, 0x0b, 0x3a, 0xab, 0xe6, 0xc1, 0x73,
    0x3b, 0x04, 0x80, 0x3d, 0xe5, 0x1e, 0xe7, 0xc9,
    0x64, 0x23, 0xab, 0x5b, 0x78, 0xd2
};

#define TEST_MKI_ID_SIZE 4

unsigned char test_mki_id[TEST_MKI_ID_SIZE] = {
    0xe1, 0xf9, 0x7a, 0x0d
};

unsigned char test_mki_id_2[TEST_MKI_ID_SIZE] = {
    0xf3, 0xa1, 0x46, 0x71
};

srtp_master_key_t master_256_key_1 = {
    test_256_key,
    test_mki_id,
    TEST_MKI_ID_SIZE
};

srtp_master_key_t master_256_key_2 = {
    test_256_key_2,
    test_mki_id_2,
    TEST_MKI_ID_SIZE
};

srtp_master_key_t *test_256_keys[2] = {
    &master_256_key_1,
    &master_256_key_2
};

const srtp_policy_t aes_256_hmac_policy = {
    { ssrc_any_outbound, 0 }, /* SSRC */
    {
        /* SRTP policy */
        SRTP_AES_ICM_256,               /* cipher type                 */
        SRTP_AES_ICM_256_KEY_LEN_WSALT, /* cipher key length in octets */
        SRTP_HMAC_SHA1,                 /* authentication func type    */
        20,                             /* auth key length in octets   */
        10,                             /* auth tag length in octets   */
        sec_serv_conf_and_auth          /* security services flag      */
    },
    {
        /* SRTCP policy */
        SRTP_AES_ICM_256,               /* cipher type                 */
        SRTP_AES_ICM_256_KEY_LEN_WSALT, /* cipher key length in octets */
        SRTP_HMAC_SHA1,                 /* authentication func type    */
        20,                             /* auth key length in octets   */
        10,                             /* auth tag length in octets   */
        sec_serv_conf_and_auth          /* security services flag      */
    },
    NULL,
    (srtp_master_key_t **)test_256_keys,
    2,    /* indicates the number of Master keys          */
    NULL, /* indicates that EKT is not in use             */
    128,  /* replay window size                           */
    0,    /* retransmission not allowed                   */
    NULL, /* no encrypted extension headers               */
    0,    /* list of encrypted extension headers is empty */
    NULL
};

void err_check(srtp_err_status_t s)
{
    if (s != srtp_err_status_ok) {
        fprintf(stderr, "error: unexpected srtp failure (code %d)\n", s);
        exit(1);
    }
}

srtp_err_status_t srtp_test_call_protect_rtcp(srtp_t srtp_sender,
                                              srtp_hdr_t *hdr,
                                              int *len,
                                              int mki_index)
{
    if (mki_index == -1) {
        return srtp_protect_rtcp(srtp_sender, hdr, len);
    } else {
        return srtp_protect_rtcp_mki(srtp_sender, hdr, len, 1, mki_index);
    }
}

srtp_err_status_t srtp_test_call_unprotect_rtcp(srtp_t srtp_sender,
                                                srtp_hdr_t *hdr,
                                                int *len,
                                                int use_mki)
{
    if (use_mki == -1) {
        return srtp_unprotect_rtcp(srtp_sender, hdr, len);
    } else {
        return srtp_unprotect_rtcp_mki(srtp_sender, hdr, len, use_mki);
    }
}

srtp_hdr_t *srtp_create_test_packet(int pkt_octet_len,
                                    uint32_t ssrc,
                                    int *pkt_len)
{
    int i;
    uint8_t *buffer;
    srtp_hdr_t *hdr;
    int bytes_in_hdr = 12;

    /* allocate memory for test packet */
    hdr = (srtp_hdr_t *)malloc(pkt_octet_len + bytes_in_hdr +
                               SRTP_MAX_TRAILER_LEN + 4);
    if (!hdr) {
        return NULL;
    }

    hdr->version = 2;            /* RTP version two     */
    hdr->p = 0;                  /* no padding needed   */
    hdr->x = 0;                  /* no header extension */
    hdr->cc = 0;                 /* no CSRCs            */
    hdr->m = 0;                  /* marker bit          */
    hdr->pt = 0xf;               /* payload type        */
    hdr->seq = htons(0x1234);    /* sequence number     */
    hdr->ts = htonl(0xdecafbad); /* timestamp           */
    hdr->ssrc = htonl(ssrc);     /* synch. source       */

    buffer = (uint8_t *)hdr;
    buffer += bytes_in_hdr;

    /* set RTP data to 0xab */
    for (i = 0; i < pkt_octet_len; i++) {
        *buffer++ = 0xab;
    }

    /* set post-data value to 0xffff to enable overrun checking */
    for (i = 0; i < SRTP_MAX_TRAILER_LEN + 4; i++) {
        *buffer++ = 0xff;
    }

    *pkt_len = bytes_in_hdr + pkt_octet_len;

    return hdr;
}

#include <stdio.h>
#define MTU 2048
char packet_string[MTU];

char *srtp_packet_to_string(srtp_hdr_t *hdr, int pkt_octet_len)
{
    int octets_in_rtp_header = 12;
    uint8_t *data = ((uint8_t *)hdr) + octets_in_rtp_header;
    int hex_len = pkt_octet_len - octets_in_rtp_header;

    /* sanity checking */
    if ((hdr == NULL) || (pkt_octet_len > MTU)) {
        return NULL;
    }

    /* write packet into string */
    sprintf(packet_string, "(s)rtp packet: {\n"
                           "   version:\t%d\n"
                           "   p:\t\t%d\n"
                           "   x:\t\t%d\n"
                           "   cc:\t\t%d\n"
                           "   m:\t\t%d\n"
                           "   pt:\t\t%x\n"
                           "   seq:\t\t%x\n"
                           "   ts:\t\t%x\n"
                           "   ssrc:\t%x\n"
                           "   data:\t%s\n"
                           "} (%d octets in total)\n",
            hdr->version, hdr->p, hdr->x, hdr->cc, hdr->m, hdr->pt, hdr->seq,
            hdr->ts, hdr->ssrc, octet_string_hex_string(data, hex_len),
            pkt_octet_len);

    return packet_string;
}

srtp_err_status_t srtcp_test(const srtp_policy_t *policy, int mki_index)
{
    int i;
    srtp_t srtcp_sender;
    srtp_t srtcp_rcvr;
    srtp_err_status_t status = srtp_err_status_ok;
    srtp_hdr_t *hdr, *hdr2;
    uint8_t hdr_enc[64];
    uint8_t *pkt_end;
    int msg_len_octets, msg_len_enc, msg_len;
    int len, len2;
    uint32_t tag_length;
    uint32_t ssrc;
    srtp_policy_t *rcvr_policy;
    int use_mki = 0;

    if (mki_index >= 0)
        use_mki = 1;

    err_check(srtp_create(&srtcp_sender, policy));

    /*
     * initialize data buffer, using the ssrc in the policy unless that
     * value is a wildcard, in which case we'll just use an arbitrary
     * one
     */
    if (policy->ssrc.type != ssrc_specific) {
        ssrc = 0xdecafbad;
    } else {
        ssrc = policy->ssrc.value;
    }
    msg_len_octets = 28;
    hdr = srtp_create_test_packet(msg_len_octets, ssrc, &len);
    /* save message len */
    msg_len = len;

    if (hdr == NULL) {
        return srtp_err_status_alloc_fail;
    }
    hdr2 = srtp_create_test_packet(msg_len_octets, ssrc, &len2);
    if (hdr2 == NULL) {
        free(hdr);
        return srtp_err_status_alloc_fail;
    }

    debug_print(mod_driver, "before protection:\n%s",
                octet_string_hex_string((uint8_t *)hdr, len));

    err_check(srtp_test_call_protect_rtcp(srtcp_sender, hdr, &len, mki_index));

    debug_print(mod_driver, "after protection:\n%s\n",
                octet_string_hex_string((uint8_t *)hdr, len));

    return srtp_err_status_ok;
}

/*
 * double.c
 *
 * Doubled AEAD mode, with specialization to AES-GCM
 *
 * Richard L. Barnes
 * Cisco
 *
 */

/*
 *
 * Copyright (c) 2013-2017, Cisco Systems, Inc.
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <openssl/evp.h>
#include "aes_icm_ossl.h"
#include "aes_gcm_ossl.h"
#include "alloc.h"
#include "err.h"                /* for srtp_debug */
#include "crypto_types.h"

srtp_debug_module_t srtp_mod_double = {
    0,               /* debugging is off by default */
    "double"         /* printable module name       */
};

#define MAX_AAD_LEN                512
#define MAX_HDR_LEN                64

/*
 * The double framework can be used with different combinations of ciphers.
 * Most of the functions below will just work with any length-preserving AEAD
 * cipher.  However, to define a different combination, you will need to define
 * a new srtp_cipher_type_t value and an allocator for it that calls
 * srtp_double_alloc().
 */
typedef struct {
    int inner_key_size;
    int outer_key_size;
    int inner_tag_size;
    int outer_tag_size;
    srtp_cipher_t *inner;
    srtp_cipher_t *outer;
    uint8_t inner_aad[MAX_AAD_LEN];
} srtp_double_ctx_t;

/* XXX: srtp_hdr_t borrowed from srtp_priv.h */
#ifndef WORDS_BIGENDIAN

typedef struct {
    unsigned char cc : 4;      /* CSRC count             */
    unsigned char x : 1;       /* header extension flag  */
    unsigned char p : 1;       /* padding flag           */
    unsigned char version : 2; /* protocol version       */
    unsigned char pt : 7;      /* payload type           */
    unsigned char m : 1;       /* marker bit             */
    uint16_t seq;              /* sequence number        */
    uint32_t ts;               /* timestamp              */
    uint32_t ssrc;             /* synchronization source */
} srtp_hdr_t;

typedef struct {
    unsigned char q : 1;       /* SEQ is present */
    unsigned char p : 1;       /* PT is present */
    unsigned char m : 1;       /* marker bit is present */
    unsigned char b : 1;       /* value of the marker bit */
    unsigned char r : 4;       /* reserved bits */
} ohb_t;

#else /*  BIG_ENDIAN */

typedef struct {
    unsigned char version : 2; /* protocol version       */
    unsigned char p : 1;       /* padding flag           */
    unsigned char x : 1;       /* header extension flag  */
    unsigned char cc : 4;      /* CSRC count             */
    unsigned char m : 1;       /* marker bit             */
    unsigned char pt : 7;      /* payload type           */
    uint16_t seq;              /* sequence number        */
    uint32_t ts;               /* timestamp              */
    uint32_t ssrc;             /* synchronization source */
} srtp_hdr_t;

typedef struct {
    unsigned char r : 4;       /* reserved bits */
    unsigned char b : 1;       /* value of the marker bit */
    unsigned char m : 1;       /* marker bit is present */
    unsigned char p : 1;       /* PT is present */
    unsigned char q : 1;       /* SEQ is present */
} ohb_t;

#endif

srtp_err_status_t apply_ohb(uint8_t *payload, int payload_len, srtp_hdr_t *hdr, unsigned int *hdr_len) {
    size_t remaining = payload_len - 1;
    ohb_t *ohb = (ohb_t *) (payload + remaining);

    /* remove extension and unset the X bit */
    *hdr_len = 12 + (4 * hdr->cc);
    hdr->x = 0;

    /* check reserved bits */
    if (ohb->r != 0) {
       return srtp_err_status_bad_param;
    }

    /* apply marker bit changes */
    if (ohb->m != 0) {
      hdr->m = ohb->b;
    }

    /* apply sequence number changes */
    if (ohb->q != 0) {
        if (remaining < 2) {
            return srtp_err_status_bad_param;
        }

        hdr->seq = payload[remaining-2];
        hdr->seq <<= 8;
        hdr->seq += payload[remaining-1];
        remaining -= 2;
    }

    /* apply payload type changes */
    if (ohb->p != 0) {
        if (remaining < 1) {
            return srtp_err_status_bad_param;
        }

        hdr->pt = payload[remaining-1] & 0x7f;
        remaining -= 1;
    }

    return srtp_err_status_ok;
}


/*
 * This function allocates an instance of a doubled cipher, allowing general
 * combinations of ciphers.
 */
static srtp_err_status_t srtp_double_alloc(const srtp_cipher_type_t *inner_type,
                                           const srtp_cipher_type_t *outer_type,
                                           const srtp_cipher_type_t *total_type,
                                           int algorithm,
                                           int inner_key_size, int outer_key_size,
                                           int inner_tag_size, int outer_tag_size,
                                           srtp_cipher_t **c)
{
    srtp_err_status_t err;
    srtp_double_ctx_t *dbl;

    debug_print(srtp_mod_double, "alloc with key size %d", inner_key_size + outer_key_size);
    debug_print(srtp_mod_double, "       ... tag size %d", inner_tag_size + outer_tag_size);

    /* Allocate the base structs */
    *c = (srtp_cipher_t *)srtp_crypto_alloc(sizeof(srtp_cipher_t));
    if (*c == NULL) {
        return (srtp_err_status_alloc_fail);
    }
    memset(*c, 0x0, sizeof(srtp_cipher_t));

    dbl = (srtp_double_ctx_t *)srtp_crypto_alloc(sizeof(srtp_double_ctx_t));
    if (dbl == NULL) {
        srtp_crypto_free(*c);
        *c = NULL;
        return (srtp_err_status_alloc_fail);
    }
    memset(dbl, 0x0, sizeof(srtp_double_ctx_t));

    /* Allocate the inner and outer contexts */
    err = inner_type->alloc(&dbl->inner, inner_key_size + SRTP_AEAD_SALT_LEN, inner_tag_size);
    if (err != srtp_err_status_ok) {
      debug_print(srtp_mod_double, "error alloc inner: %d", err);
      return err;
    }

    err = outer_type->alloc(&dbl->outer, outer_key_size + SRTP_AEAD_SALT_LEN, outer_tag_size);
    if (err != srtp_err_status_ok) {
      debug_print(srtp_mod_double, "error alloc outer: %d", err);
      return err;
    }

    /* Set up the cipher */
    dbl->inner_key_size = inner_key_size;
    dbl->outer_key_size = outer_key_size;
    dbl->inner_tag_size = inner_tag_size;
    dbl->outer_tag_size = outer_tag_size;
    (*c)->state = dbl;
    (*c)->key_len = inner_key_size + outer_key_size;
    (*c)->type = total_type;
    (*c)->algorithm = algorithm;

    debug_print(srtp_mod_double, "alloc ok", NULL);
    return (srtp_err_status_ok);
}

/*
 * This function deallocates a GCM session
 */
static srtp_err_status_t srtp_double_dealloc (srtp_cipher_t *c)
{
    srtp_double_ctx_t *ctx;

    debug_print(srtp_mod_double, "dealloc", NULL);

    ctx = (srtp_double_ctx_t*)c->state;
    if (ctx) {
        ctx->inner->type->dealloc(ctx->inner);
        ctx->outer->type->dealloc(ctx->outer);

        /* zeroize the key material */
        octet_string_set_to_zero(ctx, sizeof(srtp_double_ctx_t));
        srtp_crypto_free(ctx);
    }

    /* free memory */
    srtp_crypto_free(c);

    return (srtp_err_status_ok);
}

/*
 * aes_gcm_openssl_context_init(...) initializes the aes_gcm_double_context
 * using the value in key[].
 *
 * The key countains two AES keys of the same size, inner || outer.
 */
static srtp_err_status_t srtp_double_context_init (void* cv, const uint8_t *key)
{
    srtp_err_status_t err;
    srtp_double_ctx_t *c = (srtp_double_ctx_t *)cv;

    debug_print(srtp_mod_double, "init with key %s",
                srtp_octet_string_hex_string(key, c->inner_key_size + c->outer_key_size));

    /* Initialize the inner and outer contexts */
    err = c->inner->type->init(c->inner->state, key);
    if (err != srtp_err_status_ok) {
        return err;
    }

    return c->outer->type->init(c->outer->state, key + c->inner_key_size);
}


/*
 * aes_gcm_openssl_set_iv(c, iv) sets the counter value to the exor of iv with
 * the offset
 *
 * XXX: We use the same IV for both inner and outer contexts.  This should be
 * safe because the keys should be different.
 */
static srtp_err_status_t srtp_double_set_iv (void *cv, uint8_t *iv, srtp_cipher_direction_t direction)
{
    srtp_err_status_t err;
    srtp_double_ctx_t *c = (srtp_double_ctx_t *)cv;

    debug_print(srtp_mod_double, "iv: %s",
                srtp_octet_string_hex_string(iv, 12));

    err = c->inner->type->set_iv(c->inner->state, iv, direction);
    if (err != srtp_err_status_ok) {
        return err;
    }

    return c->outer->type->set_iv(c->outer->state, iv, direction);
}

/*
 * This function processes the AAD
 *
 * Parameters:
 *	c	Crypto context
 *	aad	Additional data to process for AEAD cipher suites
 *	aad_len	length of aad buffer
 */
static srtp_err_status_t srtp_double_set_aad (void *cv, const uint8_t *aad, uint32_t aad_len)
{
    srtp_err_status_t err;
    srtp_double_ctx_t *c = (srtp_double_ctx_t *)cv;

    debug_print(srtp_mod_double, "aad: %s",
                srtp_octet_string_hex_string(aad, aad_len));

    /* The outer AAD is the header as provided */
    debug_print(srtp_mod_double, "outer aad: %s",
                srtp_octet_string_hex_string(aad, aad_len));
    err = c->outer->type->set_aad(c->outer->state, aad, aad_len);
    if (err != srtp_err_status_ok) {
        return err;
    }

    /* For the inner AAD, we will need to cache the AAD until we have the payload */
    if (aad_len > MAX_AAD_LEN) {
        return (srtp_err_status_bad_param);
    }

    debug_print(srtp_mod_double, "caching aad: %s",
                srtp_octet_string_hex_string(aad, aad_len));
    memcpy(c->inner_aad, aad, aad_len);

    return srtp_err_status_ok;
}

/*
 * This function encrypts a buffer using AES GCM mode
 *
 * Parameters:
 *	c	Crypto context
 *	buf	data to encrypt
 *	enc_len	length of encrypt buffer
 */
static srtp_err_status_t srtp_double_encrypt (void *cv, unsigned char *buf, unsigned int *enc_len)
{
    srtp_err_status_t err;
    srtp_double_ctx_t *c = (srtp_double_ctx_t *)cv;

    debug_print(srtp_mod_double, "plaintext: %s",
                srtp_octet_string_hex_string(buf, *enc_len));

    /*
     * Apply null OHB (strip extension and unset X)
     */
    uint32_t inner_aad_len = 0;
    srtp_hdr_t *hdr = (srtp_hdr_t *) c->inner_aad;
    err = apply_ohb(buf, *enc_len, hdr, &inner_aad_len);
    if (err != srtp_err_status_ok) {
        return err;
    }

    /*
     * Set inner AAD
     */
    err = c->inner->type->set_aad(c->inner->state, c->inner_aad, inner_aad_len);
    if (err != srtp_err_status_ok) {
        return err;
    }

    debug_print(srtp_mod_double, "inner aad: %s",
                srtp_octet_string_hex_string(c->inner_aad, inner_aad_len));

    /*
     * Encrypt the data with the inner transform
     */
    err = c->inner->type->encrypt(c->inner->state, buf, enc_len);
    if (err != srtp_err_status_ok) {
        return err;
    }

    debug_print(srtp_mod_double, "inner ciphertext: %s",
                srtp_octet_string_hex_string(buf, *enc_len));

    /*
     * Append the inner tag
     */
    uint32_t tag_len = c->inner_tag_size;
    err = c->inner->type->get_tag(c->inner->state, buf + *enc_len, &tag_len);
    if (err != srtp_err_status_ok) {
        return err;
    }
    *enc_len += tag_len;

    debug_print(srtp_mod_double, "inner tag: %s",
                srtp_octet_string_hex_string(c->inner_aad, inner_aad_len));

    /*
     * Append a null OHB
     */
    buf[*enc_len] = 0;
    *enc_len += 1;

    debug_print(srtp_mod_double, "outer plaintext: %s",
                srtp_octet_string_hex_string(buf, *enc_len));

    err = c->outer->type->encrypt(c->outer->state, buf, enc_len);

    debug_print(srtp_mod_double, "outer ciphertext: %s",
                srtp_octet_string_hex_string(buf, *enc_len));

    return err;
}

/*
 * This function calculates and returns the GCM tag for a given context.
 * This should be called after encrypting the data.  The *len value
 * is increased by the tag size.  The caller must ensure that *buf has
 * enough room to accept the appended tag.
 *
 * Parameters:
 *	c	Crypto context
 *	buf	data to encrypt
 *	len	length of encrypt buffer
 */
static srtp_err_status_t srtp_double_get_tag (void *cv, uint8_t *buf, uint32_t *len)
{
    srtp_double_ctx_t *c = (srtp_double_ctx_t *)cv;
    return c->outer->type->get_tag(c->outer->state, buf, len);
}


/*
 * This function decrypts a buffer using AES GCM mode
 *
 * Parameters:
 *	c	Crypto context
 *	buf	data to encrypt
 *	enc_len	length of encrypt buffer
 */
static srtp_err_status_t srtp_double_decrypt (void *cv, unsigned char *buf, unsigned int *enc_len)
{
    srtp_err_status_t err;
    srtp_double_ctx_t *c = (srtp_double_ctx_t *)cv;

    debug_print(srtp_mod_double, "outer ciphertext: %s",
                srtp_octet_string_hex_string(buf, *enc_len));

    /*
     * Undo the outer transform
     */
    err = c->outer->type->decrypt(c->outer->state, buf, enc_len);
    if (err != srtp_err_status_ok) {
        return err;
    }

    debug_print(srtp_mod_double, "outer plaintext: %s",
                srtp_octet_string_hex_string(buf, *enc_len));

    /*
     * Parse and apply OHB
     *
     * NOTE: Assumes that set_aad has already been called.
     */
    uint32_t inner_aad_len = 0;
    srtp_hdr_t *hdr = (srtp_hdr_t *) c->inner_aad;
    err = apply_ohb(buf, *enc_len, hdr, &inner_aad_len);
    if (err != srtp_err_status_ok) {
        return err;
    }

    /*
     * Set inner AAD
     */
    err = c->inner->type->set_aad(c->inner->state, c->inner_aad, inner_aad_len);
    if (err != srtp_err_status_ok) {
        return err;
    }

    debug_print(srtp_mod_double, "inner aad: %s",
                srtp_octet_string_hex_string(c->inner_aad, inner_aad_len));


    /*
     * Undo the inner transform
     */
    err = c->inner->type->decrypt(c->inner->state, buf, enc_len);
    if (err != srtp_err_status_ok) {
        return err;
    }

    debug_print(srtp_mod_double, "plaintext: %s",
                srtp_octet_string_hex_string(buf, *enc_len));

    return err;
}

/*
 * Here we define the specific instantiation of the double framework with
 * AES-GCM as the inner and outer transforms.  There are two variants, one with
 * AES-128-GCM as the inner and outer transforms, and one with AES-256-GCM
 * likewise.
 */

/*
 * The auth tag for the doubled GCM mode consists of two
 * full-size GCM auth tags.
 */
#define GCM_AUTH_TAG_LEN           16
#define GCM_DOUBLE_AUTH_TAG_LEN    32

/*
 * The following are the global singleton isntances for the
 * base 128-bit and 256-bit GCM ciphers.
 */
extern const srtp_cipher_type_t srtp_aes_gcm_128_openssl;
extern const srtp_cipher_type_t srtp_aes_gcm_256_openssl;

/*
 * The following are the global singleton instances for the
 * 128-bit and 256-bit GCM ciphers.
 */
extern const srtp_cipher_type_t srtp_aes_gcm_128_double_openssl;
extern const srtp_cipher_type_t srtp_aes_gcm_256_double_openssl;


/*
 * This function allocates a new instance of this crypto engine.
 * The key_len parameter should be the length of two AES keys plus
 * the 12-byte salt used by SRTP with AEAD modes:
 *
 *   * 44 = 16 + 16 + 12
 *   * 76 = 32 + 32 + 12
 */
static srtp_err_status_t srtp_aes_gcm_double_openssl_alloc (srtp_cipher_t **c, int key_len, int tag_len)
{
    int base_key_size;
    int base_tag_size;
    const srtp_cipher_type_t *base_type;
    const srtp_cipher_type_t *total_type;
    int algorithm;

    /*
     * Verify the key_len is valid for one of: AES-128/256
     */
    if (key_len != SRTP_AES_GCM_128_DOUBLE_KEY_LEN_WSALT &&
        key_len != SRTP_AES_GCM_256_DOUBLE_KEY_LEN_WSALT) {
        return (srtp_err_status_bad_param);
    }

    if (tag_len != GCM_DOUBLE_AUTH_TAG_LEN) {
        return (srtp_err_status_bad_param);
    }

    /* setup cipher attributes */
    switch (key_len) {
    case SRTP_AES_GCM_128_DOUBLE_KEY_LEN_WSALT:
        base_key_size = SRTP_AES_128_KEY_LEN;
        base_tag_size = GCM_AUTH_TAG_LEN;
        base_type = &srtp_aes_gcm_128_openssl;
        total_type = &srtp_aes_gcm_128_double_openssl;
        algorithm = SRTP_AES_GCM_128_DOUBLE;
        break;
    case SRTP_AES_GCM_256_DOUBLE_KEY_LEN_WSALT:
        base_key_size = SRTP_AES_256_KEY_LEN;
        base_tag_size = GCM_AUTH_TAG_LEN;
        base_type = &srtp_aes_gcm_256_openssl;
        total_type = &srtp_aes_gcm_256_double_openssl;
        algorithm = SRTP_AES_GCM_256_DOUBLE;
        break;
    }

    return srtp_double_alloc(base_type, base_type,
                             total_type, algorithm,
                             base_key_size, base_key_size,
                             base_tag_size, base_tag_size, c);
}



/*
 * Name of this crypto engine
 */
static const char srtp_aes_gcm_128_double_description[] = "Double AES-128 GCM";
static const char srtp_aes_gcm_256_double_description[] = "Double AES-256 GCM";

/*
 * KAT values for AES self-test.  These
 * values we're derived from independent test code
 * using OpenSSL.
 */
static const uint8_t srtp_aes_gcm_double_test_case_128_key[44] = {
    0x48, 0x23, 0x83, 0xca, 0x8e, 0x4e, 0xb2, 0xeb,
    0x86, 0xe0, 0x3e, 0xd1, 0x4c, 0x65, 0xbb, 0x81,
    0x1e, 0xf8, 0x06, 0xb0, 0x1c, 0x41, 0x2b, 0x2f,
    0x69, 0xb2, 0xec, 0x8c, 0x8d, 0xa6, 0xde, 0x22,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c,
};

static uint8_t srtp_aes_gcm_double_test_case_iv[12] = {
    0x1d, 0x2b, 0x97, 0x10, 0x54, 0x0a, 0x78, 0x00,
    0x9c, 0x84, 0xd2, 0xd9,
};

static const uint8_t srtp_aes_gcm_double_test_case_aad[24] = {
    0x90, 0x01, 0x02, 0x03, 0xde, 0xad, 0xbe, 0xef,
    0xfe, 0xed, 0xfa, 0xce, 0xbe, 0xde, 0x00, 0x02,
    0x10, 0x7f, 0x23, 0xa0, 0xa1, 0xa2, 0xa3, 0x00,};

static const uint8_t srtp_aes_gcm_double_test_case_plaintext[60] = {
    0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
    0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
    0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
    0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
    0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
    0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
    0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
    0xba, 0x63, 0x7b, 0x39,
};

static const uint8_t srtp_aes_gcm_double_test_case_128_ciphertext[93] = {
    0x85, 0x29, 0xe6, 0x38, 0xf8, 0x9a, 0x1f, 0xf1,
    0x23, 0x8e, 0x05, 0xa4, 0xad, 0xfe, 0x65, 0x0f,
    0x40, 0x36, 0x8f, 0xf4, 0xd9, 0xcc, 0xca, 0x20,
    0x02, 0x42, 0xd0, 0x9f, 0x82, 0x71, 0x59, 0xd6,
    0xe7, 0xbe, 0x6f, 0xd4, 0xfe, 0x49, 0x96, 0x62,
    0xdf, 0xdf, 0xf3, 0x46, 0xdb, 0x43, 0x7c, 0x4f,
    0x1a, 0x22, 0x52, 0xe0, 0xcf, 0x9e, 0x51, 0x9a,
    0x2d, 0x25, 0xbc, 0xab, 0x30, 0x86, 0x40, 0x60,
    0x09, 0xac, 0x9e, 0xd3, 0xf8, 0x69, 0x85, 0x71,
    0x50, 0xc0, 0xd1, 0x69, 0x19, 0xb4, 0xa0, 0x49,
    0x32, 0x4e, 0x01, 0xc1, 0x02, 0x2c, 0x9d, 0x9d,
    0xcc, 0xed, 0x48, 0x65, 0xba,
};

static const srtp_cipher_test_case_t srtp_aes_gcm_double_test_case_128 = {
    SRTP_AES_GCM_128_DOUBLE_KEY_LEN_WSALT,            /* octets in key            */
    srtp_aes_gcm_double_test_case_128_key,            /* key                      */
    srtp_aes_gcm_double_test_case_iv,                 /* packet index             */
    60,                                               /* octets in plaintext      */
    srtp_aes_gcm_double_test_case_plaintext,          /* plaintext                */
    93,                                               /* octets in ciphertext     */
    srtp_aes_gcm_double_test_case_128_ciphertext,     /* ciphertext  + tag        */
    24,                                               /* octets in AAD            */
    srtp_aes_gcm_double_test_case_aad,                /* AAD                      */
    GCM_DOUBLE_AUTH_TAG_LEN,
    NULL,                                             /* pointer to next testcase */
};

static const uint8_t srtp_aes_gcm_double_test_case_256_key[76] = {
    0x91, 0x48, 0x08, 0xdc, 0xf7, 0xde, 0x74, 0x75,
    0xd5, 0x67, 0x14, 0xde, 0xea, 0x6a, 0x67, 0xd1,
    0xf8, 0x34, 0x9a, 0x84, 0xb3, 0x0e, 0xbe, 0x82,
    0x9b, 0xb5, 0xe0, 0x6a, 0x42, 0x69, 0x43, 0x53,
    0x01, 0xed, 0xae, 0xa4, 0xa1, 0x38, 0x01, 0xfa,
    0x5e, 0x7d, 0x63, 0x9c, 0xc1, 0x67, 0x71, 0xa3,
    0xc2, 0xda, 0x09, 0xd5, 0xc2, 0x7a, 0xf7, 0x05,
    0xe1, 0xa2, 0xd6, 0xad, 0xab, 0x2c, 0x71, 0x32,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c,
};

static const uint8_t srtp_aes_gcm_double_test_case_256_ciphertext[93] = {
    0xe1, 0x14, 0xbb, 0x98, 0x7a, 0x0e, 0xc0, 0xbc,
    0x48, 0x6f, 0x96, 0xc1, 0x66, 0x2e, 0xf3, 0x2b,
    0x3f, 0x76, 0xb5, 0xc8, 0x61, 0x9b, 0xfe, 0xce,
    0x28, 0xb4, 0x34, 0x1b, 0xb0, 0x32, 0x39, 0x5f,
    0xa6, 0x57, 0x14, 0x5f, 0x4e, 0x83, 0x47, 0xa7,
    0xd7, 0xf9, 0x9e, 0xaa, 0x72, 0xc5, 0x27, 0x39,
    0xa8, 0x96, 0xf5, 0x4a, 0xef, 0xc3, 0xfa, 0xbe,
    0x19, 0x48, 0xba, 0x7c, 0x87, 0x43, 0xf9, 0xf5,
    0x20, 0x44, 0x59, 0xcc, 0x8d, 0x00, 0x43, 0x27,
    0x75, 0x12, 0xf3, 0x92, 0xbf, 0xd4, 0xd0, 0xc1,
    0x9b, 0xee, 0xa3, 0x3d, 0xcc, 0x86, 0x46, 0xb9,
    0x68, 0xb5, 0x8e, 0xc3, 0x73,
};


static const srtp_cipher_test_case_t srtp_aes_gcm_double_test_case_256 = {
    SRTP_AES_GCM_128_DOUBLE_KEY_LEN_WSALT,            /* octets in key            */
    srtp_aes_gcm_double_test_case_256_key,            /* key                      */
    srtp_aes_gcm_double_test_case_iv,                 /* packet index             */
    60,                                               /* octets in plaintext      */
    srtp_aes_gcm_double_test_case_plaintext,          /* plaintext                */
    93,                                               /* octets in ciphertext     */
    srtp_aes_gcm_double_test_case_256_ciphertext,     /* ciphertext  + tag        */
    24,                                               /* octets in AAD            */
    srtp_aes_gcm_double_test_case_aad,                /* AAD                      */
    GCM_DOUBLE_AUTH_TAG_LEN,
    NULL,                                             /* pointer to next testcase */
};

/*
 * This is the vector function table for this crypto engine.
 */
const srtp_cipher_type_t srtp_aes_gcm_128_double_openssl = {
    srtp_aes_gcm_double_openssl_alloc,
    srtp_double_dealloc,
    srtp_double_context_init,
    srtp_double_set_aad,
    srtp_double_encrypt,
    srtp_double_decrypt,
    srtp_double_set_iv,
    srtp_double_get_tag,
    srtp_aes_gcm_128_double_description,
    &srtp_aes_gcm_double_test_case_128,
    SRTP_AES_GCM_128_DOUBLE
};

/*
 * This is the vector function table for this crypto engine.
 */
const srtp_cipher_type_t srtp_aes_gcm_256_double_openssl = {
    srtp_aes_gcm_double_openssl_alloc,
    srtp_double_dealloc,
    srtp_double_context_init,
    srtp_double_set_aad,
    srtp_double_encrypt,
    srtp_double_decrypt,
    srtp_double_set_iv,
    srtp_double_get_tag,
    srtp_aes_gcm_256_double_description,
    &srtp_aes_gcm_double_test_case_256,
    SRTP_AES_GCM_256_DOUBLE
};


/*
 * aes_kw.c
 *
 * AES Key Wrap with Padding
 *
 * Richard L. Barnes
 * Cisco Systems, Inc.
 *
 */

/*
 *
 * Copyright (c) 2015, Cisco Systems, Inc.
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

#include "aes_kw.h"
#include "crypto_types.h"
#include "err.h" /* for srtp_debug */
#include "alloc.h"
#include "cipher_types.h"

#include <nss.h>

#define AES_KW_MAX_OVERHEAD 16
#define AES_KW_MECHANISM    CKM_NSS_AES_KEY_WRAP
#define FAKE_MECHANISM      CKM_SHA_1_HMAC
#define FAKE_OPERATION      CKA_SIGN


srtp_debug_module_t srtp_mod_aes_kw = {
    0,                 /* debugging is off by default */
    "aes gcm key wrap" /* printable module name       */
};

/*
 * This function allocates a new instance of this crypto engine.
 * The key_len parameter should be one of 16 or 32 for
 * AES-128-KW or AES-256-KW respectively.
 */
static srtp_err_status_t srtp_aes_kw_alloc(srtp_cipher_t **c,
                                           int key_len,
                                           int tlen)
{
    srtp_aes_kw_ctx_t *kw;

    debug_print(srtp_mod_aes_kw, "allocating cipher with key length %d",
                key_len);

    /*
     * Verify the key_len is valid for one of: AES-128/192/256
     */
    if (key_len != SRTP_AES_128_KEY_LEN &&
        key_len != SRTP_AES_256_KEY_LEN) {
        return srtp_err_status_bad_param;
    }

    /* Initialize NSS */
    if (!NSS_IsInitialized() && NSS_NoDB_Init(NULL) != SECSuccess) {
        return (srtp_err_status_cipher_fail);
    }

    /* allocate memory a cipher of type aes_kw */
    *c = (srtp_cipher_t *)srtp_crypto_alloc(sizeof(srtp_cipher_t));
    if (*c == NULL) {
        return srtp_err_status_alloc_fail;
    }

    kw = (srtp_aes_kw_ctx_t *)srtp_crypto_alloc(sizeof(srtp_aes_kw_ctx_t));
    if (kw == NULL) {
        srtp_crypto_free(*c);
        *c = NULL;
        return srtp_err_status_alloc_fail;
    }

    kw->slot = PK11_GetInternalSlot();
    if (!kw->slot) {
      return srtp_err_status_cipher_fail;
    }

    kw->key = NULL;

    /* set pointers */
    (*c)->state = kw;

    /* setup cipher parameters */
    switch (key_len) {
    case SRTP_AES_128_KEY_LEN:
        (*c)->algorithm = SRTP_AES_KW_128;
        (*c)->type = &srtp_aes_kw_128;
        kw->key_size = SRTP_AES_128_KEY_LEN;
        break;
    case SRTP_AES_256_KEY_LEN:
        (*c)->algorithm = SRTP_AES_KW_256;
        (*c)->type = &srtp_aes_kw_256;
        kw->key_size = SRTP_AES_256_KEY_LEN;
        break;
    }

    /* set key size        */
    (*c)->key_len = key_len;

    return srtp_err_status_ok;
}

/*
 * This function deallocates an AES-KW session.
 */
static srtp_err_status_t srtp_aes_kw_dealloc(srtp_cipher_t *c)
{
    srtp_aes_kw_ctx_t *ctx;

    ctx = (srtp_aes_kw_ctx_t *)c->state;
    if (ctx) {
        /* free any PK11 values that have been created */
        if (ctx->slot) {
            PK11_FreeSlot(ctx->slot);
            ctx->slot = NULL;
        }

        if (ctx->key) {
            PK11_FreeSymKey(ctx->key);
            ctx->key = NULL;
        }

        /* zeroize everything */
        octet_string_set_to_zero(ctx, sizeof(srtp_aes_kw_ctx_t));
        srtp_crypto_free(ctx);
    }

    /* free memory */
    srtp_crypto_free(c);

    return (srtp_err_status_ok);
}

/*
 * aes_gcm_nss_context_init(...) initializes the aes_gcm_context
 * using the value in key[].
 *
 * the key is the secret key
 */
static srtp_err_status_t srtp_aes_kw_context_init(void *cv,
                                                  const uint8_t *key)
{
    srtp_aes_kw_ctx_t *c = (srtp_aes_kw_ctx_t *)cv;

    debug_print(srtp_mod_aes_kw, "key:  %s",
                srtp_octet_string_hex_string(key, c->key_size));

    if (!c->slot) {
        return srtp_err_status_bad_param;
    }

    SECItem keyItem = { siBuffer, (unsigned char *) key, c->key_size };
    c->key = PK11_ImportSymKey(c->slot, AES_KW_MECHANISM, PK11_OriginUnwrap,
                               CKA_WRAP, &keyItem, NULL);
    if (!c->key) {
        return srtp_err_status_cipher_fail;
    }

    return (srtp_err_status_ok);
}

/*
 * This function encrypts a buffer (in place) using AES KW mode
 */
static srtp_err_status_t srtp_aes_kw_encrypt(void *cv,
                                             unsigned char *buf,
                                             unsigned int *enc_len)
{
    srtp_aes_kw_ctx_t *c = (srtp_aes_kw_ctx_t *)cv;

    // Import the data into a fake PK11SymKey structure
    SECItem data = {siBuffer, buf, *enc_len};
    PK11SymKey *keyToWrap = PK11_ImportSymKey(c->slot, FAKE_MECHANISM,
                                              PK11_OriginUnwrap, FAKE_OPERATION,
                                              &data, NULL);
    if (!keyToWrap) {
       printf("failed to import key: %d\n", PORT_GetError());
       return srtp_err_status_algo_fail;
    }

    // Encrypt and return the wrapped key
    SECStatus rv;
    data.len += AES_KW_MAX_OVERHEAD;
    rv = PK11_WrapSymKey(AES_KW_MECHANISM, NULL, c->key, keyToWrap, &data);
    PK11_FreeSymKey(keyToWrap);
    if (rv != SECSuccess) {
       printf("failed to wrap key: %08x\n", PORT_GetError());
        return srtp_err_status_algo_fail;
    }

    *enc_len = data.len;
    return srtp_err_status_ok;
}

/*
 * This function decrypts a buffer (in place) using AES KW mode
 */
static srtp_err_status_t srtp_aes_kw_decrypt(void *cv,
                                             unsigned char *buf,
                                             unsigned int *enc_len)
{
    srtp_aes_kw_ctx_t *c = (srtp_aes_kw_ctx_t *)cv;

    // Unwrap the key
    SECItem data = {siBuffer, buf, *enc_len};
    PK11SymKey *unwrappedKey = PK11_UnwrapSymKey(c->key, AES_KW_MECHANISM, NULL,
                                                 &data, FAKE_MECHANISM, FAKE_OPERATION,
                                                 *enc_len);
    if (!unwrappedKey) {
        return srtp_err_status_algo_fail;
    }

    // Export the key data
    SECStatus rv;
    rv = PK11_ExtractKeyValue(unwrappedKey);
    if (rv != SECSuccess) {
        PK11_FreeSymKey(unwrappedKey);
        return srtp_err_status_algo_fail;
    }

    SECItem *keyData = PK11_GetKeyData(unwrappedKey);
    memcpy(buf, keyData->data, keyData->len);
    *enc_len = keyData->len;

    PK11_FreeSymKey(unwrappedKey);
    return srtp_err_status_ok;
}

/*
 * Name of this crypto engine
 */
static const char srtp_aes_kw_128_description[] =
    "AES-128 KW";
static const char srtp_aes_kw_256_description[] =
    "AES-256 KW";

// From RFC 3394, Section 4.3
static const uint8_t srtp_aes_kw_128_test_case_0_key[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};

static const uint8_t srtp_aes_kw_128_test_case_0_plaintext[16] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
};

static const uint8_t srtp_aes_kw_128_test_case_0_ciphertext[24] = {
    0x1F, 0xA6, 0x8B, 0x0A, 0x81, 0x12, 0xB4, 0x47,
    0xAE, 0xF3, 0x4B, 0xD8, 0xFB, 0x5A, 0x7B, 0x82,
    0x9D, 0x3E, 0x86, 0x23, 0x71, 0xD2, 0xCF, 0xE5,
};

static const srtp_cipher_test_case_t srtp_aes_kw_128_test_case_0 = {
    SRTP_AES_128_KEY_LEN,                   /* octets in key            */
    srtp_aes_kw_128_test_case_0_key,        /* key                      */
    NULL,                                   /* iv                       */
    16,                                     /* plaintext length         */
    srtp_aes_kw_128_test_case_0_plaintext,  /* plaintext                */
    24,                                     /* ciphertext length        */
    srtp_aes_kw_128_test_case_0_ciphertext, /* ciphertext               */
    0,                                      /* aad length               */
    NULL,                                   /* aad                      */
    0,                                      /* tag length               */
    NULL                                    /* pointer to next testcase */
};

// From RFC 3394, Section 4.3
static const uint8_t srtp_aes_kw_256_test_case_0_key[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
};

static const uint8_t srtp_aes_kw_256_test_case_0_plaintext[16] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
};

static const uint8_t srtp_aes_kw_256_test_case_0_ciphertext[24] = {
    0x64, 0xe8, 0xc3, 0xf9, 0xce, 0x0f, 0x5b, 0xa2,
    0x63, 0xe9, 0x77, 0x79, 0x05, 0x81, 0x8a, 0x2a,
    0x93, 0xc8, 0x19, 0x1e, 0x7d, 0x6e, 0x8a, 0xe7,
};

static const srtp_cipher_test_case_t srtp_aes_kw_256_test_case_0 = {
    SRTP_AES_256_KEY_LEN,                   /* octets in key            */
    srtp_aes_kw_256_test_case_0_key,        /* key                      */
    NULL,                                   /* iv                       */
    16,                                     /* plaintext length         */
    srtp_aes_kw_256_test_case_0_plaintext,  /* plaintext                */
    24,                                     /* ciphertext length        */
    srtp_aes_kw_256_test_case_0_ciphertext, /* ciphertext               */
    0,                                      /* aad length               */
    NULL,                                   /* aad                      */
    0,                                      /* tag length               */
    NULL                                    /* pointer to next testcase */
};

/*
 * This is the function table for this crypto engine.
 */
const srtp_cipher_type_t srtp_aes_kw_128 = {
    srtp_aes_kw_alloc,
    srtp_aes_kw_dealloc,
    srtp_aes_kw_context_init,
    0, /* set_aad */
    srtp_aes_kw_encrypt,
    srtp_aes_kw_decrypt,
    0, /* set_iv */
    0, /* get_tag */
    srtp_aes_kw_128_description,
    &srtp_aes_kw_128_test_case_0,
    SRTP_AES_KW_128,
};

const srtp_cipher_type_t srtp_aes_kw_256 = {
    srtp_aes_kw_alloc,
    srtp_aes_kw_dealloc,
    srtp_aes_kw_context_init,
    0, /* set_aad */
    srtp_aes_kw_encrypt,
    srtp_aes_kw_decrypt,
    0, /* set_iv */
    0, /* get_tag */
    srtp_aes_kw_256_description,
    &srtp_aes_kw_256_test_case_0,
    SRTP_AES_KW_256,
};

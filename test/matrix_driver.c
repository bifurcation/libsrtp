#include <srtp.h>
#include "srtp_priv.h"

// Policy inputs
#define TEST_MKI_ID_SIZE 4

unsigned char test_key[46] = {
    0xe1, 0xf9, 0x7a, 0x0d, 0x3e, 0x01, 0x8b, 0xe0,
    0xd6, 0x4f, 0xa3, 0x2c, 0x06, 0xde, 0x41, 0x39,
    0x0e, 0xc6, 0x75, 0xad, 0x49, 0x8a, 0xfe, 0xeb,
    0xb6, 0x96, 0x0b, 0x3a, 0xab, 0xe6, 0xc1, 0x73,
    0xc3, 0x17, 0xf2, 0xda, 0xbe, 0x35, 0x77, 0x93,
    0xb6, 0x96, 0x0b, 0x3a, 0xab, 0xe6
};

unsigned char test_mki_id[TEST_MKI_ID_SIZE] = {
    0xe1, 0xf9, 0x7a, 0x0d
};

srtp_master_key_t master_key_1 = {
    test_key,
    test_mki_id,
    TEST_MKI_ID_SIZE
};

srtp_master_key_t *test_keys[1] = {
    &master_key_1,
};

int xtn_headers[3] = {1, 3, 4};

// Non-AEAD Policy
const srtp_policy_t ctr_policy = {
    { ssrc_any_outbound, 0 }, /* SSRC */
    {
        SRTP_AES_ICM_128,               /* cipher type                 */
        SRTP_AES_ICM_128_KEY_LEN_WSALT, /* cipher key length in octets */
        SRTP_HMAC_SHA1,                 /* authentication func type    */
        16,                             /* auth key length in octets   */
        10,                             /* auth tag length in octets   */
        sec_serv_conf_and_auth          /* security services flag      */
    },
    {
        SRTP_AES_ICM_128,               /* cipher type                 */
        SRTP_AES_ICM_128_KEY_LEN_WSALT, /* cipher key length in octets */
        SRTP_HMAC_SHA1,                 /* authentication func type    */
        16,                             /* auth key length in octets   */
        10,                             /* auth tag length in octets   */
        sec_serv_conf_and_auth          /* security services flag      */
    },
    NULL,
    (srtp_master_key_t **)test_keys,
    1,    /* indicates the number of Master keys          */
    NULL, /* indicates that EKT is not in use             */
    128,  /* replay window size                           */
    0,    /* retransmission not allowed                   */
    NULL, /* no encrypted extension headers               */
    0,    /* list of encrypted extension headers is empty */
    NULL
};

// AEAD Policy
const srtp_policy_t gcm_policy = {
    { ssrc_any_outbound, 0 }, /* SSRC */
    {
        SRTP_AES_GCM_128,               /* cipher type                 */
        SRTP_AES_GCM_128_KEY_LEN_WSALT, /* cipher key length in octets */
        SRTP_NULL_AUTH,                 /* authentication func type    */
        0,                              /* auth key length in octets   */
        16,                             /* auth tag length in octets   */
        sec_serv_conf_and_auth          /* security services flag      */
    },
    {
        SRTP_AES_GCM_128,               /* cipher type                 */
        SRTP_AES_GCM_128_KEY_LEN_WSALT, /* cipher key length in octets */
        SRTP_NULL_AUTH,                 /* authentication func type    */
        0,                              /* auth key length in octets   */
        16,                             /* auth tag length in octets   */
        sec_serv_conf_and_auth          /* security services flag      */
    },
    NULL,
    (srtp_master_key_t **)test_keys,
    1,    /* indicates the number of Master keys          */
    NULL, /* indicates that EKT is not in use             */
    128,  /* replay window size                           */
    0,    /* retransmission not allowed                   */
    NULL, /* no encrypted extension headers               */
    0,    /* list of encrypted extension headers is empty */
    NULL
};

// TODO Plaintext packets

#define SRTP_PLAINTEXT_SIZE   56
#define SRTP_CIPHERTEXT_SIZE  80
#define SRTCP_PLAINTEXT_SIZE  50
#define SRTCP_CIPHERTEXT_SIZE  80

uint8_t srtp_plaintext[SRTP_PLAINTEXT_SIZE] = {
    0x90, 0x0f, 0x12, 0x34, 0xde, 0xca, 0xfb, 0xad,
    0xca, 0xfe, 0xba, 0xbe, 0xBE, 0xDE, 0x00, 0x06,
    0x17, 0x41, 0x42, 0x73, 0xA4, 0x75, 0x26, 0x27,
    0x48, 0x22, 0x00, 0x00, 0xC8, 0x30, 0x8E, 0x46,
    0x55, 0x99, 0x63, 0x86, 0xB3, 0x95, 0xFB, 0x00,
    0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
    0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab
};
uint8_t srtp_ciphertext[SRTP_CIPHERTEXT_SIZE];

uint8_t srtcp_plaintext[SRTCP_PLAINTEXT_SIZE] = {
    0xc8, 0x00, 0x06, 0xf3, 0xcb, 0x20, 0x01, 0x83,
    0xab, 0x03, 0xa1, 0xeb, 0x02, 0x0b, 0x3a, 0x00,
    0x00, 0x94, 0x20, 0x00, 0x00, 0x00, 0x9e, 0x00,
    0x00, 0x9b, 0x88, 0x81, 0xca, 0x00, 0x05, 0xf3,
    0xcb, 0x20, 0x01, 0x01, 0x0a, 0x6f, 0x75, 0x74,
    0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x00, 0x00,
    0x00, 0x00}
;
uint8_t srtcp_ciphertext[SRTP_CIPHERTEXT_SIZE] = {0, 0, 0, 0};

// Vector creators
#define REQUIRE(x) \
  rv = (x); \
  if (rv != srtp_err_status_ok) { return rv; }

#define MAIN_REQUIRE(x) \
  rv = (x); \
  if (rv != srtp_err_status_ok) { \
    return rv; \
  }

srtp_err_status_t do_srtp(int aead, int mki, int enc_ext) {
  srtp_err_status_t rv;
  srtp_policy_t policy = (aead)? gcm_policy : ctr_policy;

  if (enc_ext) {
    policy.enc_xtn_hdr = xtn_headers;
    policy.enc_xtn_hdr_count = sizeof(xtn_headers) / sizeof(xtn_headers[0]);
  }

  srtp_t srtp;
  REQUIRE(srtp_create(&srtp, &policy));

  int len = sizeof(srtp_plaintext);
  memset(srtp_ciphertext, 0, sizeof(srtp_ciphertext));
  memcpy(srtp_ciphertext, srtp_plaintext, sizeof(srtp_plaintext));
  if (mki) {
    REQUIRE(srtp_protect_mki(srtp, srtp_ciphertext, &len, 1, 0));
  } else {
    REQUIRE(srtp_protect(srtp, srtp_ciphertext, &len));
  }

  printf("===== SRTP (aead=%d, mki=%d, enc_ext=%d) =====\n", aead, mki, enc_ext);
  printf("%s\n\n", srtp_octet_string_hex_string(srtp_ciphertext, len));

  return srtp_err_status_ok;
}

srtp_err_status_t do_srtcp(int aead, int mki, int auth_only) {
  srtp_err_status_t rv;
  srtp_policy_t policy = (aead)? gcm_policy : ctr_policy;
  policy.rtcp.sec_serv = (auth_only)? sec_serv_auth : sec_serv_conf_and_auth;

  srtp_t srtp;
  REQUIRE(srtp_create(&srtp, &policy));

  int len = sizeof(srtcp_plaintext);
  memset(srtcp_ciphertext, 0, sizeof(srtcp_ciphertext));
  memcpy(srtcp_ciphertext, srtcp_plaintext, sizeof(srtcp_plaintext));
  if (mki) {
    REQUIRE(srtp_protect_rtcp_mki(srtp, srtcp_ciphertext, &len, 1, 0));
  } else {
    REQUIRE(srtp_protect_rtcp(srtp, srtcp_ciphertext, &len));
  }

  printf("===== SRCTP (aead=%d, mki=%d, auth_only=%d) =====\n", aead, mki, auth_only);
  printf("%s\n\n", srtp_octet_string_hex_string(srtcp_ciphertext, len));

  return srtp_err_status_ok;
}

int main() {
  srtp_err_status_t rv;
  MAIN_REQUIRE(srtp_init());

  // SRTP tests
  MAIN_REQUIRE(do_srtp(0, 0, 0));
  MAIN_REQUIRE(do_srtp(0, 1, 0));
  MAIN_REQUIRE(do_srtp(0, 0, 1));
#ifdef GCM
  MAIN_REQUIRE(do_srtp(1, 0, 0));
  MAIN_REQUIRE(do_srtp(1, 1, 0));
  MAIN_REQUIRE(do_srtp(1, 0, 1));
#endif

  // SRTCP tests
  MAIN_REQUIRE(do_srtcp(0, 0, 0));
  MAIN_REQUIRE(do_srtcp(0, 1, 0));
  MAIN_REQUIRE(do_srtcp(0, 0, 1));
#ifdef GCM
  MAIN_REQUIRE(do_srtcp(1, 0, 0));
  MAIN_REQUIRE(do_srtcp(1, 1, 0));
  MAIN_REQUIRE(do_srtcp(1, 0, 1));
#endif

  return srtp_shutdown();
}

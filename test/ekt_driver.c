/*
 * ekt_driver.c
 *
 * a test driver for EKT in libSRTP
 *
 * Richard L. Barnes
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

#include <string.h>
#include <stdio.h>
#include "ekt.h"
#include "util.h"

#define PACKET_BUFFER_SIZE 1024

const uint32_t base_ssrc = 0xcafebabe;

const uint8_t base_packet[] = {
  0x00, 0x00, 0x12, 0x34,
  0xde, 0xca, 0xfb, 0xad,
  0xca, 0xfe, 0xba, 0xbe,
  0x01, 0x02, 0x03, 0x04,
};

const size_t base_packet_size = 16;

/*
 * This test checks that short tags are added and removed correctly.
 * No real SRTP setup is required.
 */
srtp_err_status_t test_short_tag() {
  ekt_t ekt;
  srtp_err_status_t err = srtp_err_status_ok;

  ekt_spi_t spi = 0xABCD;
  ekt_cipher_t cipher = EKT_CIPHER_AESKW_128;
  size_t ekt_key_size = 16;
  uint8_t ekt_key[] = {
    0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8,
    0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
  };

  err = ekt_create(&ekt, spi, cipher, ekt_key, ekt_key_size);
  if (err != srtp_err_status_ok) {
    return err;
  }

  uint8_t pkt_orig[PACKET_BUFFER_SIZE];
  int size_orig = base_packet_size;
  memcpy(pkt_orig, base_packet, size_orig);

  uint8_t pkt_added[PACKET_BUFFER_SIZE];
  int size_added = base_packet_size;
  memcpy(pkt_added, base_packet, size_added);

  // Test add
  err = ekt_add_tag(ekt, NULL, pkt_added, &size_added, EKT_FLAG_SHORT_TAG);
  if (err != srtp_err_status_ok) {
    goto fail;
  }

  if ((size_added != size_orig + 1) ||
      (0 != memcmp(pkt_orig, pkt_added, size_orig)) ||
      (0 != pkt_added[size_orig])) {
    err = srtp_err_status_fail;
    goto fail;
  }

  // Test parse
  uint8_t pkt_parsed[PACKET_BUFFER_SIZE];
  int size_parsed = size_added;
  memcpy(pkt_parsed, pkt_added, size_added);

  err = ekt_process_tag(ekt, NULL, pkt_parsed, &size_parsed);
  if (err != srtp_err_status_ok) {
    goto fail;
  }

  if ((size_parsed != size_orig) ||
      (0 != memcmp(pkt_orig, pkt_parsed, size_parsed))) {
    err = srtp_err_status_fail;
    goto fail;
  }

fail:
  ekt_dealloc(ekt);
  return err;
}

#define ATTEMPT(x) \
  err = x; \
  if (err != srtp_err_status_ok) { \
    goto fail; \
  }

#define ASSERT(x) \
  if (!(x)) { \
    err = srtp_err_status_fail; \
    goto fail; \
  }

srtp_err_status_t init_test_session(srtp_t *session, uint8_t *key, srtp_ssrc_type_t type) {
  srtp_policy_t policy;
  memset(&policy, 0, sizeof(srtp_policy_t));

  srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&policy.rtp);
  srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&policy.rtcp);
  policy.key = key;
  policy.ssrc.type = type;
  policy.ssrc.value = 0;
  policy.window_size = 1024;
  policy.next = NULL;

  return srtp_create(session, &policy);
}

srtp_err_status_t test_half_tag(ekt_cipher_t cipher, size_t ekt_key_size, uint8_t *ekt_key) {
  srtp_err_status_t err = srtp_err_status_ok;

  // Create an SRTP session
  uint8_t send_key_wsalt[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
    0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd,
  };

  srtp_t send_srtp = NULL;
  srtp_policy_t policy;
  memset(&policy, 0, sizeof(srtp_policy_t));

  srtp_crypto_policy_set_aes_gcm_128_double(&policy.rtp);
  srtp_crypto_policy_set_aes_gcm_128_16_auth(&policy.rtcp);
  policy.key = send_key_wsalt;
  policy.ssrc.type = ssrc_any_outbound;
  policy.ssrc.value = 0;
  policy.window_size = 1024;
  policy.next = NULL;

  ATTEMPT( srtp_create(&send_srtp, &policy) );

  // Create the EKT transforms
  ekt_spi_t spi = 0xABCD;
  ekt_t send_ekt = NULL;
  ekt_t recv_ekt = NULL;
  ATTEMPT( ekt_create(&send_ekt, spi, cipher, ekt_key, ekt_key_size) );
  ATTEMPT( ekt_create(&recv_ekt, spi, cipher, ekt_key, ekt_key_size) );

  // Packet buffers
  uint8_t pkt_orig[PACKET_BUFFER_SIZE];
  uint8_t pkt_enc[PACKET_BUFFER_SIZE];
  uint8_t pkt_ekt_add_half[PACKET_BUFFER_SIZE];
  uint8_t pkt_ekt_add_full[PACKET_BUFFER_SIZE];

  // Packet lengths and known answers
  int auth_tag_size = 10;
  int ekt_tag_size_half = 1 + 16 +   /* encrypted SRTP key    */
                          4 + 4 +    /* SSRC and ROC          */
                          15 +       /* encryption overhead   */
                          2 + 2 + 1; /* SPI, length, tag type */
  int ekt_tag_size_full = 1 + 32 +   /* encrypted SRTP key    */
                          4 + 4 +    /* SSRC and ROC          */
                          15 +       /* encryption overhead   */
                          2 + 2 + 1; /* SPI, length, tag type */

  // Read in the base packet
  int size_orig = base_packet_size;
  memcpy(pkt_orig, base_packet, size_orig);

  // Encrypt base packet with sender context
  int size_enc = base_packet_size;
  memcpy(pkt_enc, base_packet, size_enc);
  ATTEMPT( srtp_protect(send_srtp, pkt_enc, &size_enc) );
  ASSERT( size_enc == size_orig + auth_tag_size );

  // Add half-size EKT tag and check its size
  int size_ekt_half = size_enc;
  memcpy(pkt_ekt_add_half, pkt_enc, size_ekt_half);
  ATTEMPT( ekt_add_tag(send_ekt, send_srtp, pkt_ekt_add_half, &size_ekt_half, EKT_FLAG_HALF_KEY) );
  ASSERT( size_ekt_half == size_enc + ekt_tag_size_half );

  // Add full-size EKT tag and check its size
  int size_ekt_full = size_enc;
  memcpy(pkt_ekt_add_full, pkt_enc, size_ekt_full);
  ATTEMPT( ekt_add_tag(send_ekt, send_srtp, pkt_ekt_add_full, &size_ekt_full, 0) );
  ASSERT( size_ekt_full == size_enc + ekt_tag_size_full );

fail:
  if (send_srtp) { srtp_dealloc(send_srtp); }
  return err;
}

/*
 * This test implements the following scenario:
 *
 * * Sender and recevier are initialized with generic contexts,
 *   using the same master salt, but different master keys.
 * * Sender and receiver are provisioned with the same EKT context.
 * * Sender encrypts an SRTP packet using its context
 * * Sender adds an EKT tag to the packet
 * * Receiver processes the EKT tag on the packet
 *   * This should initialize the receiver's state
 * * Receiver decrypts the SRTP packet
 *
 * At the end the SRTP packet should have decrypted successfully,
 * and the sender and receiver should have the same packet.
 */
srtp_err_status_t test_long_tag(ekt_cipher_t cipher, size_t ekt_key_size, uint8_t *ekt_key) {
  srtp_err_status_t err = srtp_err_status_ok;

  // Create the SRTP sessions
  uint8_t send_key_wsalt[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
    0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd,
  };

  uint8_t recv_key_wsalt[] = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
    0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd,
  };

  srtp_t send_srtp = NULL;
  srtp_t recv_srtp = NULL;
  ATTEMPT( init_test_session(&send_srtp, send_key_wsalt, ssrc_any_outbound) );
  ATTEMPT( init_test_session(&recv_srtp, recv_key_wsalt, ssrc_any_inbound) );

  // Create the EKT transforms
  ekt_spi_t spi = 0xABCD;

  ekt_t send_ekt = NULL;
  ekt_t recv_ekt = NULL;
  ATTEMPT( ekt_create(&send_ekt, spi, cipher, ekt_key, ekt_key_size) );
  ATTEMPT( ekt_create(&recv_ekt, spi, cipher, ekt_key, ekt_key_size) );

  // Packet buffers
  uint8_t pkt_orig[PACKET_BUFFER_SIZE];
  uint8_t pkt_enc[PACKET_BUFFER_SIZE];
  uint8_t pkt_ekt_add[PACKET_BUFFER_SIZE];
  uint8_t pkt_ekt_proc[PACKET_BUFFER_SIZE];
  uint8_t pkt_dec[PACKET_BUFFER_SIZE];

  // Packet lengths and known answers
  int auth_tag_size = 10;
  int ekt_tag_size = 1 + 16 +   /* encrypted SRTP key    */
                     4 + 4 +    /* SSRC and ROC          */
                     15 +       /* encryption overhead   */
                     2 + 2 + 1; /* SPI, length, tag type */

  // Read in the base packet
  int size_orig = base_packet_size;
  memcpy(pkt_orig, base_packet, size_orig);

  // Encrypt base packet with sender context
  int size_enc = base_packet_size;
  memcpy(pkt_enc, base_packet, size_enc);
  ATTEMPT( srtp_protect(send_srtp, pkt_enc, &size_enc) );

  ASSERT( size_enc == size_orig + auth_tag_size );

  // Add EKT tag with base context
  int size_ekt_add = size_enc;
  memcpy(pkt_ekt_add, pkt_enc, size_ekt_add);
  ATTEMPT( ekt_add_tag(send_ekt, send_srtp, pkt_ekt_add, &size_ekt_add, 0) );

  uint8_t readable_tag[] = {0xAB, 0xCD, 0x00, 0x28, 0x02};
  int readable_tag_size = sizeof(readable_tag);
  ASSERT( size_ekt_add == size_enc + ekt_tag_size );
  ASSERT( 0 == memcmp(pkt_ekt_add + size_ekt_add - readable_tag_size,
                      readable_tag, readable_tag_size) );

  // Process EKT tag with receiver context
  int size_ekt_proc = size_ekt_add;
  memcpy(pkt_ekt_proc, pkt_ekt_add, size_ekt_proc);
  ATTEMPT( ekt_process_tag(recv_ekt, recv_srtp, pkt_ekt_proc, &size_ekt_proc) );

  ASSERT( size_ekt_proc == size_enc );
  ASSERT( 0 == memcmp(pkt_ekt_proc, pkt_enc, size_ekt_proc) );

  // Decrypt encrypted packet with receiver context
  int size_dec = size_ekt_proc;
  memcpy(pkt_dec, pkt_ekt_proc, size_ekt_proc);
  ATTEMPT( srtp_unprotect(recv_srtp, pkt_dec, &size_dec) );

  ASSERT( size_dec == size_orig );
  ASSERT( 0 == memcmp(pkt_dec, pkt_orig, size_dec) );

fail:
  if (send_srtp) { srtp_dealloc(send_srtp); }
  if (recv_srtp) { srtp_dealloc(recv_srtp); }

  // TODO figure out why these cause warnings
  //if (send_ekt) { ekt_dealloc(send_ekt); }
  //if (recv_ekt) { ekt_dealloc(recv_ekt); }

  return err;
}

int main() {
  srtp_err_status_t err;

  err = srtp_init();
  if (err != srtp_err_status_ok) {
    fprintf(stderr, "Error initializing libsrtp: %d\n", err);
    return 1;
  }

  err = test_short_tag();
  if (err != srtp_err_status_ok) {
    fprintf(stderr, "Error in short tag test: %d\n", err);
    return 1;
  }

  uint8_t key_128[] = {
    0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8,
    0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
  };
  err = test_long_tag(EKT_CIPHER_AESKW_128, 16, key_128);
  if (err != srtp_err_status_ok) {
    fprintf(stderr, "Error in long tag / 128 test: %d\n", err);
    return 1;
  }

  uint8_t key_256[] = {
    0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8,
    0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
    0xef, 0xee, 0xed, 0xec, 0xeb, 0xea, 0xe9, 0xe8,
    0xe7, 0xe6, 0xe5, 0xe4, 0xe3, 0xe2, 0xe1, 0xe0,
  };
  err = test_long_tag(EKT_CIPHER_AESKW_256, 32, key_256);
  if (err != srtp_err_status_ok) {
    fprintf(stderr, "Error in long tag / 256 test: %d\n", err);
    return 1;
  }

  printf("ok\n");
  return 0;
}

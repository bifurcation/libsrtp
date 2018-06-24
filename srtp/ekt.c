/*
 * ekt.c
 *
 * Encrypted Key Transport for SRTP
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

#include "ekt.h"
#include "srtp_priv.h"

/*
 * SRTPMasterKeyLength = BYTE
 * SRTPMasterKey = 1*256BYTE
 * SSRC = 4BYTE; SSRC from RTP
 * ROC = 4BYTE ; ROC from SRTP FOR THE GIVEN SSRC
 *
 * EKTPlaintext = SRTPMasterKeyLength SRTPMasterKey SSRC ROC
 *
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * :                                                               :
 * :                        EKT Ciphertext                         :
 * :                                                               :
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |   Security Parameter Index    | Length                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |0 0 0 0 0 0 1 0|
 * +-+-+-+-+-+-+-+-+
 *
 *  0 1 2 3 4 5 6 7
 * +-+-+-+-+-+-+-+-+
 * |0 0 0 0 0 0 0 0|
 * +-+-+-+-+-+-+-+-+
 */

typedef struct {
  uint32_t ssrc;
  uint32_t roc;
} ekt_plaintext_trailer_t;

typedef struct {
  uint16_t spi;
  uint16_t len;
  uint8_t type;
} ekt_tag_trailer_t;

#define EKT_PLAINTEXT_TRAILER_SIZE 8
#define EKT_TAG_TRAILER_SIZE       5

#define EKT_TAG_TYPE_SHORT 0x00
#define EKT_TAG_TYPE_LONG  0x02

srtp_err_status_t
ekt_create(ekt_t *ekt, ekt_spi_t spi, ekt_cipher_t cipher, uint8_t *key, size_t key_size) {
  ekt_ctx_t *ctx;

  if ((ekt == NULL) || (key_size > MAX_EKT_KEY_LEN)) {
    return srtp_err_status_bad_param;
  }

  ctx = (ekt_ctx_t*) srtp_crypto_alloc(sizeof(ekt_ctx_t));
  if (ctx == NULL) {
    return srtp_err_status_alloc_fail;
  }
  *ekt = ctx;

  ctx->spi = spi;
  ctx->cipher = cipher;
  ctx->key_size = key_size;
  memcpy(ctx->key, key, key_size);
  return srtp_err_status_ok;
}

srtp_err_status_t
ekt_dealloc(ekt_t ctx) {
  srtp_crypto_free(ctx);
  return srtp_err_status_ok;
}

srtp_err_status_t
ekt_add_tag(ekt_t ekt, srtp_t session, uint8_t *pkt, int *pkt_size, ekt_flags_t flags) {
  if (flags & EKT_FLAG_SHORT_TAG) {
    pkt[*pkt_size] = EKT_TAG_TYPE_SHORT;
    *pkt_size += 1;
    return srtp_err_status_ok;
  }

  srtp_err_status_t err;

  // Read SSRC from packet
  srtp_hdr_t *hdr = (srtp_hdr_t*) pkt;
  uint32_t ssrc = ntohl(hdr->ssrc);

  // Get ROC for this SSRC from session
  uint32_t roc;
  err = srtp_get_stream_roc(session, ssrc, &roc);
  if (err != srtp_err_status_ok) {
    return err;
  }

  // Get master key for this SSRC from session
  uint8_t *master_key;
  uint8_t master_key_size;
  err = srtp_get_stream_master_key(session, ssrc, &master_key, &master_key_size);
  if (err != srtp_err_status_ok) {
    return err;
  }

  // Construct EKT plaintext in place
  int tag_start = *pkt_size;
  int tag_end = *pkt_size;

  pkt[tag_end] = master_key_size;
  tag_end += 1;

  memcpy(pkt + tag_end, master_key, master_key_size);
  tag_end += master_key_size;

  ekt_plaintext_trailer_t *pt_trailer = (ekt_plaintext_trailer_t*) (pkt + tag_end);
  pt_trailer->ssrc = htonl(ssrc);
  pt_trailer->roc = htonl(roc);
  tag_end += EKT_PLAINTEXT_TRAILER_SIZE;

  // TODO Encrypt EKT plaintext in place, according to specified cipher

  // Append tag trailer
  ekt_tag_trailer_t *tag_trailer = (ekt_tag_trailer_t*) (pkt + tag_end);
  tag_trailer->spi = htons(ekt->spi);
  tag_trailer->len = htons(tag_end - tag_start);
  tag_trailer->type = EKT_TAG_TYPE_LONG;
  tag_end += EKT_TAG_TRAILER_SIZE;

  *pkt_size = tag_end;
  return srtp_err_status_ok;
}

/*
 * Parse an EKT tag from an encrypted packet and update the session
 * as appropriate
 */
srtp_err_status_t
ekt_process_tag(ekt_t ekt, srtp_t session, uint8_t *pkt, int *pkt_size) {
  srtp_err_status_t err;

  uint8_t tag_type = pkt[*pkt_size - 1];
  if (tag_type == EKT_TAG_TYPE_SHORT) {
    *pkt_size -= 1;
    return srtp_err_status_ok;
  } else if (tag_type != EKT_TAG_TYPE_LONG) {
    // TODO-RLB: Better error status
    return srtp_err_status_bad_param;
  }

  int pkt_end = *pkt_size;

  // Parse length and SPI, check that they're sensible
  if (pkt_end < EKT_TAG_TRAILER_SIZE) {
    // TODO-RLB: Better error status
    return srtp_err_status_bad_param;
  }
  pkt_end -= EKT_TAG_TRAILER_SIZE;

  ekt_tag_trailer_t *tag_trailer = (ekt_tag_trailer_t*) (pkt + pkt_end);
  uint16_t spi = ntohs(tag_trailer->spi);
  uint16_t len = ntohs(tag_trailer->len);

  if ((spi != ekt->spi) || (len > pkt_end - sizeof(srtp_hdr_t))) {
    // TODO-RLB: Better error status
    return srtp_err_status_bad_param;
  }
  pkt_end -= len;

  // TODO: Decrypt ciphertext

  // Parse SSRC and ROC from plaintext
  uint8_t master_key_size = pkt[pkt_end];
  uint8_t *master_key = pkt + pkt_end + 1;

  ekt_plaintext_trailer_t *pt_trailer = (ekt_plaintext_trailer_t*) (master_key + master_key_size);
  uint32_t ssrc = htonl(pt_trailer->ssrc);
  uint32_t roc = htonl(pt_trailer->roc);

  // Get or create a stream for this SSRC
  srtp_stream_t stream;
  stream = srtp_get_stream(session, ssrc);
  int new_stream = 0;
  if (!stream) {
    new_stream = 1;

    /* clone the base stream for this session */
    err = srtp_stream_clone(session->stream_template, ssrc, &stream);
    if (err != srtp_err_status_ok) {
      return err;
    }
  }

  // Set ROC for this stream
  stream->pending_roc = roc;

  // Get master key for this stream
  srtp_session_keys_t *curr_keys = &stream->session_keys[0];
  uint8_t new_master_key[MAX_SRTP_KEY_LEN];
  memcpy(new_master_key, curr_keys->master_key, MAX_SRTP_KEY_LEN);

  // Overwrite the first part of the key with the EKT-provided key
  if (master_key_size > curr_keys->master_key_size) {
    // TODO-RLB: Better error status
    return srtp_err_status_bad_param;
  }
  memcpy(new_master_key, master_key, master_key_size);

  // Set master key for this SSRC on session
  srtp_master_key_t master_key_str;
  master_key_str.key = new_master_key;
  master_key_str.mki_id = NULL;
  master_key_str.mki_size = 0;
  stream->num_master_keys = 1;
  err = srtp_stream_init_keys(stream, &master_key_str, 0);
  if (err != srtp_err_status_ok) {
    srtp_stream_dealloc(stream, session->stream_template);
    return err;
  }

  // If we created a new stream, store it at the head of the
  // stream_list
  if (new_stream) {
    stream->next = session->stream_list;
    session->stream_list = stream;
  }

  *pkt_size = pkt_end;
  return srtp_err_status_ok;
}

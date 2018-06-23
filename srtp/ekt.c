#include "ekt.h"
#include "alloc.h"
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
ekt_add_tag(ekt_t ekt, srtp_t session, uint8_t *pkt, size_t *pkt_size, ekt_flags_t flags) {
  if (flags & EKT_FLAG_SHORT_TAG) {
    pkt[*pkt_size] = EKT_TAG_TYPE_SHORT;
    *pkt_size += 1;
    return srtp_err_status_ok;
  }

  srtp_err_status_t err;

  // Read SSRC from packet
  srtp_hdr_t *hdr = (srtp_hdr_t*) pkt;
  uint32_t ssrc = hdr->ssrc;

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
  size_t tag_start = *pkt_size;
  size_t tag_end = *pkt_size;

  pkt[tag_end] = master_key_size;
  tag_end += 1;

  memcpy(pkt + tag_end, master_key, master_key_size);
  tag_end += master_key_size;

  ekt_plaintext_trailer_t *pt_trailer = (ekt_plaintext_trailer_t*) (pkt + tag_end);
  pt_trailer->ssrc = htonl(ssrc);
  pt_trailer->roc = htonl(roc);
  tag_end += sizeof(ekt_plaintext_trailer_t);

  // TODO Encrypt EKT plaintext in place, according to specified cipher

  // Append tag trailer
  ekt_tag_trailer_t *tag_trailer = (ekt_tag_trailer_t*) (pkt + tag_end);
  tag_trailer->spi = htons(ekt->spi);
  tag_trailer->len = htons(tag_end - tag_start);
  tag_trailer->type = EKT_TAG_TYPE_LONG;
  tag_end += sizeof(ekt_tag_trailer_t);

  *pkt_size = tag_end;
  return srtp_err_status_ok;
}

/*
 * Parse an EKT tag from an encrypted packet and update the session
 * as appropriate
 */
srtp_err_status_t
ekt_process_tag(ekt_t ekt, srtp_t session, uint8_t *pkt, size_t *pkt_size) {
  uint8_t tag_type = pkt[*pkt_size - 1];
  if (tag_type == EKT_TAG_TYPE_SHORT) {
    *pkt_size -= 1;
    return srtp_err_status_ok;
  } else if (tag_type != EKT_TAG_TYPE_LONG) {
    // TODO-RLB: Better error status
    return srtp_err_status_bad_param;
  }

  size_t pkt_end = *pkt_size;

  // Parse length and SPI, check that they're sensible
  if (pkt_end < sizeof(ekt_tag_trailer_t)) {
    // TODO-RLB: Better error status
    return srtp_err_status_bad_param;
  }
  pkt_end -= sizeof(ekt_tag_trailer_t);

  ekt_tag_trailer_t *tag_trailer = (ekt_tag_trailer_t*) (pkt + pkt_end);
  uint16_t spi = ntohs(tag_trailer->spi);
  uint16_t len = ntohs(tag_trailer->len);

  if ((spi != ekt->spi) || (len > pkt_end - sizeof(srtp_hdr_t))) {
    // TODO-RLB: Better error status
    return srtp_err_status_bad_param;
  }
  pkt_end -= len + sizeof(ekt_tag_trailer_t);

  // TODO: Decrypt ciphertext

  // Parse SSRC and ROC from plaintext
  uint8_t master_key_size = pkt[pkt_end];
  ekt_plaintext_trailer_t *pt_trailer = (ekt_plaintext_trailer_t*) (pkt + pkt_end + 1 + master_key_size);
  uint32_t ssrc = htonl(pt_trailer->ssrc);
  uint32_t roc = htonl(pt_trailer->roc);

  // TODO: Set ROC for this SSRC on session
  // TODO: Set master key for this SSRC on session

  *pkt_size = pkt_end;
  return srtp_err_status_ok;
}

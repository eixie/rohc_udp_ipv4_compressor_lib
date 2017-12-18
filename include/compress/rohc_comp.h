#ifndef ROHC_COMPRESSOR_H
#define ROHC_COMPRESSOR_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>
#include "rohc_packet.h"
#include "rohc_buf.h"

#ifdef ROHC_DLL_EXPORT
#define ROHC_EXPORT __declspec(dllexport)
#else
#define ROHC_EXPORT
#endif

typedef enum
{
    ROHC_STATUS_OK                 = 0,
    ROHC_STATUS_NET_PARSE_FAIL     = 1,
    ROHC_STATUS_MALFORMED          = 2,
    ROHC_STATUS_NO_CONTEXT         = 3,
    ROHC_STATUS_OUTPUT_TOO_SMALL   = 4,
    ROHC_STATUS_INVALID_COMPRESSOR = 5,
    ROHC_STATUS_ERROR              = 6,
}rohc_status_t;

typedef enum
{
    ROHC_LARGE_CID,
    ROHC_SMALL_CID,
}rohc_cid_type_t;

#define ROHC_STATIC_CONTEXT_BUF_LEN  (16) //static chain length 14Bytes, extra 2 bytes alignment
#define ROHC_DYNAMIC_CONTEXT_BUF_LEN (12) //Dynamic chain 9Bytes, extra 3 bytes for alignment

typedef struct
{
    uint8_t  cid;
    uint8_t  static_context_size;
    uint8_t  dynamic_context_size;
    uint8_t  static_context_buf[ROHC_STATIC_CONTEXT_BUF_LEN];
    uint8_t  dynamic_context_buf[ROHC_DYNAMIC_CONTEXT_BUF_LEN];
    uint16_t SN;
    uint16_t ip_id;
    rohc_cid_type_t cid_type;
    rohc_packet_t   packet_type;
}rohc_comp_packet_info_t;

typedef uint8_t rohc_comp_index_t;

ROHC_EXPORT rohc_status_t rohc_compress(const rohc_comp_index_t comp_idx,
                                        rohc_buf_t *const rohc_pkt,
                                        rohc_comp_packet_info_t *const rohc_pkt_info,
                                        const rohc_buf_t uncomp_data);

ROHC_EXPORT rohc_comp_index_t rohc_allocate_compressor(const rohc_cid_type_t cid_type,
                                                       const uint8_t max_cid,
                                                       const uint32_t wlsb_sn_window_capacity,
                                                       const uint32_t wlsb_ip_id_window_capacity,
                                                       const uint32_t periodic_ir_timeout,
                                                       const uint32_t periodic_fo_timeout);

ROHC_EXPORT  void rohc_release_compressor(const rohc_comp_index_t comp_idx);

#undef ROHC_EXPORT

#ifdef __cplusplus
}
#endif

#endif /* ROHC_COMPRESSOR_H */


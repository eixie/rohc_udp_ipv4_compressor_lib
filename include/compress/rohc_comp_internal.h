#ifndef ROHC_COMPRESS_INTERNAL_H
#define ROHC_COMPRESS_INTERNAL_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>
#include <stdbool.h>
#include "rohc_comp.h"
#include "rohc_comp_udp_ipv4.h"
#include "rohc_comp_sm.h"
#include "rohc_buf.h"

#define ROHC_LARGE_CID_MAX  255U
#define ROHC_SMALL_CID_MAX  15U

#define DFL_PERIODIC_IR_DOWN_TRANS_TIMEOUT (500U)
#define DFL_PERIODIC_FO_DOWN_TRANS_TIMEOUT (100U)
#define DEFAULT_CONTEXT_NUM_PER_COMPRESSOR (32U) //by default, compressor support 32 streams.
#define MAX_CONTEXT_NUM_PER_COMPRESSOR (128U) // each compressor support at most 128 streams

typedef enum
{
	ROHC_PROFILE_UDP= 0x0002,
	ROHC_PROFILE_MAX,
}alp_rohc_profile_t;

typedef struct
{
    uint8_t max_cid;
    rohc_cid_type_t cid_type;
    uint32_t wlsb_sn_win_capacity;
    uint32_t wlsb_ip_id_win_capacity;
    uint32_t perodic_ir_timeout_cnt;
    uint32_t perodic_fo_timeout_cnt;
}rohc_comp_config_t;

typedef struct
{
    bool in_use;
    uint8_t cid;
    size_t last_use_time;
    rohc_packet_t packet_type;
    rohc_comp_config_t *cfg;
    udp_ipv4_comp_context_t udp_ip_ctx;
    rohc_comp_state_machine_t sm;
}rohc_comp_context_t;

typedef struct
{
    uint16_t total_num;
    rohc_comp_context_t* ctx_array;
}rohc_comp_context_managment_t;

typedef struct
{
    bool in_use;
    uint8_t next_avail_cid;
    rohc_comp_config_t cfg;
    rohc_comp_context_managment_t ctx_mm;
}rohc_compressor_t;

extern bool encode_rohc_packet_header(rohc_comp_context_t *const ctx, rohc_buf_t *const header_buf);
extern rohc_status_t rohc_comp_internal(rohc_comp_context_t *const ctx,
                                        rohc_buf_t *const comp_pkt,
                                        const network_packet_t *const net_pkt);

extern void rohc_comp_context_init(rohc_comp_context_t *const ctx,
                                   const uint8_t cid,
                                   rohc_comp_config_t *const cfg);

extern void rohc_comp_context_deinit(rohc_comp_context_t *const ctx);

extern bool rohc_comp_get_last_packet_info(const rohc_comp_context_t *const ctx,
                                           rohc_comp_packet_info_t *const pkt_info);

#endif


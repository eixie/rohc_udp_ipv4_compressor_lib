#ifndef ROHC_UDP_IPV4_COMP_H
#define ROHC_UDP_IPV4_COMP_H

#include <stdint.h>
#include <stdbool.h>
#include "rohc_comp_wlsb.h"
#include "rohc_packet.h"
#include "rohc_crc.h"
#include "network_packet.h"
#include "rohc_buf.h"

#define UDP_IP_COMPRESS_MAX_SN (0xFFFFU)

typedef enum
{
    DYN_CHG_MASK_TOS      = 0x01,
    DYN_CHG_MASK_TTL      = 0x02,
    DYN_CHG_MASK_DF       = 0x04,
    DYN_CHG_MASK_RND      = 0x08,
    DYN_CHG_MASK_NBO      = 0x10,
    DYN_CHG_MASK_SID      = 0x20,
    DYN_CHG_MASK_CSUM     = 0x40,
    DYN_CHG_MASK_ERROR    = 0x80,
}udp_ipv4_dynamic_change_mask_t;

typedef struct
{
    bool valid;
    bool df;
    bool rnd;
    bool nbo;
    uint8_t tos;
    uint8_t ttl;
    uint16_t SN;
    uint16_t ip_id;
    uint16_t udp_csum;
    uint16_t ip_csum;
    uint16_t frag_info;
    uint16_t ip_len;
    uint16_t udp_len;
}udp_ipv4_dynamic_part_t;

typedef struct
{
    uint32_t src_addr;
    uint32_t dst_addr;
    uint16_t src_port;
    uint16_t dst_port;
}udp_ipv4_static_part_t;

typedef struct
{
    size_t c_tos;
    size_t c_ttl;
    size_t c_df;
    size_t c_rnd;
    size_t c_nbo;
    size_t c_udp_csum;
}context_remain_no_change_counter_t;

typedef struct
{
    size_t stable_cnt_tos;
    size_t stable_cnt_ttl;
    size_t stable_cnt_df;
    size_t stable_cnt_rnd;
    size_t stable_cnt_nbo;
    size_t stable_cnt_udp_csum;
}context_stable_threshold_t;

typedef struct
{
    uint16_t orig_value;
    uint8_t max_k_lsb;
    wlsb_t *wlsb;
}wlsb_endoder_t;

typedef struct udp_ipv4_comp_context
{
    bool first_packet;
    bool dynamic_stable;

    udp_ipv4_static_part_t  s_part;

    udp_ipv4_dynamic_part_t last_d;
    udp_ipv4_dynamic_part_t cur_d;

    context_remain_no_change_counter_t dyn_no_chg_counter;
    context_stable_threshold_t thresh;
    wlsb_endoder_t sn_enc;
    wlsb_endoder_t ip_id_enc;
}udp_ipv4_comp_context_t;

extern bool udp_ipv4_code_UO_x_random_fields(const udp_ipv4_comp_context_t *const ctx,
                                             rohc_buf_t *const uo_x_hdr);

extern bool udp_ipv4_code_dynamic(const udp_ipv4_comp_context_t *const ctx,
	                              rohc_buf_t *const dyn_chain_buf);

extern  bool udp_ipv4_code_static(const udp_ipv4_comp_context_t *const udp_ip_ctx,
                                  rohc_buf_t *const static_chain_buf);

extern uint8_t udp_ipv4_calculate_UO_x_crc(const udp_ipv4_comp_context_t *const ctx,
                                           const rohc_crc_type_t crc_type,
                                           const uint8_t init_val);

extern bool udp_ipv4_udpate_context(udp_ipv4_comp_context_t *const ctx,
                                    const network_packet_t *const net_pkt);

extern void udp_ipv4_init_context(udp_ipv4_comp_context_t *const ctx,
                                  const uint16_t sn_win_capacity,
                                  const uint16_t ip_id_win_capacity);

extern void udp_ipv4_deinit_context(udp_ipv4_comp_context_t *const ctx);

extern bool udp_ipv4_static_context_match(udp_ipv4_comp_context_t *const ctx,
                                          uint32_t src_addr,
                                          uint32_t dst_addr,
                                          uint16_t src_port,
                                          uint16_t dst_port);

extern uint16_t udp_ipv4_get_SN(const udp_ipv4_comp_context_t *const ctx);

extern uint16_t udp_ipv4_get_IP_ID_minus_SN(const udp_ipv4_comp_context_t *const ctx);
extern uint16_t udp_ipv4_get_IP_ID(const udp_ipv4_comp_context_t *const ctx);

extern rohc_packet_t udp_ipv4_comp_decide_fo_packet(const void *const udp_ip_ctx);
extern rohc_packet_t udp_ipv4_comp_decide_so_packet(const void *const udp_ip_ctx);

#endif /* ROHC_UDP_IPV4_COMP_H */

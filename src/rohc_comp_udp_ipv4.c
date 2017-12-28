#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <string.h>

#include "rohc_utils.h"
#include "rohc_buf.h"
#include "rohc_comp_udp_ipv4.h"
#include "ip_v4.h"
#include "rohc_crc.h"
#include "rohc_log.h"
#include "rohc_packet.h"

static bool is_random_ipv4_id(const uint16_t old_id, const uint16_t new_id)
{
    const uint16_t MAX_IP_ID_DELTA = 10;

    if (new_id >= old_id)
    {
        if (new_id - old_id < MAX_IP_ID_DELTA)
        {
            return false;
        }
    }
    else
    {
        //wrap around happens from old to new
        if ((old_id > (IP_MAX_IP_ID - MAX_IP_ID_DELTA)) && (new_id < MAX_IP_ID_DELTA))
        {
            if (old_id + MAX_IP_ID_DELTA < new_id)
            {
                return false;
            }
        }
    }

    return true;
}

static inline bool is_udp_checksump_behavior_change(const uint16_t checksum1, const uint16_t checksum2)
{
    return (((checksum1 != 0) && (checksum2 == 0)) ||
            ((checksum1 == 0) && (checksum2 != 0)));
}


static inline bool is_dynamic_stable(udp_ipv4_comp_context_t *const ctx)
{
    if ((ctx != NULL) &&
        (ctx->dyn_no_chg_counter.c_tos >= ctx->thresh.stable_cnt_tos) &&
        (ctx->dyn_no_chg_counter.c_ttl >= ctx->thresh.stable_cnt_ttl) &&
        (ctx->dyn_no_chg_counter.c_rnd >= ctx->thresh.stable_cnt_rnd) &&
        (ctx->dyn_no_chg_counter.c_nbo >= ctx->thresh.stable_cnt_nbo) &&
        (ctx->dyn_no_chg_counter.c_df  >= ctx->thresh.stable_cnt_df) &&
        (ctx->dyn_no_chg_counter.c_udp_csum >= ctx->thresh.stable_cnt_udp_csum))
    {
        return true;
    }

    return false;
}

static bool ipv4_id_is_static(udp_ipv4_comp_context_t *const ctx,
                              const uint16_t old_id,
                              const uint16_t new_id)
{
    ROHC_NULL_PTR_CHECK_RET(ctx, false);

    if (old_id == new_id)
    {
        if (ctx->dyn_no_chg_counter.c_sid >= ctx->thresh.stable_cnt_sid)
        {
            return true;
        }
        else
        {
            ctx->dyn_no_chg_counter.c_sid++;
        }
    }
    else if (ctx->dyn_no_chg_counter.c_sid != 0)
    {
        ctx->dyn_no_chg_counter.c_sid = 0;
    }

    return false;
}

static void udp_ipv4_detect_id_jump_behavior(udp_ipv4_comp_context_t *const ctx)
{
    ROHC_NULL_PTR_CHECK(ctx);

    if (ctx->last_d.valid && ctx->cur_d.valid)
    {
        uint16_t old_id = rohc_ntoh16(ctx->last_d.ip_id);
        uint16_t new_id = rohc_ntoh16(ctx->cur_d.ip_id);

        ctx->cur_d.sid = ipv4_id_is_static(ctx, old_id, new_id);

        if (ctx->cur_d.sid)
        {
            ctx->cur_d.rnd = false;
            ctx->cur_d.nbo = true;
            ROHC_LOG_DEBUG("static id case id =%d\n", new_id);
        }
        else if (!is_random_ipv4_id(old_id, new_id))
        {
            ctx->cur_d.rnd = false;
            ctx->cur_d.nbo = true;
        }
        else
        {
            /* change byte ordering and check behaviour again */
            old_id = ROHC_ENDIAN_SWAP16(old_id);
            new_id = ROHC_ENDIAN_SWAP16(new_id);

            ctx->cur_d.sid = ipv4_id_is_static(ctx, old_id, new_id);

            if (ctx->cur_d.sid)
            {
                ROHC_LOG_DEBUG("nbo static id case id =%d\n", new_id);
                ctx->cur_d.rnd = false;
                ctx->cur_d.nbo = false;
            }
            else if (!is_random_ipv4_id(old_id, new_id))
            {
                ctx->cur_d.rnd = false;
                ctx->cur_d.nbo = false;
            }
            else
            {
                ctx->cur_d.rnd = true;
                ctx->cur_d.nbo = true;
            }
        }
    }
    else
    {   //default behavior of IP_ID
        ctx->cur_d.rnd = false;
        ctx->cur_d.nbo = true;
    }
}


static void udp_ipv4_update_dynamic_no_change_counters(udp_ipv4_comp_context_t *const ctx)
{
    bool sid_change = false;

    ROHC_NULL_PTR_CHECK(ctx);

    if (ctx->cur_d.valid && ctx->last_d.valid)
    {
        if (ctx->last_d.tos != ctx->cur_d.tos)
        {
            ctx->dyn_no_chg_counter.c_tos = 0;
        }
        else if (ctx->dyn_no_chg_counter.c_tos < ctx->thresh.stable_cnt_tos)
        {
            ctx->dyn_no_chg_counter.c_tos++;
            ROHC_LOG_TRACE("c_tos %d, stable cnt %d\n", ctx->dyn_no_chg_counter.c_tos,
                           ctx->thresh.stable_cnt_tos);
        }

        if (ctx->last_d.ttl != ctx->cur_d.ttl)
        {
            ctx->dyn_no_chg_counter.c_ttl = 0;
        }
        else if (ctx->dyn_no_chg_counter.c_ttl < ctx->thresh.stable_cnt_ttl)
        {
            ctx->dyn_no_chg_counter.c_ttl++;

            ROHC_LOG_TRACE("c_ttl %d, stable cnt %d\n", ctx->dyn_no_chg_counter.c_ttl,
                           ctx->thresh.stable_cnt_ttl);
        }

        if (ctx->last_d.df != ctx->cur_d.df)
        {
            ctx->dyn_no_chg_counter.c_df = 0;
        }
        else if (ctx->dyn_no_chg_counter.c_df < ctx->thresh.stable_cnt_df)
        {
            ctx->dyn_no_chg_counter.c_df++;
            ROHC_LOG_TRACE("c_df %d, stable cnt %d\n", ctx->dyn_no_chg_counter.c_df,
                           ctx->thresh.stable_cnt_df);
        }

        if (ctx->last_d.nbo != ctx->cur_d.nbo)
        {
            ctx->dyn_no_chg_counter.c_nbo = 0;
        }
        else if (ctx->dyn_no_chg_counter.c_nbo <= ctx->thresh.stable_cnt_nbo)
        {
            ctx->dyn_no_chg_counter.c_nbo++;
            ROHC_LOG_TRACE("c_nbo %d, stable cnt %d\n", ctx->dyn_no_chg_counter.c_nbo,
                           ctx->thresh.stable_cnt_nbo);
        }

        if (ctx->last_d.rnd != ctx->cur_d.rnd)
        {
            ctx->dyn_no_chg_counter.c_rnd = 0;
        }
        else if (ctx->dyn_no_chg_counter.c_rnd <= ctx->thresh.stable_cnt_rnd)
        {
            ctx->dyn_no_chg_counter.c_rnd++;
            ROHC_LOG_TRACE("c_rnd %d, stable cnt %d\n", ctx->dyn_no_chg_counter.c_rnd,
                           ctx->thresh.stable_cnt_rnd);
        }

        if (is_udp_checksump_behavior_change(ctx->cur_d.udp_csum, ctx->last_d.udp_csum))
        {
            ctx->dyn_no_chg_counter.c_udp_csum = 0;
        }
        else if (ctx->dyn_no_chg_counter.c_udp_csum <= ctx->thresh.stable_cnt_udp_csum)
        {
            ctx->dyn_no_chg_counter.c_udp_csum++;
            ROHC_LOG_TRACE("c_udp_csum %d, stable cnt %d\n", ctx->dyn_no_chg_counter.c_udp_csum,
                           ctx->thresh.stable_cnt_udp_csum);
        }

        if (ctx->cur_d.sid != ctx->last_d.sid)
        {
            sid_change = true;
            ROHC_LOG_TRACE("SID field change %d->%d, update dynamic\n",
                           ctx->last_d.sid, ctx->cur_d.sid);
        }
    }
    else if (ctx->cur_d.valid)
    {
        memset(&ctx->dyn_no_chg_counter, 0, sizeof(context_remain_no_change_counter_t));
    }
    else
    {
        ROHC_LOG_ERROR("%s No valid dynamic context\n", __FUNCTION__);
        assert(0);
    }

    if (sid_change)
    {
        ctx->dynamic_stable = false;
    }
    else
    {
        ctx->dynamic_stable = is_dynamic_stable(ctx);
    }
}

extern bool udp_ipv4_udpate_context(udp_ipv4_comp_context_t *const ctx,
                                    const network_packet_t *const net_pkt)
{
    ROHC_NULL_PTR_CHECK_RET(ctx, false);
    ROHC_NULL_PTR_CHECK_RET(net_pkt, false);

    if (ctx->first_packet)
    {
        ctx->first_packet = false;

        ctx->s_part.src_addr = net_pkt->ip_hdr.src_addr;
        ctx->s_part.dst_addr = net_pkt->ip_hdr.dst_addr;
        ctx->s_part.src_port = net_pkt->udp_hdr.src;
        ctx->s_part.dst_port = net_pkt->udp_hdr.dest;
        ROHC_LOG_DEBUG("set static ctx:0x%02x:%02x:%02x:%02x",
                       ctx->s_part.src_addr,
                       ctx->s_part.dst_addr,
                       ctx->s_part.src_port,
                       ctx->s_part.dst_port);
    }

    ctx->last_d = ctx->cur_d;

    ctx->cur_d.tos       = net_pkt->ip_hdr.tos;
    ctx->cur_d.ip_len    = net_pkt->ip_hdr.tot_len;
    ctx->cur_d.ip_id     = net_pkt->ip_hdr.id;
    ctx->cur_d.frag_info = net_pkt->ip_hdr.frag_info;
    ctx->cur_d.ttl       = net_pkt->ip_hdr.ttl;
    ctx->cur_d.ip_csum   = net_pkt->ip_hdr.csum;

    ctx->cur_d.udp_csum  = net_pkt->udp_hdr.csum;
    ctx->cur_d.udp_len   = net_pkt->udp_hdr.len;
    ctx->cur_d.valid     = true;

    udp_ipv4_detect_id_jump_behavior(ctx);

    udp_ipv4_update_dynamic_no_change_counters(ctx);

    ++ctx->cur_d.SN;

    ctx->sn_enc.orig_value = ctx->cur_d.SN;
    ctx->sn_enc.max_k_lsb = wlsb_g_max_k(ctx->sn_enc.wlsb,
                                         ctx->sn_enc.orig_value);
    wlsb_add_ref_to_window(ctx->sn_enc.wlsb,
                           ctx->sn_enc.orig_value);

    ctx->ip_id_enc.orig_value = (rohc_ntoh16(ctx->cur_d.ip_id) - ctx->cur_d.SN);

    ctx->ip_id_enc.max_k_lsb = wlsb_g_max_k(ctx->ip_id_enc.wlsb,
                                            ctx->ip_id_enc.orig_value);
    wlsb_add_ref_to_window(ctx->ip_id_enc.wlsb,
                           ctx->ip_id_enc.orig_value);

    ROHC_LOG_TRACE("update context SN %d, klsb %d bits, ip_id %d, ofst klsb %d bits\n",
                   ctx->cur_d.SN, ctx->sn_enc.max_k_lsb,
                   rohc_ntoh16(ctx->cur_d.ip_id), ctx->ip_id_enc.max_k_lsb);

    return true;
}

extern uint8_t udp_ipv4_calculate_UO_x_crc(const udp_ipv4_comp_context_t *const ctx,
                                           const rohc_crc_type_t crc_type,
                                           const uint8_t init_val)
{
    ROHC_NULL_PTR_CHECK_RET(ctx, 0);
    uint8_t crc = init_val;
    uint8_t crc_static[18];
    uint8_t crc_dynamic[10];

    //CRC_STATIC of IP
    crc_static[0] = IPV4_HEADER_VER_HL;
    crc_static[1] = ctx->cur_d.tos;
    memcpy(crc_static + 2,  (uint8_t *)(&ctx->cur_d.frag_info), 2);
    crc_static[4] = ctx->cur_d.ttl;
    crc_static[5] = IP_PROTOCOL_UDP;
    memcpy(crc_static + 6,  (uint8_t *)(&ctx->s_part.src_addr), 4);
    memcpy(crc_static + 10, (uint8_t *)(&ctx->s_part.dst_addr), 4);
    //CRC_STATIC of UDP
    memcpy(crc_static + 14, (uint8_t *)(&ctx->s_part.src_port), 2);
    memcpy(crc_static + 16, (uint8_t *)(&ctx->s_part.dst_port), 2);

    //CRC_DYNAMIC of IP
    memcpy(crc_dynamic,     (uint8_t *)(&ctx->cur_d.ip_len),   2);
    memcpy(crc_dynamic + 2, (uint8_t *)(&ctx->cur_d.ip_id),    2);
    memcpy(crc_dynamic + 4, (uint8_t *)(&ctx->cur_d.ip_csum),  2);
    //CRC_DYNAMIC of UDP
    memcpy(crc_dynamic + 6, (uint8_t *)(&ctx->cur_d.udp_len),  2);
    memcpy(crc_dynamic + 8, (uint8_t *)(&ctx->cur_d.udp_csum), 2);

    /* bytes 1-2 (Version, Header length, TOS) */
    crc = rohc_cal_crc(crc_type, crc_static, 18, crc);
    crc = rohc_cal_crc(crc_type, crc_dynamic, 10, crc);

    return crc;
}

/* udp-ipv4 static chain (14Bytes)
  +---+---+---+---+---+---+---+---+
  |  Version = 4  |       0       |
  +---+---+---+---+---+---+---+---+
  |           Protocol            |
  +---+---+---+---+---+---+---+---+
  /        Source Address         /   4 octets
  +---+---+---+---+---+---+---+---+
  /      Destination Address      /   4 octets
  +---+---+---+---+---+---+---+---+
  /          Source Port          /   2 octets
  +---+---+---+---+---+---+---+---+
  /       Destination Port        /   2 octets
  +---+---+---+---+---+---+---+---+
 */
extern  bool udp_ipv4_code_static(const udp_ipv4_comp_context_t *const ctx,
                                  rohc_buf_t *const static_chain_buf)
{
#define UDP_IP_STATIC_CHAIN_LENGTH  (14U)

    uint8_t buf[UDP_IP_STATIC_CHAIN_LENGTH];

    ROHC_NULL_PTR_CHECK_RET(ctx, false);
    if (!rohc_buf_size_check(*static_chain_buf, UDP_IP_STATIC_CHAIN_LENGTH))
    {
        return false;
    }

    buf[0] = 0x40;
    buf[1] = IP_PROTOCOL_UDP;
    memcpy(&buf[2],  &ctx->s_part.src_addr, 4);
    memcpy(&buf[6],  &ctx->s_part.dst_addr, 4);
    memcpy(&buf[10], &ctx->s_part.src_port, 2);
    memcpy(&buf[12], &ctx->s_part.dst_port, 2);
    rohc_buf_append(static_chain_buf, buf, UDP_IP_STATIC_CHAIN_LENGTH);

    return true;
}

/* udp-ipv4 dynamic chain (9 Bytes)
 +---+---+---+---+---+---+---+---+
 |        Type of Service        |
+---+---+---+---+---+---+---+---+
 |         Time to Live          |
 +---+---+---+---+---+---+---+---+
 /        Identification         /   2 octets, sent verbatim
 +---+---+---+---+---+---+---+---+
 | DF|RND|NBO|SID|       0       |
 +---+---+---+---+---+---+---+---+
 /           Checksum            /   2 octets
 +---+---+---+---+---+---+---+---+
 /           UDP SN              /   2 octets
 +---+---+---+---+---+---+---+---+
*/

extern bool udp_ipv4_code_dynamic(const udp_ipv4_comp_context_t *const ctx,
                                  rohc_buf_t *const dyn_chain_buf)
{
#define UDP_IP_DYNAMIC_CHAIN_LENGTH  9U

    const udp_ipv4_dynamic_part_t *dyn;
    uint8_t buf[UDP_IP_DYNAMIC_CHAIN_LENGTH];
    uint8_t df_rnd_nbo_byte = 0x0;
    uint16_t ip_id;

    ROHC_NULL_PTR_CHECK_RET(ctx, false);
    if (!rohc_buf_size_check(*dyn_chain_buf, UDP_IP_DYNAMIC_CHAIN_LENGTH))
    {
        return false;
    }

    dyn = &ctx->cur_d;

    buf[0] = dyn->tos;
    buf[1] = dyn->ttl;

    ip_id = dyn->ip_id;

    if (!dyn->nbo)
    {
        ip_id = ROHC_ENDIAN_SWAP16(ip_id);
    }

    memcpy(&buf[2], &ip_id, 2);

    if (dyn->df)
    {
        df_rnd_nbo_byte = 0x80;
    }

    if (dyn->rnd)
    {
        df_rnd_nbo_byte |= 0x40;
    }

    if (dyn->nbo)
    {
        df_rnd_nbo_byte |= 0x20;
    }

    if (dyn->sid)
    {
        df_rnd_nbo_byte |= 0x10;
    }

    buf[4] = df_rnd_nbo_byte;

    memcpy(&buf[5], &ctx->cur_d.udp_csum, 2);
    memcpy(&buf[7], &ctx->cur_d.SN, 2);

    rohc_buf_append(dyn_chain_buf, buf, UDP_IP_DYNAMIC_CHAIN_LENGTH);

    return true;
}

extern bool udp_ipv4_code_UO_x_random_fields(const udp_ipv4_comp_context_t *const ctx,
                                             rohc_buf_t *const uo_x_hdr)
{
    uint8_t k = 0;
    uint8_t buf[4];

    if (!rohc_buf_size_check(*uo_x_hdr, 4))
    {
        return false;
    }

    if (ctx->cur_d.rnd)
    {
        memcpy(buf, (uint8_t *)(&ctx->cur_d.ip_id), 2);
        ROHC_LOG_DEBUG("set rand IP-ID = 0x%04x\n", ctx->cur_d.ip_id);
        k += 2;
    }

    if (ctx->cur_d.udp_csum != 0)
    {
        ROHC_LOG_DEBUG("set UDP checksum = 0x%04x\n", ctx->cur_d.udp_csum);
        memcpy(&buf + k, (uint8_t *)(&ctx->cur_d.udp_csum), 2);
        k += 2;
    }

    rohc_buf_append(uo_x_hdr, buf, k);

    return true;
}

extern rohc_packet_t udp_ipv4_comp_decide_fo_packet(const void *const udp_ip_ctx)
{
    const udp_ipv4_comp_context_t *const ctx = (const udp_ipv4_comp_context_t *)udp_ip_ctx;
    rohc_packet_t pkt_type;

    ROHC_NULL_PTR_CHECK_RET(udp_ip_ctx, ROHC_PACKET_UNKNOWN);

    if ((ctx->sn_enc.max_k_lsb <= UOR_2_SN_BITS) &&
        ((ctx->ip_id_enc.max_k_lsb == 0) || ctx->cur_d.sid) &&
        (ctx->dynamic_stable))
    {
        pkt_type = ROHC_PACKET_UOR_2;
    }
    else
    {
        pkt_type = ROHC_PACKET_IR_DYN;
    }

    ROHC_LOG_DEBUG("decide fo pkt %s, sn klsb %d, ipid klsb %d, sid %d dynamic_stable %d\n",
                   rohc_get_packet_type_str(pkt_type),
                   ctx->sn_enc.max_k_lsb,
                   ctx->ip_id_enc.max_k_lsb,
                   ctx->cur_d.sid,
                   ctx->dynamic_stable);

    return pkt_type;
}

extern rohc_packet_t udp_ipv4_comp_decide_so_packet(const void *const udp_ip_ctx)
{
    rohc_packet_t pkt_type;

    const udp_ipv4_comp_context_t *const ctx = (const udp_ipv4_comp_context_t *)udp_ip_ctx;

    ROHC_NULL_PTR_CHECK_RET(udp_ip_ctx, ROHC_PACKET_UNKNOWN);

    if (!ctx->dynamic_stable)
    {
        pkt_type = ROHC_PACKET_IR_DYN;
    }
    else if ((ctx->ip_id_enc.max_k_lsb != 0) && (!ctx->cur_d.sid))
    {
        if ((ctx->ip_id_enc.max_k_lsb <= UO_1_IP_ID_BITS) && (ctx->sn_enc.max_k_lsb <= UO_1_SN_BITS))
        {
            pkt_type = ROHC_PACKET_UO_1;
        }
        else
        {
            pkt_type = ROHC_PACKET_IR_DYN;
        }
    }
    else if (ctx->sn_enc.max_k_lsb <= UO_0_SN_BITS)
    {
        pkt_type = ROHC_PACKET_UO_0;
    }
    else if (ctx->sn_enc.max_k_lsb <= UOR_2_SN_BITS)
    {
        pkt_type = ROHC_PACKET_UOR_2;
    }
    else
    {
        pkt_type = ROHC_PACKET_IR_DYN;
    }

    ROHC_LOG_DEBUG("decide so pkt %s, sn klsb %d, ipid klsb %d, sid %d, dynamic_stable %d\n",
                   rohc_get_packet_type_str(pkt_type),
                   ctx->sn_enc.max_k_lsb,
                   ctx->ip_id_enc.max_k_lsb,
                   ctx->cur_d.sid,
                   ctx->dynamic_stable);

    return pkt_type;
}

extern void udp_ipv4_init_context(udp_ipv4_comp_context_t *const ctx,
                                  const uint16_t sn_win_capacity,
                                  const uint16_t ip_id_win_capacity)
{

	ROHC_NULL_PTR_CHECK(ctx);
    memset(ctx, 0, sizeof(udp_ipv4_comp_context_t));

    ctx->first_packet = true;

    ctx->thresh.stable_cnt_tos = UDP_IP_DYNAMIC_NO_CHANGE_STABLE_THREASHOLD;
    ctx->thresh.stable_cnt_ttl = UDP_IP_DYNAMIC_NO_CHANGE_STABLE_THREASHOLD;
    ctx->thresh.stable_cnt_df = UDP_IP_DYNAMIC_NO_CHANGE_STABLE_THREASHOLD;
    ctx->thresh.stable_cnt_rnd = UDP_IP_DYNAMIC_NO_CHANGE_STABLE_THREASHOLD;
    ctx->thresh.stable_cnt_nbo = UDP_IP_DYNAMIC_NO_CHANGE_STABLE_THREASHOLD;
    ctx->thresh.stable_cnt_udp_csum = UDP_IP_DYNAMIC_NO_CHANGE_STABLE_THREASHOLD;

    if (ctx->sn_enc.wlsb != NULL)
    {
        wlsb_deinit(ctx->sn_enc.wlsb);
        ROHC_LOG_DEBUG("%s deinit old sn wlsb\n", __FUNCTION__);
    }

    ctx->sn_enc.wlsb = wlsb_init(sn_win_capacity, ROHC_LSB_SHIFT_SN);

    if (ctx->sn_enc.wlsb == NULL)
    {
        ROHC_LOG_DEBUG("%s Init SN wlsb fail\n", __FUNCTION__);
        assert(0);
    }

    if (ctx->ip_id_enc.wlsb != NULL)
    {
        wlsb_deinit(ctx->ip_id_enc.wlsb);
        ROHC_LOG_DEBUG("%s deinit old ip_id wlsb\n", __FUNCTION__);
    }

    ctx->ip_id_enc.wlsb = wlsb_init(ip_id_win_capacity, ROHC_LSB_SHIFT_IP_ID);

    if (ctx->ip_id_enc.wlsb == NULL)
    {
        ROHC_LOG_DEBUG("%s Init ipid wlsb fail\n", __FUNCTION__);
        assert(0);
    }

    ROHC_LOG_INFO("Init udp ipv4 context success\n");
}

extern void udp_ipv4_deinit_context(udp_ipv4_comp_context_t *const ctx)
{
    if (ctx != NULL)
    {
        if (ctx->sn_enc.wlsb != NULL)
        {
            wlsb_deinit(ctx->sn_enc.wlsb);
            ROHC_LOG_DEBUG("%s deinit sn wlsb\n", __FUNCTION__);
        }

        if (ctx->ip_id_enc.wlsb != NULL)
        {
            wlsb_deinit(ctx->ip_id_enc.wlsb);
            ROHC_LOG_DEBUG("%s deinit ip_id wlsb\n", __FUNCTION__);
        }
    }
}

extern bool udp_ipv4_static_context_match(udp_ipv4_comp_context_t *const ctx,
                                           uint32_t src_addr,
                                           uint32_t dst_addr,
                                           uint16_t src_port,
                                           uint16_t dst_port)
{
    assert(ctx != NULL);
    if((ctx->s_part.src_addr == src_addr) &&
       (ctx->s_part.dst_addr == dst_addr) &&
       (ctx->s_part.src_port == src_port) &&
       (ctx->s_part.dst_port == dst_port))
    {
        return true;
    }

    return false;
}

extern uint16_t udp_ipv4_get_SN(const udp_ipv4_comp_context_t *const ctx)
{
    assert(ctx != NULL);

    return ctx->cur_d.SN;
}

extern uint16_t udp_ipv4_get_IP_ID_minus_SN(const udp_ipv4_comp_context_t *const ctx)
{
    assert(ctx != NULL);

    return (ctx->cur_d.ip_id - ctx->cur_d.SN);
}

extern uint16_t udp_ipv4_get_IP_ID(const udp_ipv4_comp_context_t *const ctx)
{
    assert(ctx != NULL);
    return ctx->cur_d.ip_id;
}

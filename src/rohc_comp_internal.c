#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "rohc_comp.h"
#include "rohc_comp_internal.h"
#include "rohc_log.h"
#include "rohc_buf.h"
#include "rohc_utils.h"

//64 bytes is safe to cover IR/IR-DYN/UO_x packet type rohc headers
static const uint16_t MAXIMUM_ROHC_HEADER_SIZE = 64;

/*
 *   0   1   2   3   4   5   6   7
 *  --- --- --- --- --- --- --- ---
 * :         Add-CID octet         : if for small CIDs and CID != 0
 * +---+---+---+---+---+---+---+---+
 * |     non_cid_1st_octet         |
 * +---+---+---+---+---+---+---+---+
 * :                               :
 * /     0-1 octets of CID info    / 0-1 octets if for large CIDs
 * :                               :
 * +---+---+---+---+---+---+---+---+
 */
static bool fill_cid_and_first_octet(rohc_buf_t *const rohc_hdr,
                                     const rohc_cid_type_t cid_type,
                                     const uint8_t first_octect,
                                     const uint8_t cid)
{
    uint8_t len = 0;
    uint8_t buf[2];

    ROHC_NULL_PTR_CHECK_RET(rohc_hdr, false);

    if (!rohc_buf_size_check(*rohc_hdr, 2))
    {
        return false;
    }

    if (cid_type == ROHC_SMALL_CID)
    {
        if (cid > 0)
        {
            assert(cid <= ROHC_SMALL_CID_MAX);
            buf[0] = 0xE0 | (cid & 0x0f);
            buf[1] = first_octect;
            len = 2;
        }
        else
        {
            buf[0] = first_octect;
            len = 1;
        }
    }
    else if (cid_type == ROHC_LARGE_CID)
    {
        buf[0] = first_octect;
        buf[1] = cid;
        len = 2;
    }
    else
    {
        ROHC_LOG_ERROR("%s ALP only support 1 byte cid and not support svdl\n", __FUNCTION__);
        assert(0);
        return false;
    }

    if (len > 0)
    {
        rohc_buf_append(rohc_hdr, buf, len);
        return true;
    }

    return false;
}

static bool encode_IR_header(rohc_comp_context_t *const ctx, rohc_buf_t *const IR_hdr)
{
    uint8_t *crc;
    uint8_t f_octect = ROHC_IR_PREAMBLE_CODE;

    ROHC_NULL_PTR_CHECK_RET(ctx, false);
    ROHC_NULL_PTR_CHECK_RET(IR_hdr, false);

    if (!rohc_buf_size_check(*IR_hdr, MAXIMUM_ROHC_HEADER_SIZE))
    {
        return false;
    }

    if (!fill_cid_and_first_octet(IR_hdr, ctx->cfg->cid_type, f_octect, ctx->cid))
    {
        ROHC_LOG_ERROR("invalid cid and 1st byte fill\n");
        assert(0);
        return false;
    }

    rohc_buf_append_byte(IR_hdr, ROHC_PROFILE_UDP);
    crc = rohc_buf_append_byte(IR_hdr, 0); // init CRC = 0

    assert(crc != NULL);

    if (!udp_ipv4_code_static(&ctx->udp_ip_ctx, IR_hdr))
    {
        ROHC_LOG_ERROR("encode static chain fail\n");
        assert(0);
        return false;
    }

    if (!udp_ipv4_code_dynamic(&ctx->udp_ip_ctx, IR_hdr))
    {
        ROHC_LOG_ERROR("encode dynamic chain fail\n");
        assert(0);
        return false;
    }

    *crc = rohc_cal_crc(ROHC_CRC_TYPE_8,
                        rohc_buf_get_pointer(*IR_hdr, 0),
                        IR_hdr->len,
                        CRC_8_INIT_VAL);
    return true;
}

/*
 *   0   1   2   3   4   5   6   7
 *  --- --- --- --- --- --- --- ---
 * :         Add-CID octet         : if for small CIDs and CID != 0
 * +---+---+---+---+---+---+---+---+
 * | 1   1   1   1   1   0   0   0 | IR-DYN packet type
 * +---+---+---+---+---+---+---+---+
 * :                               :
 * /     0-1 octets of CID info    / 0-1 octets if for large CIDs
 * :                               :
 * +---+---+---+---+---+---+---+---+
 * |            Profile            | 1 octet
 * +---+---+---+---+---+---+---+---+
 * |              CRC              | 1 octet
 * +---+---+---+---+---+---+---+---+
 * |                               |
 * /         Dynamic chain         / variable length
 * |                               |
 * +---+---+---+---+---+---+---+---+
 * |             SN                | 2 octets if not RTP nor ESP
 * +---+---+---+---+---+---+---+---+
 * :                               :
 * /           Payload             / variable length
 * :                               :
 *  - - - - - - - - - - - - - - - -
 */

static bool encode_IR_DYN_header(rohc_comp_context_t *const ctx, rohc_buf_t *const IR_dyn_hdr)
{
    uint8_t *crc;
    uint8_t f_octect = ROHC_IR_DYN_PREAMBLE_CODE;

    ROHC_NULL_PTR_CHECK_RET(ctx, false);
    ROHC_NULL_PTR_CHECK_RET(IR_dyn_hdr, false);

    if (!rohc_buf_size_check(*IR_dyn_hdr, MAXIMUM_ROHC_HEADER_SIZE))
    {
        return false;
    }

    if (!fill_cid_and_first_octet(IR_dyn_hdr, ctx->cfg->cid_type, f_octect, ctx->cid))
    {
        ROHC_LOG_ERROR( "invalid cid and 1st byte fill\n");
        assert(0);
    }

    rohc_buf_append_byte(IR_dyn_hdr, ROHC_PROFILE_UDP);
    crc = rohc_buf_append_byte(IR_dyn_hdr, 0); // init CRC = 0

    assert(crc != NULL);

    if (!udp_ipv4_code_dynamic(&ctx->udp_ip_ctx, IR_dyn_hdr))
    {
        ROHC_LOG_ERROR( "encode dynamic chain fail\n");
        assert(0);
        return false;
    }

    *crc = rohc_cal_crc(ROHC_CRC_TYPE_8,
                         rohc_buf_get_pointer(*IR_dyn_hdr, 0),
                         IR_dyn_hdr->len,
                         CRC_8_INIT_VAL);

    return true;
}


/*
 *   0   1   2   3   4   5   6   7
 * +---+---+---+---+---+---+---+---+
 * | 1   1   0 |        SN         |
 * +===+===+===+===+===+===+===+===+
 * | X |            CRC            |   X = 0
 * +---+---+---+---+---+---+---+---+
 */
static bool code_UOR2_header(rohc_comp_context_t *const ctx, rohc_buf_t *const uor_2_hdr)
{
    uint8_t f_octect = 0;
    uint8_t x_crc;

    ROHC_NULL_PTR_CHECK_RET(ctx, false);
    ROHC_NULL_PTR_CHECK_RET(uor_2_hdr, false);

    if (!rohc_buf_size_check(*uor_2_hdr, MAXIMUM_ROHC_HEADER_SIZE))
    {
        return false;
    }

    f_octect = 0xc0 | ((uint8_t)(udp_ipv4_get_SN(&ctx->udp_ip_ctx) & 0x1f)); /* 1 1 0 x x x x x */

    if (!fill_cid_and_first_octet(uor_2_hdr, ctx->cfg->cid_type, f_octect, ctx->cid))
    {
        ROHC_LOG_ERROR( "invalid cid and 1st byte fill\n");
        assert(0);
    }

    x_crc = udp_ipv4_calculate_UO_x_crc(&ctx->udp_ip_ctx,
                                        ROHC_CRC_TYPE_7,
                                        CRC_7_INIT_VAL);
    x_crc &= 0x7F;
    rohc_buf_append_byte(uor_2_hdr, x_crc);

    return udp_ipv4_code_UO_x_random_fields(&ctx->udp_ip_ctx, uor_2_hdr);
}

/*
 *   0   1   2   3   4   5   6   7
 * +---+---+---+---+---+---+---+---+
 * | 0 |      SN       |    CRC    |
 * +===+===+===+===+===+===+===+===+
 */
static bool encode_UO0_header(rohc_comp_context_t *const ctx, rohc_buf_t * const uo_0_hdr)
{
    uint8_t f_octect = 0;
    uint8_t crc;

    ROHC_NULL_PTR_CHECK_RET(ctx, false);
    ROHC_NULL_PTR_CHECK_RET(uo_0_hdr, false);

    if (!rohc_buf_size_check(*uo_0_hdr, MAXIMUM_ROHC_HEADER_SIZE))
    {
        return false;
    }

    crc = udp_ipv4_calculate_UO_x_crc(&ctx->udp_ip_ctx,
                                      ROHC_CRC_TYPE_3,
                                      CRC_3_INIT_VAL);

    f_octect = ((uint8_t)(udp_ipv4_get_SN(&ctx->udp_ip_ctx) & 0x0f)) << 3;
    f_octect |= crc;

    if (!fill_cid_and_first_octet(uo_0_hdr, ctx->cfg->cid_type, f_octect, ctx->cid))
    {
        ROHC_LOG_ERROR( "%s, invalid cid and 1st byte fill\n", __FUNCTION__);
        assert(0);
    }

    return udp_ipv4_code_UO_x_random_fields(&ctx->udp_ip_ctx, uo_0_hdr);

}

/*
 *   0   1   2   3   4   5   6   7
 * +---+---+---+---+---+---+---+---+
 * | 1   0 |         IP-ID         |
 * +===+===+===+===+===+===+===+===+
 * |        SN         |    CRC    |
 * +---+---+---+---+---+---+---+---+
 */

static bool encode_UO1_header(rohc_comp_context_t *const ctx, rohc_buf_t *const uo_1_hdr)
{
    uint8_t f_octect = 0;
    uint8_t sn_crc;
    uint8_t ip_id_ofst;
    uint8_t sn_low;

    ROHC_NULL_PTR_CHECK_RET(ctx, false);
    ROHC_NULL_PTR_CHECK_RET(uo_1_hdr, false);

    if (!rohc_buf_size_check(*uo_1_hdr, MAXIMUM_ROHC_HEADER_SIZE))
    {
        return false;
    }

    ip_id_ofst = (uint8_t)udp_ipv4_get_IP_ID_minus_SN(&ctx->udp_ip_ctx);

    f_octect = 0x80 | (ip_id_ofst & 0x3F);

    if (!fill_cid_and_first_octet(uo_1_hdr, ctx->cfg->cid_type, f_octect, ctx->cid))
    {
        ROHC_LOG_ERROR( "%s, invalid cid and 1st byte fill\n", __FUNCTION__);
        assert(0);
    }

    sn_crc = udp_ipv4_calculate_UO_x_crc(&ctx->udp_ip_ctx,
                                         ROHC_CRC_TYPE_3,
                                         CRC_3_INIT_VAL);

    sn_low = (uint8_t)(udp_ipv4_get_SN(&ctx->udp_ip_ctx));
    sn_crc = ((sn_low & 0x1f) << 3) | (sn_crc & 0x07);
    ROHC_LOG_DEBUG("uo_1 sn_low 0x%02x, sn_crc 0x%02x\n", sn_low, sn_crc);
    rohc_buf_append_byte(uo_1_hdr, sn_crc);

    return udp_ipv4_code_UO_x_random_fields(&ctx->udp_ip_ctx, uo_1_hdr);
}

extern bool encode_rohc_packet_header(rohc_comp_context_t *const ctx, rohc_buf_t *const header_buf)
{
    ROHC_NULL_PTR_CHECK_RET(ctx, false);
    ROHC_NULL_PTR_CHECK_RET(header_buf, false);

    rohc_buf_clear(header_buf);

    switch (ctx->packet_type)
    {
    case ROHC_PACKET_IR:
        return encode_IR_header(ctx, header_buf);
    case ROHC_PACKET_IR_DYN:
        return encode_IR_DYN_header(ctx, header_buf);
    case ROHC_PACKET_UO_0:
        return encode_UO0_header(ctx, header_buf);
    case ROHC_PACKET_UO_1:
        return encode_UO1_header(ctx, header_buf);
    case ROHC_PACKET_UOR_2:
        return code_UOR2_header(ctx, header_buf);
    default:
        ROHC_LOG_ERROR( "%s unknonwn packet type %d\n",
                       __FUNCTION__, ctx->packet_type);
        assert(0);
        return false;
    }

    return true;
}

extern rohc_status_t rohc_comp_internal(rohc_comp_context_t *const ctx,
                                        rohc_buf_t *const comp_pkt,
                                        const network_packet_t *const net_pkt)
{
    ROHC_NULL_PTR_CHECK_RET(ctx, ROHC_STATUS_ERROR);
    ROHC_NULL_PTR_CHECK_RET(net_pkt, ROHC_STATUS_ERROR);
    ROHC_NULL_PTR_CHECK_RET(net_pkt->payload, ROHC_STATUS_ERROR);

    if (!rohc_buf_size_check(*comp_pkt, (MAXIMUM_ROHC_HEADER_SIZE + net_pkt->payload_len)))
    {
        return ROHC_STATUS_OUTPUT_TOO_SMALL;
    }

    if (!udp_ipv4_udpate_context(&ctx->udp_ip_ctx, net_pkt))
    {
        return ROHC_STATUS_ERROR;
    }

    rohc_sm_state_update(&ctx->sm);

    ctx->packet_type =
        rohc_sm_decide_packet_type(&ctx->sm, (const void *)(&ctx->udp_ip_ctx));

    if (ctx->packet_type == ROHC_PACKET_UNKNOWN)
    {
        ROHC_LOG_ERROR( "%s, knownn rohc packet type\n", __FUNCTION__);
        return ROHC_STATUS_ERROR;
    }

    rohc_buf_clear(comp_pkt);
    encode_rohc_packet_header(ctx, comp_pkt);
    if (!rohc_buf_append(comp_pkt, net_pkt->payload, net_pkt->payload_len))
    {
        ROHC_LOG_ERROR( "%s append payload after rohc header fail\n", __FUNCTION__);
        return ROHC_STATUS_MALFORMED;
    }

    return ROHC_STATUS_OK;
}

extern void rohc_comp_context_init(rohc_comp_context_t *const ctx,
                                   const uint8_t cid,
                                   rohc_comp_config_t *const cfg)
{
    ROHC_NULL_PTR_CHECK(ctx);
    ROHC_NULL_PTR_CHECK(cfg);

    udp_ipv4_init_context(&ctx->udp_ip_ctx, cfg->wlsb_sn_win_capacity, cfg->wlsb_ip_id_win_capacity);
    rohc_sm_init(&ctx->sm, cid, cfg->perodic_ir_timeout_cnt, cfg->perodic_fo_timeout_cnt,
                 udp_ipv4_comp_decide_fo_packet, udp_ipv4_comp_decide_so_packet);

    ctx->cid = cid;
    ctx->cfg = cfg;
    ctx->in_use = true;
    ctx->last_use_time = 0;

    ROHC_LOG_INFO( "%s, cid %d Done\n", __FUNCTION__, cid);
}

extern void rohc_comp_context_deinit(rohc_comp_context_t *const ctx)
{
    ROHC_NULL_PTR_CHECK(ctx);

    udp_ipv4_deinit_context(&ctx->udp_ip_ctx);

    ROHC_LOG_INFO("%s, cid %d Done\n", __FUNCTION__, ctx->cid);
}

extern bool rohc_comp_get_last_packet_info(const rohc_comp_context_t *const ctx,
                                           rohc_comp_packet_info_t *const pkt_info)
{
    rohc_buf_t rohc_buf;

    ROHC_NULL_PTR_CHECK_RET(ctx, false);
    ROHC_NULL_PTR_CHECK_RET(pkt_info, false);

    pkt_info->packet_type = ctx->packet_type;
    pkt_info->cid = ctx->cid;
    pkt_info->cid_type = ctx->cfg->cid_type;
    pkt_info->ip_id = udp_ipv4_get_IP_ID(&ctx->udp_ip_ctx);
    pkt_info->SN = udp_ipv4_get_SN(&ctx->udp_ip_ctx);

    rohc_buf = rohc_buf_init(pkt_info->static_context_buf, ROHC_STATIC_CONTEXT_BUF_LEN, true);
    udp_ipv4_code_static(&ctx->udp_ip_ctx, &rohc_buf);
    pkt_info->static_context_size = rohc_buf.len;

    rohc_buf = rohc_buf_init(pkt_info->dynamic_context_buf, ROHC_DYNAMIC_CONTEXT_BUF_LEN, true);
    udp_ipv4_code_dynamic(&ctx->udp_ip_ctx, &rohc_buf);
    pkt_info->dynamic_context_size = rohc_buf.len;

   return true;
}

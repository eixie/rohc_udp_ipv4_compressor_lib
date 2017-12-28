#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include "rohc_comp.h"
#include "rohc_comp_internal.h"
#include "rohc_log.h"
#include "rohc_utils.h"

#define MAX_COMPRESSOR_NUM (8) // support at most 8 decompressors
static rohc_compressor_t g_compressors[MAX_COMPRESSOR_NUM];

static bool init_context_management(rohc_comp_context_managment_t *const mm,
                                    const uint16_t tot_ctx_num)
{
    ROHC_NULL_PTR_CHECK_RET(mm, false);

    memset(mm, 0, sizeof(rohc_comp_context_managment_t));

    if (tot_ctx_num == 0)
    {
        mm->total_num = DEFAULT_CONTEXT_NUM_PER_COMPRESSOR;
    }
    else if (tot_ctx_num >= MAX_CONTEXT_NUM_PER_COMPRESSOR)
    {
        mm->total_num = MAX_CONTEXT_NUM_PER_COMPRESSOR;
    }
    else
    {
        mm->total_num = tot_ctx_num;
    }

    mm->ctx_array = calloc(tot_ctx_num, sizeof(rohc_comp_context_t));

    if (mm->ctx_array == NULL)
    {
        ROHC_LOG_ERROR("%s init context memory fail\n", __FUNCTION__);
        return false;
    }

    ROHC_LOG_INFO("%s init context num %d\n", __FUNCTION__, tot_ctx_num);
    return true;
}

static void set_wlsb_window_capacity(rohc_comp_config_t *const cfg,
                                     const uint32_t wlsb_sn_capacity,
                                     const uint32_t wlsb_ip_id_capacity)
{
    ROHC_NULL_PTR_CHECK(cfg);

    if ((wlsb_sn_capacity == 0) || (!IS_POW_OF_2(wlsb_sn_capacity)))
    {
        const uint32_t dfl_sn_wlsb_width = 4;
        cfg->wlsb_sn_win_capacity = dfl_sn_wlsb_width;
    }
    else
    {
        cfg->wlsb_sn_win_capacity = wlsb_sn_capacity;
    }

    if ((wlsb_ip_id_capacity == 0) || (!IS_POW_OF_2(wlsb_ip_id_capacity)))
    {
        const uint32_t dfl_ip_id_wlsb_width = 4;
        cfg->wlsb_ip_id_win_capacity = dfl_ip_id_wlsb_width;
    }
    else
    {
        cfg->wlsb_ip_id_win_capacity = wlsb_ip_id_capacity;
    }

    ROHC_LOG_INFO("set wlsb window: sn %d, ip-id %d\n",
                  cfg->wlsb_sn_win_capacity,
                  cfg->wlsb_ip_id_win_capacity);
}

static void set_periodic_down_trans_timeout(rohc_comp_config_t *const cfg,
                                            const uint32_t periodic_ir_timeout,
                                            const uint32_t periodic_fo_timeout)
{
    ROHC_NULL_PTR_CHECK(cfg);

    if ((periodic_ir_timeout == 0) ||
        (periodic_fo_timeout == 0) ||
        (periodic_ir_timeout <= periodic_fo_timeout))
    {
        cfg->perodic_ir_timeout_cnt = DFL_PERIODIC_IR_DOWN_TRANS_TIMEOUT;
        cfg->perodic_fo_timeout_cnt = DFL_PERIODIC_FO_DOWN_TRANS_TIMEOUT;
    }
    else
    {
        cfg->perodic_ir_timeout_cnt = periodic_ir_timeout;
        cfg->perodic_fo_timeout_cnt = periodic_fo_timeout;
    }

    ROHC_LOG_INFO("set refresh timeout, ir %d, fo %d\n",
                  cfg->perodic_ir_timeout_cnt,
                  cfg->perodic_fo_timeout_cnt);
}

static rohc_comp_context_t* find_comp_context(rohc_compressor_t *const comp,
                                                const network_packet_t  *const net_pkt)
{

#define INVALID_COMP_CTX_INDEX (0xFFFF)

    static size_t current_time_clock = 0;

    rohc_comp_context_managment_t *mm;
    rohc_comp_context_t *ctx = NULL;

    uint16_t free_idx = INVALID_COMP_CTX_INDEX;
    uint16_t oldest_used_idx = INVALID_COMP_CTX_INDEX;
    size_t oldest_used_time = current_time_clock;
    uint16_t i;

    ROHC_NULL_PTR_CHECK_RET(comp, NULL);
    ROHC_NULL_PTR_CHECK_RET(net_pkt, NULL);

    mm = &comp->ctx_mm;

    current_time_clock++;

    for (i = 0; i <= mm->total_num; i++)
    {
        if (mm->ctx_array[i].in_use)
        {
            bool context_match = udp_ipv4_static_context_match(&mm->ctx_array[i].udp_ip_ctx,
                                                               net_pkt->ip_hdr.src_addr,
                                                               net_pkt->ip_hdr.dst_addr,
                                                               net_pkt->udp_hdr.src,
                                                               net_pkt->udp_hdr.dest);
            if (context_match)
            {
                ctx = &mm->ctx_array[i];
                mm->ctx_array[i].last_use_time = current_time_clock;

                ROHC_LOG_INFO("found match ctx context [%d] for CID[%d]\n", i, ctx->cid);
                break;
            }
            else
            {
                if (oldest_used_time < mm->ctx_array[i].last_use_time)
                {
                    oldest_used_time = mm->ctx_array[i].last_use_time;
                    oldest_used_idx = i;
                }
            }
        }
        else if (free_idx == INVALID_COMP_CTX_INDEX)
        {
            free_idx = i;
        }
    }

    if (ctx == NULL)
    {
        uint16_t  idx;
        uint8_t cid;

        if ((free_idx != INVALID_COMP_CTX_INDEX) && (comp->next_avail_cid < comp->cfg.max_cid))
        {
            cid = comp->next_avail_cid++;
            idx = free_idx;
            ROHC_LOG_INFO("create new context [%d] for CID[%d]\n", idx, cid);
        }
        else if (oldest_used_idx != INVALID_COMP_CTX_INDEX)
        {
            cid = mm->ctx_array[oldest_used_idx].cid;
            idx = oldest_used_idx;
            ROHC_LOG_INFO("reuse oldest context [%d] for CID[%d]\n", idx, cid);
        }
        else
        {
            return NULL;
        }

        ctx = &mm->ctx_array[idx];
        mm->ctx_array[idx].last_use_time = current_time_clock;
        rohc_comp_context_init(ctx, cid, &comp->cfg);
    }

    return ctx;
}


rohc_status_t rohc_compress(const rohc_comp_index_t comp_idx,
                            rohc_buf_t *const rohc_pkt,
                            rohc_comp_packet_info_t *const rohc_pkt_info,
                            const rohc_buf_t uncomp_data)
{
    rohc_compressor_t *comp = NULL;
    rohc_status_t ret;
    rohc_comp_context_t *ctx = NULL;
    network_packet_t net_pkt;

    if ((comp_idx >= MAX_COMPRESSOR_NUM) || (!g_compressors[comp_idx].in_use))
    {
        return ROHC_STATUS_INVALID_COMPRESSOR;
    }

    comp = &g_compressors[comp_idx];

    if (!parse_net_packet(&net_pkt, rohc_buf_get_pointer(uncomp_data, 0), uncomp_data.len))
    {
        return ROHC_STATUS_NET_PARSE_FAIL;
    }

    ctx = find_comp_context(comp, &net_pkt);
    if (ctx == NULL)
    {
        return ROHC_STATUS_NO_CONTEXT;
    }

    ret = rohc_comp_internal(ctx, rohc_pkt, &net_pkt);

    if (ret != ROHC_STATUS_OK)
    {
        return ret;
    }

    if (!rohc_comp_get_last_packet_info(ctx, rohc_pkt_info))
    {
        return ROHC_STATUS_ERROR;
    }

    return ret;
}

static inline bool rohc_validate_cid(const rohc_cid_type_t cid_type, const uint16_t max_cid)
{
    switch (cid_type)
    {
    case ROHC_SMALL_CID:
        return (max_cid <= ROHC_SMALL_CID_MAX);
    case ROHC_LARGE_CID:
        return (max_cid <= ROHC_LARGE_CID_MAX);
    default:
        return false;
    }
    return false;
}

/**
 * @brief Allocate compressor API
 *
 * There are MAX_COMPRESSOR_NUM(8) global g_compressors for ROHC
 * compress, and allocate a free compressor.
 *
 * @see
 *
 * @param         the configuration(cid/wlsb/refresh_timeout)
 * @return        the index of compressor
 */
rohc_comp_index_t rohc_allocate_compressor(const rohc_cid_type_t cid_type,
                                                       const uint8_t  max_cid,
                                                       const uint32_t wlsb_sn_window_capacity,
                                                       const uint32_t wlsb_ip_id_window_capacity,
                                                       const uint32_t periodic_ir_timeout,
                                                       const uint32_t periodic_fo_timeout)
{
    rohc_comp_index_t idx;
    rohc_compressor_t *comp = NULL;

    for (idx = 0; idx < MAX_COMPRESSOR_NUM; ++idx)
    {
        if (!g_compressors[idx].in_use)
        {
            comp = &g_compressors[idx];
            ROHC_LOG_INFO("alloc compressor[%d]\n", idx);
            break;
        }
    }

    if (comp == NULL)
    {
        return MAX_COMPRESSOR_NUM;
    }

    if (!rohc_validate_cid(cid_type, max_cid))
    {
        return MAX_COMPRESSOR_NUM;
    }

    comp->next_avail_cid = 0;
    comp->cfg.cid_type = cid_type;
    comp->cfg.max_cid = max_cid;

    set_wlsb_window_capacity(&comp->cfg, wlsb_sn_window_capacity, wlsb_ip_id_window_capacity);
    set_periodic_down_trans_timeout(&comp->cfg, periodic_ir_timeout,  periodic_fo_timeout);

    if (!init_context_management(&comp->ctx_mm, ((uint16_t)max_cid) + 1))
    {
        return MAX_COMPRESSOR_NUM;
    }

    comp->in_use = true;

    return idx;
}

void rohc_release_compressor(const rohc_comp_index_t comp_idx)
{
    if ((comp_idx < MAX_COMPRESSOR_NUM) && (g_compressors[comp_idx].in_use))
    {
        rohc_compressor_t *comp = &g_compressors[comp_idx];
        uint16_t i;

        for (i = 0; i < comp->ctx_mm.total_num; ++i)
        {
            if (comp->ctx_mm.ctx_array[i].in_use)
            {
                rohc_comp_context_deinit(&comp->ctx_mm.ctx_array[i]);
            }
        }

        free(comp->ctx_mm.ctx_array);

        comp->in_use = false;
    }
}

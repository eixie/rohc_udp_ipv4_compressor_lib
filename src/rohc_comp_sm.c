#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#include "rohc_comp_sm.h"
#include "rohc_log.h"
#include "rohc_utils.h"
#include "rohc_packet.h"

static inline void rohc_sm_change_state(rohc_comp_state_machine_t *const sm,
                                        const rohc_comp_sm_state_t new_state)
{
    if (new_state != sm->state)
    {
        ROHC_LOG_DEBUG("cid %u: change: %d to state %d", sm->cid, sm->state, new_state);

        sm->ir_cnt = 0;
        sm->fo_cnt = 0;
        sm->so_cnt = 0;
        sm->state = new_state;
    }
}

static void rohc_sm_state_periodic_down_transitiation(rohc_comp_state_machine_t *const sm)
{
    ROHC_NULL_PTR_CHECK(sm);

    if (sm->perodic_ir_cnt >= PERODIC_DOWN_TRANS_TO_IR_COUNT)
    {
        sm->perodic_ir_cnt = 0;
        rohc_sm_change_state(sm, ROHC_COMP_STATE_IR);
        ROHC_LOG_DEBUG("periodic transitation to IR timeout\n");
    }
    else if (sm->perodic_fo_cnt >= PERODIC_DOWN_TRANS_TO_FO_COUNT)
    {
        sm->perodic_fo_cnt = 0;

        if (sm->state != ROHC_COMP_STATE_IR)
        {
            rohc_sm_change_state(sm, ROHC_COMP_STATE_FO);
            ROHC_LOG_DEBUG("periodic down transitation to FO timeout\n");
        }
    }

    if (sm->state == ROHC_COMP_STATE_SO)
    {
        sm->perodic_fo_cnt++;
    }

    if ((sm->state == ROHC_COMP_STATE_SO) || (sm->state == ROHC_COMP_STATE_FO))
    {
        sm->perodic_ir_cnt++;
    }
}

extern void rohc_sm_state_update(rohc_comp_state_machine_t *const sm)
{
    ROHC_NULL_PTR_CHECK(sm);
    rohc_sm_state_periodic_down_transitiation(sm);

    switch (sm->state)
    {
    case ROHC_COMP_STATE_IR:
        if (sm->ir_cnt >= MAX_CONTINUOUS_IR_COUNT)
        {
            rohc_sm_change_state(sm, ROHC_COMP_STATE_FO);
        }
        break;

    case ROHC_COMP_STATE_FO:
        if (sm->fo_cnt >= MAX_CONTINUOUS_FO_COUNT)
        {
            rohc_sm_change_state(sm, ROHC_COMP_STATE_SO);
        }
        break;

    default:
        break;
    }
}

extern rohc_packet_t rohc_sm_decide_packet_type(rohc_comp_state_machine_t *const sm,
                                                const void *const ctx)
{
    rohc_packet_t pkt_type = ROHC_PACKET_UNKNOWN;

    ROHC_NULL_PTR_CHECK_RET(sm, ROHC_PACKET_UNKNOWN);
    ROHC_NULL_PTR_CHECK_RET(ctx, ROHC_PACKET_UNKNOWN);

    switch (sm->state)
    {
    case ROHC_COMP_STATE_IR:
        sm->ir_cnt++;
        pkt_type = ROHC_PACKET_IR;
        break;

    case ROHC_COMP_STATE_FO:
        sm->fo_cnt++;
        assert(pkt_type != ROHC_PACKET_IR);
        pkt_type = sm->func_decide_fo_packet(ctx);
        break;

    case ROHC_COMP_STATE_SO:
        sm->so_cnt++;
        pkt_type = sm->func_decide_so_packet(ctx);
        assert(pkt_type != ROHC_PACKET_IR);

        if (pkt_type == ROHC_PACKET_IR_DYN)
        {
            rohc_sm_change_state(sm, ROHC_COMP_STATE_FO);
            ROHC_LOG_DEBUG("Dynamic change, down trans SO->FO\n");
        }
        break;

    default:
        ROHC_LOG_ERROR("%s Bad sm state %d\n", __FUNCTION__, sm->state);
        assert(0);
    }

    ROHC_LOG_DEBUG("pkt_type '%s' chosen", rohc_get_packet_descr(pkt_type));

    return pkt_type;
}

extern void rohc_sm_init(rohc_comp_state_machine_t *const sm,
                         const uint8_t cid,
                         const uint32_t perodic_ir_timeout_cnt,
                         const uint32_t perodic_fo_timeout_cnt,
                         const decide_rohc_packet_func func_decide_fo_packet,
                         const decide_rohc_packet_func func_decide_so_packet)
{
    ROHC_NULL_PTR_CHECK(sm);

    memset(sm, 0, sizeof(rohc_comp_state_machine_t));

    sm->cid = cid;

    if((perodic_ir_timeout_cnt == 0) ||
       (perodic_fo_timeout_cnt == 0) ||
       (perodic_ir_timeout_cnt <= perodic_fo_timeout_cnt))
    {
        sm->perodic_ir_timeout_cnt = PERODIC_DOWN_TRANS_TO_IR_COUNT;
        sm->perodic_fo_timeout_cnt = PERODIC_DOWN_TRANS_TO_FO_COUNT;

        ROHC_LOG_INFO("%s, use default ir timeout %d, fo timeout%d\n", __FUNCTION__,
                      PERODIC_DOWN_TRANS_TO_IR_COUNT,
                      PERODIC_DOWN_TRANS_TO_FO_COUNT);
    }
    else
    {
        sm->perodic_ir_timeout_cnt = perodic_ir_timeout_cnt;
        sm->perodic_fo_timeout_cnt = perodic_fo_timeout_cnt;

        ROHC_LOG_INFO("%s, use setting ir timeout %d, fo timeout%d\n", __FUNCTION__,
                      perodic_ir_timeout_cnt, perodic_fo_timeout_cnt);
    }

    sm->func_decide_fo_packet = func_decide_fo_packet;
    sm->func_decide_so_packet = func_decide_so_packet;

    ROHC_LOG_INFO("%s, cid %d\n", __FUNCTION__, cid);
}


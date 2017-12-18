#ifndef ROHC_STATE_MACHINE_H
#define ROHC_STATE_MACHINE_H

#include <stdint.h>
#include <stdbool.h>
#include "rohc_packet.h"

typedef enum
{
    PERODIC_DOWN_TRANS_TO_IR_COUNT  = 1000U,
    PERODIC_DOWN_TRANS_TO_FO_COUNT  = 500U,
    MAX_CONTINUOUS_IR_COUNT = 2U,
    MAX_CONTINUOUS_FO_COUNT = 2U,
}rohc_comp_sm_cfg_t;

typedef enum
{
	ROHC_COMP_STATE_UNKNOWN = 0,
	ROHC_COMP_STATE_IR = 1,
	ROHC_COMP_STATE_FO = 2,
	ROHC_COMP_STATE_SO = 3,
}rohc_comp_sm_state_t;

typedef rohc_packet_t (*decide_rohc_packet_func)(const void*);

typedef struct
{
    uint8_t cid;

	rohc_comp_sm_state_t state;

	uint32_t ir_cnt;
	uint32_t fo_cnt;
	uint32_t so_cnt;

	uint32_t perodic_ir_cnt;
	uint32_t perodic_fo_cnt;

    uint32_t perodic_ir_timeout_cnt;
    uint32_t perodic_fo_timeout_cnt;

    decide_rohc_packet_func func_decide_fo_packet;
    decide_rohc_packet_func func_decide_so_packet;

}rohc_comp_state_machine_t;

extern void rohc_sm_init(rohc_comp_state_machine_t *const sm,
                         const uint8_t cid,
                         const uint32_t perodic_ir_timeout_cnt,
                         const uint32_t perodic_fo_timeout_cnt,
                         const decide_rohc_packet_func func_decide_fo_packet,
                         const decide_rohc_packet_func func_decide_so_packet);

extern rohc_packet_t rohc_sm_decide_packet_type(rohc_comp_state_machine_t *const sm,
                                                const void *const ctx);

extern void rohc_sm_state_update(rohc_comp_state_machine_t *const sm);

#endif /* ROHC_STATE_MACHINE_H */


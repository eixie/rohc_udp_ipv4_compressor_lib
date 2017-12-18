#ifndef ROHC_COMP_WLSB_H
#define ROHC_COMP_WLSB_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C"
{
#endif

typedef enum
{
	ROHC_LSB_SHIFT_SN         = -1,      /**< real value for non-RTP SN */
	ROHC_LSB_SHIFT_IP_ID      =  0,      /**< real value for IP-ID */
}lsb_shift_t;

typedef struct
{
    uint16_t start; //v_ref - p
    uint16_t end;   // v_ref + (2^k - 1) - p
}lsb_interval_t;

typedef struct
{
	lsb_shift_t p;
	uint16_t win_mask;

	uint16_t earliest;
	uint16_t next_latest;

	uint16_t avail_ref_cnt;
	uint16_t win_capacity;
	uint16_t ref_window[1];
}wlsb_t;

extern wlsb_t* wlsb_init(const uint16_t win_capacity, const lsb_shift_t p);

extern void wlsb_deinit(wlsb_t *const wlsb);
extern void wlsb_add_ref_to_window(wlsb_t *const wlsb, const uint16_t ref_v);
extern uint8_t wlsb_g_max_k(const wlsb_t *const wlsb, const uint16_t v);

#ifdef __cplusplus
}
#endif

#endif /* ROHC_COMP_WLSB_H */


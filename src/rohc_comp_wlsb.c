#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>

#include "rohc_log.h"
#include "rohc_utils.h"
#include "rohc_comp_wlsb.h"

/* f(v_ref, k) = [v_ref-p, v_ref+(2^k-1)-p] */
static inline lsb_interval_t lsb_f(const uint16_t v_ref, const uint8_t k, const lsb_shift_t p)
{
    lsb_interval_t intvl;
	uint16_t intvl_size = (uint16_t) (((1UL) << k) - 1);

	assert(k <= 16);

    intvl.start = v_ref - (int8_t)p;
    intvl.end = v_ref + intvl_size - (int8_t)p;

	return intvl;
}

static inline bool v_in_interval(const uint16_t intvl_start,
                                 const uint16_t intvl_end,
                                 const uint16_t v)
{
    if (intvl_start <= intvl_end)
    {
        if ((v >= intvl_start) && (v <= intvl_end))
        {
           return true;
        }
    }
    else
    {
        if (v >= intvl_start || v <= intvl_end)         // wrap around case
        {
            return true;
        }
    }

    return false;
}

/* k = g(v_ref_c, v)*/
static uint8_t lsb_g(const uint16_t v_ref_c, const uint16_t v, const lsb_shift_t p)
{
    lsb_interval_t intvl;
    uint8_t min_k;

    for (min_k = 0; min_k < 16; min_k++)
    {
        intvl = lsb_f(v_ref_c, min_k, p);

        if (v_in_interval(intvl.start, intvl.end, v))
        {
            break;
        }
    }

    return min_k;
}

/* k = max(g(v_min,v), g(v_max, v)),
 * v_min and v_max are the min and max value in the sliding ref_window
 */
extern uint8_t wlsb_g_max_k(const wlsb_t *const wlsb, const uint16_t v)
{
	uint8_t max_k = 0;

     assert(wlsb != NULL);

	/* use all bits if the ref_window contains no value */
	if(wlsb->avail_ref_cnt == 0)
	{
        max_k = 16;
	}
	else
    {
        uint16_t i;
        uint16_t idx = wlsb->earliest;

        for (i = 0; i < wlsb->avail_ref_cnt; i++)
        {
            uint8_t k = lsb_g(wlsb->ref_window[idx], v, wlsb->p);
            max_k = (max_k > k) ? max_k : k;

            idx = (idx + 1) & wlsb->win_mask;
        }
    }

	return max_k;
}

extern void wlsb_add_ref_to_window(wlsb_t *const wlsb, const uint16_t ref_v)
{
    assert(wlsb != NULL);
    assert(wlsb->ref_window != NULL);

    if (wlsb->avail_ref_cnt < wlsb->win_capacity)
    {
        wlsb->avail_ref_cnt++;
    }
    else
    {
        wlsb->earliest = (wlsb->earliest + 1) & wlsb->win_mask;
    }

    wlsb->ref_window[wlsb->next_latest] = ref_v;
    wlsb->next_latest = (wlsb->next_latest + 1) & wlsb->win_mask;
}

extern wlsb_t* wlsb_init(const uint16_t win_capacity, const lsb_shift_t p)
{
	wlsb_t *wlsb;

	assert(win_capacity > 0);
	assert(win_capacity != 0 && (win_capacity & (win_capacity - 1)) == 0);

	wlsb = malloc(sizeof(wlsb_t) + sizeof(uint16_t) * (win_capacity - 1));

	if(wlsb == NULL)
	{
        ROHC_LOG_ERROR("alloca wlsb fail\n");
		return NULL;
	}

	wlsb->earliest = 0;
	wlsb->next_latest   = 0;
	wlsb->avail_ref_cnt = 0;
    wlsb->win_capacity = win_capacity;
	wlsb->win_mask = win_capacity - 1;
	wlsb->p = p;

	return wlsb;
}


extern void wlsb_deinit(wlsb_t *const wlsb)
{
    free(wlsb);
}


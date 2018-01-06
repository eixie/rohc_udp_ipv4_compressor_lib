#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include "rohc_log.h"
#include "rohc_buf.h"
#include "rohc_utils.h"

#include "rohc_cache_file.h"

#define MIN_CACHE_BUFFER_SIZE  (128 * 1024)
#define MIN_CACHE_BUFFER_FULL_MARGIN (32)

static inline void rohc_cahce_dump_flush(rohc_cache_file_t *const cfp)
{
    if (cfp != NULL)
    {
        if (rohc_buf_get_data_size(cfp->buf) > 0)
        {
            if (cfp->fp != NULL)
            {
                fwrite(rohc_buf_get_pointer(cfp->buf, 0),
                       rohc_buf_get_data_size(cfp->buf), 1, cfp->fp);
                fflush(cfp->fp);
            }

            rohc_buf_clear(&cfp->buf);
        }
    }
}

extern rohc_cache_file_t * rohc_cache_fopen(const char *path,
                                                 const char *mode,
                                                 uint32_t cache_buf_size,
                                                 uint32_t buf_full_margin)
{
    static uint32_t serial_number = 0;
    rohc_cache_file_t *cfp = NULL;

    ROHC_NULL_PTR_CHECK_RET(path, false);
    ROHC_NULL_PTR_CHECK_RET(mode, false);

    if (cache_buf_size < MIN_CACHE_BUFFER_SIZE)
    {
        ROHC_LOG_DEBUG("adjust cache buffer size to 128KB\n");
        cache_buf_size = MIN_CACHE_BUFFER_SIZE;
    }

    if (buf_full_margin < MIN_CACHE_BUFFER_FULL_MARGIN)
    {
        ROHC_LOG_DEBUG("adjust cache buffer full margin size to 32B\n");
        buf_full_margin = MIN_CACHE_BUFFER_FULL_MARGIN;
    }

    if (cache_buf_size <= buf_full_margin)
    {
        cache_buf_size = buf_full_margin << 1;
        ROHC_LOG_DEBUG("adjust cache buffer size to %d = (2 * full margin)\n", cache_buf_size);
    }

    cfp = malloc(sizeof(rohc_cache_file_t) + cache_buf_size);

    if (cfp == NULL)
    {
        ROHC_LOG_INFO("allocate cache file fail\n");
        return NULL;
    }

    cfp->buf = rohc_buf_init(cfp->data, cache_buf_size, true);
    cfp->fp = fopen(path, mode);
    cfp->buf_full_limit = cache_buf_size - buf_full_margin;
    cfp->serial_number = serial_number++;

    ROHC_LOG_DEBUG("%s, sn%d, buf tot size(%d), full limit(%d)\n",
                   __FUNCTION__,
                   cfp->serial_number,
                   cache_buf_size,
                   cfp->buf_full_limit);
    return cfp;
}

extern void rohc_cache_fclose(rohc_cache_file_t *const cfp)
{
    if (cfp != NULL)
    {
        ROHC_LOG_DEBUG("%s, sn%d\n", cfp->serial_number, __FUNCTION__);
        rohc_cahce_dump_flush(cfp);
        fclose(cfp->fp);
        free(cfp);
    }
}

extern bool rohc_cache_fwrite(rohc_cache_file_t *const cfp, const rohc_buf_t *const src_buf)
{
    ROHC_NULL_PTR_CHECK_RET(cfp, false);
    ROHC_NULL_PTR_CHECK_RET(src_buf, false);

    if (rohc_buf_get_data_size(cfp->buf) >= cfp->buf_full_limit)
    {
        ROHC_LOG_DEBUG("flush cache, sn(%d), data size(%d) > full limit(%d)\n",
                       cfp->serial_number
                       rohc_buf_get_data_size(cfp->buf),
                       cfp->buf_full_limit);

        rohc_cahce_dump_flush(cfp);
    }

    if (src_buf != NULL)
    {
        ROHC_LOG_DEBUG("new data(size %d) add to cache, cur buf size %d\n",
                       rohc_buf_get_data_size(*src_buf),
                       rohc_buf_get_data_size(cfp->buf));

        if (!rohc_buf_append_buf(&cfp->buf, *src_buf))
        {
            assert(0);
        }
    }

    return true;
}

#ifndef ROHC_CACHE_FILE_H
#define ROHC_CACHE_FILE_H

#include <stdint.h>
#include <stdbool.h>
#include "rohc_buf.h"

typedef struct
{
    uint32_t       serial_number;
    FILE           *fp;
    uint32_t       buf_full_limit;
    rohc_buf_t     buf;
    uint8_t        data[1];
}rohc_cache_file_t;

extern bool rohc_cache_fwrite(rohc_cache_file_t *const cfp,
                              const rohc_buf_t *const src_buf);

extern void rohc_cache_fclose(rohc_cache_file_t *const cfp);

extern rohc_cache_file_t* rohc_cache_fopen(const char *path,
                                           const char *mode,
                                           uint32_t cache_buf_size,
                                           uint32_t buf_full_margin);

#endif /* ROHC_CACHE_FILE_H */

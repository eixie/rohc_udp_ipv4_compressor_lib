#ifndef ROHC_BUF_H
#define ROHC_BUF_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <string.h>

/*
 * rohc_buf data structure

  ------------------------------------------------------------------------
  | used_area(maybe prepend)        |  data area       |    free area    |
  ------------------------------------------------------------------------
  |                                 |                  |                 |
  buf_start(data)                 offset          offset + len        tot_size

*/

typedef struct rohc_buf
{
	uint8_t *data;
	uint32_t offset;
	uint32_t len;
    uint32_t tot_size;
}rohc_buf_t;

static inline bool rohc_buf_valid(const rohc_buf_t buf)
{
    if ((buf.data != NULL) && (buf.tot_size > 0) && (buf.offset + buf.len <= buf.tot_size))
    {
        return true;
    }

    return false;
}

static inline bool rohc_buf_empty(const rohc_buf_t buf)
{
    assert(rohc_buf_valid(buf));

    return (buf.len == 0);
}

static inline uint32_t rohc_buf_free_size(const rohc_buf_t buf)
{
    assert(rohc_buf_valid(buf));
    return (buf.tot_size - buf.len);
}

static inline uint32_t rohc_buf_get_data_size(const rohc_buf_t buf)
{
    assert(rohc_buf_valid(buf));
    return buf.len;
}

static inline uint8_t rohc_buf_get_value(const rohc_buf_t buf, const uint32_t index)
{
    assert(rohc_buf_valid(buf));

    if (index < buf.len)
    {
        return buf.data[index + buf.offset];
    }

    return 0;
}

static inline uint8_t* rohc_buf_get_pointer(const rohc_buf_t buf, const uint32_t index)
{
    assert(rohc_buf_valid(buf));

    if (index + buf.offset < buf.tot_size)
    {
        return &buf.data[index + buf.offset];
    }

    return NULL;
}

static inline uint8_t* rohc_buf_get_free_start(const rohc_buf_t buf)
{
    return rohc_buf_get_pointer(buf, buf.len);
}

static inline bool rohc_buf_pull(rohc_buf_t *const buf, const uint32_t size)
{
    if (buf != NULL)
    {
        assert(rohc_buf_valid(*buf));

        if (size <= buf->len)
        {
            buf->offset += size;
            buf->len -= size;

            return true;
        }
    }
    return false;
}


static inline bool rohc_buf_push(rohc_buf_t *const buf, const uint32_t size)
{
    if (buf != NULL)
    {
        assert(!rohc_buf_valid(*buf));

        if (size <= buf->offset)
        {
            buf->offset -= size;
            buf->len += size;
            return true;
        }
    }

    return false;
}

static inline bool rohc_buf_prepend(rohc_buf_t *const buf,
                             const uint8_t *const data,
                             const uint32_t size)
{
    if ((data != NULL) && (buf != NULL) && rohc_buf_push(buf, size))
    {
        memcpy(rohc_buf_get_pointer(*buf, 0), data, size);
        return true;
    }

    return false;
}

static inline bool rohc_buf_append(rohc_buf_t *const buf,
                            const uint8_t *const data,
                            const uint32_t size)
{
    if ((buf != NULL) && (data != NULL) && (rohc_buf_free_size(*buf) >= size))
    {
        memcpy(rohc_buf_get_free_start(*buf), data, size);
        buf->len += size;
        return true;
    }

    return false;
}

static inline uint8_t* rohc_buf_append_byte(rohc_buf_t *const buf, const uint8_t data)
{
    if ((buf != NULL) && (rohc_buf_free_size(*buf) >= 1))
    {
        uint8_t *append_pos = rohc_buf_get_free_start(*buf);

        *append_pos  = data;
        buf->len++;

        return append_pos;
    }

    return NULL;
}

static inline bool rohc_buf_append_buf(rohc_buf_t *const dst, const rohc_buf_t src)
{
    if ((dst != NULL) && (rohc_buf_free_size(*dst) >= src.len))
    {
        memcpy(rohc_buf_get_free_start(*dst), rohc_buf_get_pointer(src, 0), src.len);

        dst->len += src.len;
        return true;
    }

    return false;
}

static inline void rohc_buf_clear(rohc_buf_t *const buf)
{
    assert(buf != NULL);

    buf->len = 0;
    buf->offset = 0;
}

static inline rohc_buf_t rohc_buf_init(uint8_t* data,
                                const uint32_t buf_len,
                                const bool is_empty_buf)
{
    rohc_buf_t buf = {NULL, 0, 0, 0};

    assert((data != NULL) && (buf_len > 0));

    buf.data = data;
    buf.tot_size = buf_len;
    buf.len = is_empty_buf ? 0: buf_len;

    return buf;
}

static inline bool rohc_buf_size_check(const rohc_buf_t buf, const uint32_t min_size_required)
{
    assert(buf.data != NULL);

    if (!rohc_buf_valid(buf))
    {
        fprintf(stderr, "%s:%d, invalid rohc_buf\n", __FUNCTION__, __LINE__);
        return false;
    }
    else if (rohc_buf_free_size(buf) < min_size_required)
    {
        fprintf(stderr, "%s free size not safe %d, min_free %d\n",
                       __FUNCTION__, rohc_buf_free_size(buf), min_size_required);
        return false;
    }

    return true;
}

#ifdef __cplusplus
}
#endif

#endif /* ROHC_BUF_H */


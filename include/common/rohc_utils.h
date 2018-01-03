#ifndef ROHC_COMP_UTILS_H
#define ROHC_COMP_UTILS_H

#ifdef __cplusplus
extern "C"
{
#endif

#include<stdio.h>
#include<assert.h>
#include"rohc_buf.h"

#define ROHC_ENDIAN_SWAP16(x)  ((((uint16_t)(x) & 0xff00)>>8) | (((uint16_t)(x) & 0xff)<<8))

#define ROHC_ENDIAN_SWAP32(x)  ((((uint32_t)(x) & 0xff000000)>>24) | \
                               (((uint32_t)(x) & 0x00ff0000)>>8)  | \
                               (((uint32_t)(x) & 0x0000ff00)<<8)  | \
                               (((uint32_t)(x) & 0x000000ff)<<24))

#define ROHC_NULL_PTR_CHECK_RET(ptr, ret)                                    \
do                                                                           \
{                                                                            \
    if((ptr) == NULL)                                                        \
    {                                                                        \
        fprintf(stderr, "%s, %d Pointer NULL\n", __FUNCTION__, __LINE__);    \
        assert(0);                                                           \
        return (ret);                                                        \
    }                                                                        \
}while (0)

#define ROHC_NULL_PTR_CHECK(ptr)                                             \
do                                                                           \
{                                                                            \
    if((ptr) == NULL)                                                        \
    {                                                                        \
        fprintf(stderr, "%s, %d Pointer NULL\n", __FUNCTION__, __LINE__);    \
        assert(0);                                                           \
        return;                                                              \
    }                                                                        \
}while (0)

#define ROHC_NULL_INDEX_OVFLOW_CHECK(idx, max_idx)                                                   \
do                                                                                                   \
{                                                                                                    \
    if ((idx) >= (max_idx))                                                                          \
    {                                                                                                \
        fprintf(stderr, "%s, Oveflow Idx %d >= max %d\n", __FUNCTION__, __LINE__, (idx), (max_idx)); \
        assert(0);                                                                                   \
        return;                                                                                      \
    }                                                                                                \
}while (0)

#define ROHC_NULL_INDEX_OVFLOW_CHECK_RET(idx, max_idx, ret)                                          \
do                                                                                                   \
{                                                                                                    \
    if ((idx) >= (max_idx))                                                                          \
    {                                                                                                \
        fprintf(stderr, "%s, Oveflow Idx %d >= max %d\n", __FUNCTION__, __LINE__, (idx), (max_idx)); \
        assert(0);                                                                                   \
        return (ret);                                                                                \
    }                                                                                                \
}while (0)

#define IS_POW_OF_2(x) ((((x)) & ((x) - 1)) == 0)

static inline uint16_t rohc_ntoh16(const uint16_t net16)
{
#if WORDS_BIGENDIAN == 1
	return net16;
#else
	return ROHC_ENDIAN_SWAP16(net16);
#endif
}

static inline uint32_t rohc_ntoh32(const uint32_t net32)
{
#if WORDS_BIGENDIAN == 1
	return net32;
#else
	return ROHC_ENDIAN_SWAP32(net32);
#endif

}
static inline uint16_t rohc_htno16(const uint16_t host16)
{
#if WORDS_BIGENDIAN == 1
	return host16;
#else
	return ROHC_ENDIAN_SWAP16(host16);
#endif
}

static inline uint32_t rohc_hton32(const uint32_t host32)
{
#if WORDS_BIGENDIAN == 1
	return host32;
#else
	return ROHC_ENDIAN_SWAP32(host32);
#endif
}

#define  ROHC_ALIGN_1BYTE  __attribute__((packed))
#ifdef __cplusplus
}
#endif

#endif /* ROHC_UTILS_H*/

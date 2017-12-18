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

extern uint16_t rohc_ntoh16(const uint16_t net16);

#define  ROHC_ALIGN_1BYTE  __attribute__((packed))
#ifdef __cplusplus
}
#endif

#endif /* ROHC_UTILS_H*/

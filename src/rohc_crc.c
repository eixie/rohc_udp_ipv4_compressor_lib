#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <stdio.h>

#include "rohc_crc.h"

enum
{
    CRC_3_MASK  = 0x7,
    CRC_7_MASK  = 0x7F,
    CRC_8_MASK  = 0xFF,
};

static struct
{
    uint8_t crc_3[256];
    uint8_t crc_7[256];
    uint8_t crc_8[256];
}g_crc_tables;

static void crc_init_table(uint8_t *const table, const rohc_crc_type_t crc_type)
{
	uint8_t crc;
	uint8_t polynom;
	int i, j;

	assert(table != NULL);

    switch(crc_type)
    {
    case ROHC_CRC_TYPE_3:
        polynom = 0x6;
        break;
    case ROHC_CRC_TYPE_7:
        polynom = 0x79;
        break;
    case ROHC_CRC_TYPE_8:
        polynom = 0xe0;
        break;
    case ROHC_CRC_TYPE_UNKONWN:
    default:
        assert(0);
    }

	for(i = 0; i < 256; i++)
	{
		crc = i;

		for(j = 0; j < 8; j++)
		{
			if(crc & 1)
			{
				crc = (crc >> 1) ^ polynom;
			}
			else
			{
				crc = crc >> 1;
			}
		}

		table[i] = crc;
	}
}

static inline uint8_t fast_crc_cal(const uint8_t *const data,
                                   const uint32_t size,
                                   const uint8_t init_val,
                                   const uint8_t *const crc_table,
                                   const uint8_t mask)
{
	uint8_t crc = init_val;
	uint32_t i;

    assert(data != NULL);

	for(i = 0; i < size; i++)
	{
		crc = crc_table[data[i] ^ (crc & mask)];
	}

	return crc;
}

extern uint8_t rohc_cal_crc(const rohc_crc_type_t crc_type,
                            const uint8_t *const data,
                            const uint32_t length,
                            const uint8_t init_val)
{
    static bool g_crc_tables_inited = false;
	uint8_t crc;

    assert(data != NULL);

    if (!g_crc_tables_inited)
    {
        crc_init_table(g_crc_tables.crc_3, ROHC_CRC_TYPE_3);
        crc_init_table(g_crc_tables.crc_7, ROHC_CRC_TYPE_7);
        crc_init_table(g_crc_tables.crc_8, ROHC_CRC_TYPE_8);
        g_crc_tables_inited = true;
    }

    switch (crc_type)
    {
    case ROHC_CRC_TYPE_8:
        crc = fast_crc_cal(data, length, init_val, g_crc_tables.crc_8, CRC_8_MASK);
        break;
    case ROHC_CRC_TYPE_7:
        crc = fast_crc_cal(data, length, init_val, g_crc_tables.crc_7, CRC_7_MASK);
        break;
    case ROHC_CRC_TYPE_3:
        crc = fast_crc_cal(data, length, init_val, g_crc_tables.crc_3, CRC_3_MASK);
        break;
    case ROHC_CRC_TYPE_UNKONWN:
    default:
        assert(0);
    }

	return crc;
}


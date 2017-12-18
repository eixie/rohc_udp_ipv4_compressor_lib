#ifndef ROHC_COMPRESS_CRC_H
#define ROHC_COMPRESS_CRC_H

#include <stdint.h>
#include <stdbool.h>

enum
{
    CRC_3_INIT_VAL = 0x7,
    CRC_7_INIT_VAL = 0x7f,
    CRC_8_INIT_VAL = 0xff,
};

typedef enum
{
	ROHC_CRC_TYPE_UNKONWN = 0,
	ROHC_CRC_TYPE_3 = 3,
	ROHC_CRC_TYPE_7 = 7,
	ROHC_CRC_TYPE_8 = 8,
}rohc_crc_type_t;

extern uint8_t rohc_cal_crc(const rohc_crc_type_t crc_type,
                            const uint8_t *const data,
                            const uint32_t length,
                            const uint8_t init_val);


#endif /* ROHC_COMPRESS_CRC_H */


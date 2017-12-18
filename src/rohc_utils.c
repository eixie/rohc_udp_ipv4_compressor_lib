#include <stdint.h>
#include "rohc_utils.h"


extern uint16_t rohc_ntoh16(const uint16_t net16)
{
#if WORDS_BIGENDIAN == 1
	return net16;
#else
	return ROHC_ENDIAN_SWAP16(net16);
#endif

}

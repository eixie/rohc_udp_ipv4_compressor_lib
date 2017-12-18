#include "rohc_packet.h"

const char * rohc_get_packet_descr(const rohc_packet_t packet_type)
{
	switch(packet_type)
    {
    case ROHC_PACKET_IR:
        return "IR";
    case ROHC_PACKET_IR_DYN:
        return "IR-DYN";
    case ROHC_PACKET_UO_0:
        return "UO-0";
    case ROHC_PACKET_UO_1:
        return "UO-1";
    case ROHC_PACKET_UOR_2:
        return "UOR-2";
    default:
        return "unknown ROHC packet";
    }

    return "unknown ROHC packet";
}

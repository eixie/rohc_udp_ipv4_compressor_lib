#ifndef ROHC_COMP_PACKETS_H
#define ROHC_COMP_PACKETS_H

#ifdef __cplusplus
extern "C"
{
#endif

typedef enum
{
    ROHC_PACKET_IR        = 0, /**< ROHC IR packet */
    ROHC_PACKET_IR_DYN    = 1, /**< ROHC IR-DYN packet */
    ROHC_PACKET_UO_0      = 2, /**< ROHC UO-0 packet */
    ROHC_PACKET_UO_1      = 3, /**< ROHC UO-1 packet (for all non-RTP profiles) */
    ROHC_PACKET_UOR_2     = 4, /**< ROHC UOR-2 packet (for all non-RTP profiles) */
    ROHC_PACKET_UNKNOWN   = 5, /**< Unknown packet type */
    ROHC_PACKET_MAX            /**< The number of packet types */
} rohc_packet_t;

enum
{
    UO_0_SN_BITS    = 4,
    UO_1_SN_BITS    = 5,
    UO_1_IP_ID_BITS = 6,
    UOR_2_SN_BITS   = 5,
};

enum packet_type_preamble
{
    ROHC_IR_PREAMBLE_CODE       = 0xFD, //0x1111,1101
    ROHC_IR_NO_D_PREAMBLE_CODE  = 0xFC, //0x1111,1100
    ROHC_IR_DYN_PREAMBLE_CODE   = 0xF8, //0x1111,1000
    ROHC_UOR_2_PREAMBLE_CODE    = 0xC0, //0x110 sn[4:0]
    ROHC_UO_1_PREAMBLE_CODE     = 0x80, //0x10 IP-ID[5:0]
    ROHC_UO_0_PREAMBLE_CODE     = 0x00, //0x0 sn[6:3] crc[2:0]
};

static inline const char * rohc_get_packet_type_str(const rohc_packet_t packet_type)
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

#ifdef __cplusplus
}
#endif

#endif /* ROHC_COMP_PACKETS_H */


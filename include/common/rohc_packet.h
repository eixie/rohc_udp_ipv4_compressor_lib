#ifndef ALP_ROHC_PACKETS_H
#define ALP_ROHC_PACKETS_H

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

enum
{
    ROHC_IR_PREAMBLE_CODE       = 0xFC, //0x1111,110D
    ROHC_IR_DYN_PREAMBLE_CODE   = 0xF8, //0x1111,1000
    ROHC_IR_UOR_2_PREAMBLE_CODE = 0xC0, //0x110 sn[4:0]
    ROHC_IR_UO_1_PREAMBLE_CODE  = 0x80, //0x10 IP-ID[5:0]
    ROHC_IR_UO_0_PREAMBLE_CODE  = 0x00, //0x0 sn[6:3] crc[2:0]
};

#ifdef ALP_ROHC_DLL_EXPORT
#define ALP_ROHC_EXPORT __declspec(dllexport)
#else
#define ALP_ROHC_EXPORT
#endif

const char* ALP_ROHC_EXPORT alp_rohc_get_packet_descr(const rohc_packet_t packet_type);

rohc_packet_t ALP_ROHC_EXPORT alp_rohc_get_packet_type(const char *const packet_id);


#undef ALP_ROHC_EXPORT

#ifdef __cplusplus
}
#endif

#endif /* ALP_ROHC_PACKETS_H */


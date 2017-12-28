#ifndef ROHC_IP_V4_H
#define ROHC_IP_V4_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>

#define IPV4_HEADER_VER_HL  (0x45)
#define IPV4_DF             (0x4000)
#define IP_PROTOCOL_UDP     (17)
#define IP_MAX_IP_ID        (0xFFFFU)
#define IP_PACKET_MAX_LEN   (0xFFFFU)

#pragma pack(1)
typedef struct ipv4_header
{
	uint8_t  ver_hl;
	uint8_t  tos;
	uint16_t tot_len;
	uint16_t id;
	uint16_t frag_info;  /**< Fragment flags and Fragment offset*/
	uint8_t  ttl;
	uint8_t  prot;
	uint16_t csum;
	uint32_t src_addr;
	uint32_t dst_addr;
}ipv4_header_t;
#pragma pack()

extern uint16_t ip_v4_calc_checksum(const uint16_t *data, uint32_t length);
extern bool ip_v4_is_fragment(const ipv4_header_t *const ip_hdr);
#ifdef __cplusplus
}
#endif

#endif /* ROHC_IP_V4_H */

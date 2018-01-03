#ifndef ROHC_UDP_H
#define ROHC_UDP_H

#pragma pack(1)
typedef struct
{
	uint16_t src;
	uint16_t dest;
	uint16_t len;
	uint16_t csum;
}udp_header_t;
#pragma pack()

#endif /*ROHC_UDP_H */

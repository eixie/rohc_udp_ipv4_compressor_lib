#ifndef ALP_NETWORK_PACKET_H
#define ALP_NETWORK_PACKET_H

#include <stdint.h>
#include <stdbool.h>

#include "ip_v4.h"
#include "udp.h"

typedef struct network_packet
{
    const uint8_t  *ip_data; /* playload of ip */
    uint32_t       ip_len;   /* ip header + ip payload length*/

    const uint8_t  *udp_data; /* payload of udp*/
    uint32_t       udp_payload_len;
    uint32_t       udp_len;   /* udp header + udp payload length */


    ipv4_header_t  ip_hdr;
    udp_header_t   udp_hdr;
}network_packet_t;

extern bool parse_net_packet(network_packet_t *const net_pkt,
                             const uint8_t * const data,
                             uint32_t size);

#endif /* ALP_NETWORK_PACKET_H */

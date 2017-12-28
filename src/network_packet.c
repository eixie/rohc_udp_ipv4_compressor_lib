#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "rohc_utils.h"
#include "rohc_log.h"
#include "network_packet.h"

extern bool parse_net_packet(network_packet_t *const net_pkt,
                             const uint8_t * const data,
                             uint32_t len)
{
    ROHC_NULL_PTR_CHECK_RET(net_pkt, false);
    ROHC_NULL_PTR_CHECK_RET(net_pkt, false);

    if (len < (sizeof(ipv4_header_t) + sizeof(udp_header_t)))
    {
        ROHC_LOG_WARN("len %d too short for udpIp packet\n", len);
        return false;
    }
    else if (*data != IPV4_HEADER_VER_HL)
    {
        ROHC_LOG_WARN("first data not 0x45, but 0x%x\n", *data);
        return false;
    }

    net_pkt->ip_data = data;
    net_pkt->ip_len = len;

    memcpy(&net_pkt->ip_hdr, data, sizeof(ipv4_header_t));

#if 0
    ROHC_LOG_DEBUG("ip header dump\n[0~7]: 0x%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x\n",
                   data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]);

    ROHC_LOG_DEBUG("[8~15]: 0x%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x\n",
                   data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15]);

    ROHC_LOG_DEBUG("[16~23]: 0x%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x\n",
                   data[16], data[17], data[18], data[19], data[20], data[21], data[22], data[23]);

    ROHC_LOG_DEBUG("[24~17]: 0x%02x-%02x-%02x-%02x\n",
                   data[24], data[25], data[26], data[27]);
#endif

    if (rohc_ntoh16(net_pkt->ip_hdr.tot_len) != net_pkt->ip_len)
    {
        ROHC_LOG_WARN("mismatch, ip pkt len %d, real data len %d\n",
                      rohc_ntoh16(net_pkt->ip_hdr.tot_len), net_pkt->ip_len);
        return false;
    }
    else if (ip_v4_is_fragment(&net_pkt->ip_hdr))
    {
        ROHC_LOG_WARN("rohc does not support fragment\n");
        return false;
    }
    else if (net_pkt->ip_hdr.prot != IP_PROTOCOL_UDP)
    {
        ROHC_LOG_WARN("ip protocol(%d) is not udp(17)\n",
                      net_pkt->ip_hdr.prot);
        return false;
    }
    else if (ip_v4_calc_checksum((const uint16_t *)data, sizeof(ipv4_header_t)) != 0x0)
    {
        ROHC_LOG_WARN("ip bad checksum hdr: 0x%04x\n", net_pkt->ip_hdr.csum);
        return false;
    }

    //check udp
    net_pkt->udp_data = data + sizeof(ipv4_header_t);
    net_pkt->udp_len  = len - sizeof(ipv4_header_t);
    net_pkt->udp_payload_len = net_pkt->udp_len  - 8;

    memcpy(&net_pkt->udp_hdr, net_pkt->udp_data, sizeof(udp_header_t));

    if (rohc_ntoh16(net_pkt->udp_hdr.len) != net_pkt->udp_len)
    {
        ROHC_LOG_WARN("mismatch, udp pkt len %d, real data len %d\n",
                      rohc_ntoh16(net_pkt->udp_hdr.len), net_pkt->udp_len);
        return false;
    }

    return true;
}


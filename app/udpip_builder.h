#ifndef ROHC_COMP_APP_UDP_IP_BUILDER_H
#define ROHC_COMP_APP_UDP_IP_BUILDER_H

#include <stdint.h>

extern bool build_udp_ip_headers(uint8_t *const pkt_buf_start,
                                 const uint8_t *const data,
                                 const uint16_t payload_len,
                                 const uint32_t src_addr,
                                 const uint32_t dst_addr,
                                 const uint16_t src_port,
                                 const uint16_t dst_port,
                                 const uint16_t id);
#endif /* ROHC_COMP_APP_UDP_IP_BUILDER_H */

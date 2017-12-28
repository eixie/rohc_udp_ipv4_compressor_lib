#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <string.h>

#include "ip_v4.h"
#include "udp.h"
#include "rohc_log.h"
#include "rohc_utils.h"

typedef struct
{
    uint32_t src_addr;
    uint32_t dst_addr;
    uint16_t proto;
    uint16_t len;
} __attribute__((packed)) udp_dummy_header_t;

typedef struct
{
    udp_dummy_header_t dummy;
    udp_header_t real;

}__attribute__((packed)) udp_full_header_t;


static uint16_t calc_checksum(const uint16_t *data, uint32_t length)
{
    uint16_t csum = 0;
    uint32_t sum = 0;

    if (data != NULL)
    {
        while (length > 1)
        {
            sum += (*data);
            ++data;
            length -= sizeof(uint16_t);
        }

        if (length == 1)
        {
            sum += *(uint8_t *)data;
        }

        while (sum >> 16)
        {
            sum = (sum >> 16) + (sum & 0xffff);
        }

        csum = (uint16_t)(~sum);
    }

    return csum;
}

static udp_full_header_t build_full_udp_header(const uint16_t udp_tot_len,
                                               const uint32_t src_addr,
                                               const uint32_t dst_addr,
                                               const uint16_t src_port,
                                               const uint16_t dst_port)
{
    udp_full_header_t full_hdr;

    full_hdr.dummy.src_addr = src_addr;
    full_hdr.dummy.dst_addr = dst_addr;
    full_hdr.dummy.proto    = ROHC_ENDIAN_SWAP16(IP_PROTOCOL_UDP);
    full_hdr.dummy.len      = ROHC_ENDIAN_SWAP16(udp_tot_len);

    full_hdr.real.src       = ROHC_ENDIAN_SWAP16(src_port);
    full_hdr.real.dest      = ROHC_ENDIAN_SWAP16(dst_port);
    full_hdr.real.len       = ROHC_ENDIAN_SWAP16(udp_tot_len);
    full_hdr.real.csum      = 0;

    ROHC_LOG_DEBUG("UDP Hdr SrcPort %d, Dst Port %d, Len %d\n", src_port, dst_port, udp_tot_len);

    return full_hdr;
}

static bool udp_create_header(uint8_t *const udp_header_start,
                              const uint16_t udp_tot_len,
                              const uint32_t src_addr,
                              const uint32_t dst_addr,
                              const uint32_t src_port,
                              const uint32_t dst_port)
{
    udp_full_header_t header;

    assert(udp_header_start != NULL);

    if (udp_header_start == NULL)
    {
        ROHC_LOG_ERROR("%s, udp_header_start NULL\n", __FUNCTION__);
        return false;
    }

    header = build_full_udp_header(udp_tot_len, src_addr, dst_addr, src_port, dst_port);

    memcpy(udp_header_start, (uint8_t *)&header, sizeof(udp_full_header_t));

    header.real.csum = calc_checksum((const uint16_t *)udp_header_start,
                                     udp_tot_len + sizeof(udp_dummy_header_t));

    memcpy(udp_header_start, (uint8_t *)&header, sizeof(udp_full_header_t));

    return true;
}

static ipv4_header_t build_ipv4_header(const uint16_t ip_tot_len,
                                            const uint32_t src_addr,
                                            const uint32_t dst_addr,
                                            const uint8_t  prot,
                                            const uint16_t id)
{
    ipv4_header_t hdr;

    hdr.ver_hl     = IPV4_HEADER_VER_HL;
    hdr.tos        = 0;
    hdr.tot_len    = ROHC_ENDIAN_SWAP16(ip_tot_len);
    hdr.id         = ROHC_ENDIAN_SWAP16(id);
    hdr.frag_info  = 0;
    hdr.ttl        = 128;//0xFF;
    hdr.prot       = prot;
    hdr.csum       = 0;
    hdr.src_addr   = src_addr;
    hdr.dst_addr   = dst_addr;

    hdr.csum = calc_checksum((const uint16_t *)(&hdr), sizeof(ipv4_header_t));

    ROHC_LOG_DEBUG("Ip hdr: Len %d, id %d csum0x%08x, SrcIpAddr 0x%08x, DstIpAddr 0x%x\n",
                  ip_tot_len, id, hdr.csum, hdr.src_addr, hdr.dst_addr);

    return hdr;
}

static bool ipv4_create_header(uint8_t *const ip_header_start,
                               const uint16_t ip_tot_len,
                               const uint32_t src_addr,
                               const uint32_t dst_addr,
                               const uint8_t  prot,
                               const uint16_t id)
{
    ipv4_header_t headr;

    if (ip_header_start == NULL)
    {
        ROHC_LOG_ERROR("%s, udp_header_start NULL\n", __FUNCTION__);
        return false;
    }

    headr = build_ipv4_header(ip_tot_len, src_addr, dst_addr, prot, id);

    memcpy(ip_header_start, (uint8_t *)&headr, sizeof(ipv4_header_t));

    return true;
}

extern bool build_udp_ip_headers(uint8_t *const pkt_buf_start,
                                 const uint8_t *const data,
                                 const uint16_t payload_len,
                                 const uint32_t src_addr,
                                 const uint32_t dst_addr,
                                 const uint32_t src_port,
                                 const uint32_t dst_port,
                                 const uint16_t id)
{
    bool create = false;

    uint16_t tot_hdr_len = sizeof(ipv4_header_t) + sizeof(udp_header_t);
    uint16_t udp_tot_len = payload_len + sizeof(udp_header_t);
    uint16_t ip_tot_len  = payload_len + tot_hdr_len;

    uint16_t udp_dummpy_ofst_from_ip_start =
        sizeof(ipv4_header_t) - sizeof(udp_dummy_header_t);


    assert(pkt_buf_start != NULL);
    assert(data != NULL);

    memcpy(pkt_buf_start + tot_hdr_len, data, payload_len);

    create = udp_create_header(pkt_buf_start + udp_dummpy_ofst_from_ip_start,
                               udp_tot_len,
                               src_addr,
                               dst_addr,
                               src_port,
                               dst_port);
    if (!create)
    {
        ROHC_LOG_ERROR("%s, udp_create_header fail\n", __FUNCTION__);
        return false;
    }

    create = ipv4_create_header(pkt_buf_start,
                                ip_tot_len,
                                src_addr,
                                dst_addr,
                                IP_PROTOCOL_UDP,
                                id);

    if (!create)
    {
        ROHC_LOG_ERROR("%s, ipv4_create_header fail\n", __FUNCTION__);
        return false;
    }

    return true;
}

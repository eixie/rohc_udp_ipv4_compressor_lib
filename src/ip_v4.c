#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <assert.h>

#include "rohc_utils.h"
#include "ip_v4.h"

extern uint16_t ip_v4_calc_checksum(const uint16_t *data, uint32_t length)
{
    uint16_t checksum = 0;
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

        checksum = (uint16_t)(~sum);
    }

    return checksum;
}

extern bool ip_v4_is_fragment(const ipv4_header_t *const ip_hdr)
{
    return ((rohc_ntoh16(ip_hdr->frag_info) & (~IPV4_DF)) != 0);
}

extern inline uint16_t ip_v4_get_id_nbo(const ipv4_header_t *const ip_hdr, const bool nbo)
{
    assert(ip_hdr != NULL);
    return (nbo ? ip_hdr->id : ROHC_ENDIAN_SWAP16(ip_hdr->id));
}


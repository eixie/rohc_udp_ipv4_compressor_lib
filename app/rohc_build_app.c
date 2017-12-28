#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#if 1//__LINUX__
#include <arpa/inet.h>
#else
#include <winsock2.h>
#endif

#include "rohc_buf.h"
#include "rohc_comp.h"
#include "rohc_log.h"
#include "rohc_utils.h"
#include "ip_v4.h"
#include "udp.h"
#include "udpip_builder.h"

static void gen_pcap_global_header(uint8_t *const pcap_buf, uint8_t *const pcap_g_hdr_size)
{
    const uint8_t pcap_global_hdr[24] =
    {
        0x4D, 0x3C, 0xB2, 0xA1, 0x02, 0x00, 0x04, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x04, 0x00, 0x65, 0x00, 0x00, 0x00,
    };

    ROHC_NULL_PTR_CHECK(pcap_buf);
    ROHC_NULL_PTR_CHECK(pcap_g_hdr_size);

    memcpy(pcap_buf, pcap_global_hdr, 24);
    *pcap_g_hdr_size = 24;
}

static void gen_pcap_packet_header(uint8_t *const pcap_buf,
                                   uint8_t *const pcap_pkt_hdr_size,
                                   const uint32_t pcap_pkt_hdr_rec_len,
                                   const uint32_t pcap_pkt_hdr_act_len)
{
    const uint8_t pcap_pkt_hdr_fix_part[8] =
    {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };

    ROHC_NULL_PTR_CHECK(pcap_buf);
    ROHC_NULL_PTR_CHECK(pcap_pkt_hdr_size);

    memcpy(pcap_buf, pcap_pkt_hdr_fix_part, 8);
    memcpy(pcap_buf + 8 ,  (const uint8_t *)(&pcap_pkt_hdr_rec_len), 4);
    memcpy(pcap_buf + 12 , (const uint8_t *)(&pcap_pkt_hdr_act_len), 4);

    *pcap_pkt_hdr_size = 16;
}

static uint16_t gen_udp_ipv4_payload(uint8_t *const payload,
                                     const uint16_t min_size,
                                     const uint16_t max_size,
                                     const bool fix_len,
                                     const bool rand_data)
{
    uint16_t payload_len;
    uint16_t i;

    ROHC_NULL_PTR_CHECK_RET(payload, 0);

    if (!fix_len)
    {
        assert(min_size <= max_size);
        payload_len = rand() % (max_size - min_size + 1) + min_size;
    }
    else
    {
        payload_len = min_size;
    }

    if (!rand_data)
    {
    	static uint8_t pkt_data = 0;
        memset(payload, pkt_data++, payload_len);
    }
    else
    {
        for (i = 0; i < payload_len; ++i)
        {
            payload[i] = (uint8_t)rand();
        }
    }

    return payload_len;
}

#define IP_PACKET_SIZE_MAX    64 * 1024
#define IP_PACKET_PAYLOAD_MAX  (IP_PACKET_SIZE_MAX - 28)
static uint8_t g_ip_buffer[IP_PACKET_SIZE_MAX];
static uint8_t g_payload_buffer[IP_PACKET_PAYLOAD_MAX];

#define ROHC_PACKET_SIZE_MAX 64 *1024
static uint8_t g_rohc_buffer[ROHC_PACKET_SIZE_MAX];

#define PCAP_PACKET_MAX_SIZE (64*1024 + 128)
unsigned char g_pcap_buffer[PCAP_PACKET_MAX_SIZE];

static void run_alp_build(uint32_t total_pkt_cnt)
{
    const char *src_addr_str = "172.26.150.77";
    const char *dst_addr_str = "172.26.150.57";

    const uint32_t src_addr = (uint32_t)inet_addr(src_addr_str); //big endian
    const uint32_t dst_addr = (uint32_t)inet_addr(dst_addr_str); //big endian
    const uint16_t src_port = 51040;
    const uint16_t dst_port = 5003;

    FILE *fp_udp_ip_dump = fopen("udp_ip_packet.bin", "w");
    FILE *fp_rohc_dump   = fopen("rohc_packet.bin", "w");
    FILE *fp_rohc_pkt_len_dump = fopen("rohc_packet_len_rec.bin", "w");
    FILE *fp_pcap_dump   = fopen("udp_ip_pcap_packet.pcap", "w");

    uint32_t i = 0;
    bool   first_packet = true;
    uint32_t tot_pcap_pkt_size = 0;
    uint8_t pcap_global_hdr_size = 0;
    uint8_t pcap_pkt_hdr_size = 0;

    rohc_buf_t ip_pkt;
    rohc_buf_t rohc_pkt;
    rohc_comp_index_t comp_idx = rohc_allocate_compressor(ROHC_LARGE_CID, 10, 8, 20, 500, 100);
    rohc_comp_packet_info_t rohc_info;
    rohc_status_t ret;

    char rohc_pkt_len_str[8];
    uint16_t id = 0;

    for (i = 0; i < total_pkt_cnt; ++i)
    {
        uint16_t payload_len = gen_udp_ipv4_payload(g_payload_buffer, 100, 100, false, false);
        uint16_t ip_tot_len;

        if ((uint32_t)payload_len + 28 >= IP_PACKET_MAX_LEN)
        {
            continue;
        }

        ip_tot_len = payload_len + 28;


        rohc_buf_clear(&rohc_pkt);


        build_udp_ip_headers(g_ip_buffer, g_payload_buffer, payload_len,
                             src_addr, dst_addr, src_port, dst_port, id);

        //id += rand()%2 + 1;
        ++id;

        ROHC_LOG_DEBUG("ip packet[%d] len - %d\n", (i+1), ip_tot_len);
        fwrite(g_ip_buffer, ip_tot_len, 1, fp_udp_ip_dump);
        ip_pkt = rohc_buf_init(g_ip_buffer, ip_tot_len, false);

        tot_pcap_pkt_size = 0;
        pcap_global_hdr_size = 0;

        if (first_packet)
        {
            gen_pcap_global_header(g_pcap_buffer, &pcap_global_hdr_size);
            first_packet = false;
        }

        pcap_pkt_hdr_size = 0;

        gen_pcap_packet_header(g_pcap_buffer + pcap_global_hdr_size,
                               &pcap_pkt_hdr_size, ip_tot_len, ip_tot_len);


        memcpy(g_pcap_buffer + pcap_global_hdr_size + pcap_pkt_hdr_size, g_ip_buffer, ip_tot_len);
        tot_pcap_pkt_size = pcap_global_hdr_size + pcap_pkt_hdr_size + ip_tot_len;

        fwrite(g_pcap_buffer, tot_pcap_pkt_size, 1, fp_pcap_dump);

        rohc_pkt = rohc_buf_init(g_rohc_buffer, ROHC_PACKET_SIZE_MAX, true);
        ret = rohc_compress(comp_idx, &rohc_pkt, &rohc_info, ip_pkt);

        if (ret != ROHC_STATUS_OK)
        {
            ROHC_LOG_ERROR("rohc compress ret %d fail\n", (uint32_t)ret);
        }

        ROHC_LOG_DEBUG("last rohc pkt info: "
                       "SN%d, ip_id %d, pktType %d, cid %d, cid type%d, static size %d, dyn size%d\n",
                       rohc_info.SN,
                       ROHC_ENDIAN_SWAP16(rohc_info.ip_id),
                       rohc_info.packet_type,
                       rohc_info.cid,
                       rohc_info.cid_type,
                       rohc_info.dynamic_context_size,
                       rohc_info.static_context_size);

        snprintf(rohc_pkt_len_str, 7, "%d\n", (uint32_t)rohc_pkt.len);
        fwrite(rohc_pkt_len_str, strlen(rohc_pkt_len_str), 1, fp_rohc_pkt_len_dump);
        fwrite(rohc_buf_get_pointer(rohc_pkt, 0), rohc_pkt.len, 1, fp_rohc_dump);
    }

    rohc_release_compressor(comp_idx);

    fflush(fp_pcap_dump);
    fflush(fp_udp_ip_dump);
    fflush(fp_rohc_dump);
    fflush(fp_rohc_pkt_len_dump);

    fclose(fp_pcap_dump);
    fclose(fp_udp_ip_dump);
    fclose(fp_rohc_dump);
    fclose(fp_rohc_pkt_len_dump);
}

int main(int argc, char *argv[])
{
    uint32_t total_pkt_cnt = 1200; //default 10000 packet

    if (argc >= 2)
    {
        total_pkt_cnt = atoi(argv[1]);
    }

    ROHC_LOG_INFO("start build %d random udp_ip packet/pcap and rohc pkt", total_pkt_cnt);

    run_alp_build(total_pkt_cnt);
}

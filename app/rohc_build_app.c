#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <time.h>

#if __LINUX__
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

#define IP_PACKET_SIZE_MAX    (64 * 1024)
#define IP_PACKET_PAYLOAD_MAX  (IP_PACKET_SIZE_MAX - 28)
#define ROHC_PACKET_SIZE_MAX (64 *1024)
#define PCAP_PACKET_MAX_SIZE (64*1024 + 128)

#define IO_DATA_CACHE_BUF_FULL_SIZE (2 * 1024 * 1024) //2M
#define IO_DATA_CACHE_BUF_TOTAL_SIZE (IO_DATA_CACHE_BUF_FULL_SIZE + IP_PACKET_SIZE_MAX)

#define IO_LEN_REC_CACHE_BUF_FULL_SIZE (128 * 1024)
#define IO_LEN_REC_CACHE_BUF_TOTAL_SIZE (IO_LEN_REC_CACHE_BUF_FULL_SIZE + 32)

typedef enum
{
    IP_ID_SEQUENTIAL_INC  = 0,
    IP_ID_SEQUENTIAL_JUMP = 1,
    IP_ID_STATIC_IP_ID    = 2,
    IP_ID_RANDOM          = 3,
}IP_ID_BEHAVIOR_E;

struct rohc_test_config
{
    rohc_cid_type_t cid_type;
    uint8_t strm_num;
    uint32_t send_round;
    uint16_t payload_min;
    uint16_t payload_max;
    IP_ID_BEHAVIOR_E ip_id_behave;
    uint32_t sim_pkt_loss_start_pkt;
    uint32_t sim_pkt_loss_end_pkt;
};

typedef struct
{
    uint32_t src_addr;
    uint32_t dst_addr;
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t ip_id;
    size_t   packet_cnt;
}udp_ip_stream_cfg_t;

struct rohc_comp_test_context
{
    FILE *fp_udp_ip_dump;
    FILE *fp_rohc_dump;
    FILE *fp_rohc_pkt_len_dump;
    FILE *fp_pcap_dump;

    uint8_t comp_idx;
    udp_ip_stream_cfg_t cfg[1];
};

typedef enum
{
    CACHE_DUMP_IP = 0,
    CACHE_DUMP_ROHC = 1,
    CACHE_DUMP_ROHC_LEN = 2,
    CACHE_DUMP_PCAP = 3,
    CACHE_DUMP_FLUSH = 4,
    CACHE_DUMP_INIT = 5,
}cache_dump_type_t;

static inline void flush_cache_to_file(rohc_buf_t *const cache, FILE *fp)
{
    if ((cache != NULL) && (fp != NULL))
    {
        if (rohc_buf_get_data_size(*cache) > 0)
        {
            fwrite(rohc_buf_get_pointer(*cache, 0), rohc_buf_get_data_size(*cache), 1, fp);
            fflush(fp);
            rohc_buf_clear(cache);
        }
    }
}

static void cache_file_write(struct rohc_comp_test_context *ctx,
                             const cache_dump_type_t cache_type,
                             const rohc_buf_t *const src_buf)
{
    static uint8_t g_ip_cache_buf[IO_DATA_CACHE_BUF_TOTAL_SIZE];
    static uint8_t g_pcap_cache_buf[IO_DATA_CACHE_BUF_TOTAL_SIZE];
    static uint8_t g_rohc_cache_buf[IO_DATA_CACHE_BUF_TOTAL_SIZE];
    static uint8_t g_rohc_len_rec_cache_buf[IO_LEN_REC_CACHE_BUF_TOTAL_SIZE];

    static rohc_buf_t ip_cache;
    static rohc_buf_t pcap_cache;
    static rohc_buf_t rohc_cache;
    static rohc_buf_t rohc_len_rec_cache;

    if (cache_type == CACHE_DUMP_INIT)
    {
        ip_cache   = rohc_buf_init(g_ip_cache_buf, IO_DATA_CACHE_BUF_TOTAL_SIZE, true);
        pcap_cache = rohc_buf_init(g_pcap_cache_buf, IO_DATA_CACHE_BUF_TOTAL_SIZE, true);
        rohc_cache = rohc_buf_init(g_rohc_cache_buf, IO_DATA_CACHE_BUF_TOTAL_SIZE, true);
        rohc_len_rec_cache = rohc_buf_init(g_rohc_len_rec_cache_buf, IO_LEN_REC_CACHE_BUF_TOTAL_SIZE, true);
        printf("init cache buffer\n");
    }
    else if (cache_type == CACHE_DUMP_FLUSH)
    {
        flush_cache_to_file(&ip_cache, ctx->fp_udp_ip_dump);
        flush_cache_to_file(&rohc_cache, ctx->fp_rohc_dump);
        flush_cache_to_file(&pcap_cache, ctx->fp_pcap_dump);
        flush_cache_to_file(&rohc_len_rec_cache, ctx->fp_rohc_pkt_len_dump);
        printf("flush cache buffer to file\n");
    }
    else
    {
        if (rohc_buf_get_data_size(ip_cache) >= IO_DATA_CACHE_BUF_FULL_SIZE)
        {
            ROHC_LOG_DEBUG("udp-ip data full %d, flush cache\n",
                           rohc_buf_get_data_size(ip_cache));
            flush_cache_to_file(&ip_cache, ctx->fp_udp_ip_dump);
        }

        if (rohc_buf_get_data_size(pcap_cache) >= IO_DATA_CACHE_BUF_FULL_SIZE)
        {
            ROHC_LOG_DEBUG("pcap data full %d, flush cache\n",
                           rohc_buf_get_data_size(pcap_cache));
            flush_cache_to_file(&pcap_cache, ctx->fp_pcap_dump);
        }

        if (rohc_buf_get_data_size(rohc_cache) >= IO_DATA_CACHE_BUF_FULL_SIZE)
        {
            ROHC_LOG_DEBUG("rohc data full %d, flush cache\n",
                           rohc_buf_get_data_size(rohc_cache));
            flush_cache_to_file(&rohc_cache, ctx->fp_rohc_dump);
        }

        if (rohc_buf_get_data_size(rohc_len_rec_cache) >= IO_LEN_REC_CACHE_BUF_FULL_SIZE)
        {
            ROHC_LOG_DEBUG("rohc data full %d, flush cache\n",
                           rohc_buf_get_data_size(rohc_len_rec_cache));
            flush_cache_to_file(&rohc_len_rec_cache, ctx->fp_rohc_pkt_len_dump);
        }
    }

    if (src_buf != NULL)
    {
        switch (cache_type)
        {
        case CACHE_DUMP_IP:
            ROHC_LOG_DEBUG("new ip data type size %d, buf size %d\n",
                           rohc_buf_get_data_size(*src_buf),
                           rohc_buf_get_data_size(ip_cache));
            if (!rohc_buf_append_buf(&ip_cache, *src_buf))
            {
                assert(0);
            }
            break;

        case CACHE_DUMP_PCAP:
            ROHC_LOG_DEBUG("new pcap data type size %d, buf size %d\n",
                           rohc_buf_get_data_size(*src_buf),
                           rohc_buf_get_data_size(pcap_cache));
            if (!rohc_buf_append_buf(&pcap_cache, *src_buf))
            {
                assert(0);
            }
            break;

        case CACHE_DUMP_ROHC:
            ROHC_LOG_DEBUG("new rohc data type size %d, buf size %d\n",
                           rohc_buf_get_data_size(*src_buf),
                           rohc_buf_get_data_size(rohc_cache));
            if (!rohc_buf_append_buf(&rohc_cache, *src_buf))
            {
                assert(0);
            }
            break;

        case CACHE_DUMP_ROHC_LEN:
            ROHC_LOG_DEBUG("new len_rec data type size %d, buf size %d\n",
                           rohc_buf_get_data_size(*src_buf),
                           rohc_buf_get_data_size(rohc_len_rec_cache));

            if (!rohc_buf_append_buf(&rohc_len_rec_cache, *src_buf))
            {
                assert(0);
            }
            break;
        default:
            break;
        }
    }
}

static void gen_pcap_global_header(rohc_buf_t *const pcap_buf)
{
    const uint8_t pcap_global_hdr[24] =
    {
        0x4D, 0x3C, 0xB2, 0xA1, 0x02, 0x00, 0x04, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x04, 0x00, 0x65, 0x00, 0x00, 0x00,
    };

    ROHC_NULL_PTR_CHECK(pcap_buf);

    if (!rohc_buf_append(pcap_buf, pcap_global_hdr, 24))
    {
        assert(0);
    }
}

static void pack_pcap_packet_header(rohc_buf_t *const pcap_buf,
                                    const uint32_t pcap_pkt_hdr_rec_len,
                                    const uint32_t pcap_pkt_hdr_act_len)
{
    uint8_t pcap_pkt_hdr[16];
    const uint8_t pcap_pkt_hdr_fix_part[8] =
    {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };

    ROHC_NULL_PTR_CHECK(pcap_buf);

    memcpy(pcap_pkt_hdr, pcap_pkt_hdr_fix_part, 8);
    memcpy(pcap_pkt_hdr + 8,  (const uint8_t *)(&pcap_pkt_hdr_rec_len), 4);
    memcpy(pcap_pkt_hdr + 12, (const uint8_t *)(&pcap_pkt_hdr_act_len), 4);

    if (!rohc_buf_append(pcap_buf, pcap_pkt_hdr, 16))
    {
        assert(0);
    }
}


static void pack_pcap_packet(struct rohc_comp_test_context *ctx, rohc_buf_t ip_pkt)
{
    static bool add_pcap_global_hdr = true;
    static uint8_t g_pcap_buf[PCAP_PACKET_MAX_SIZE];

    rohc_buf_t pcap_pkt = rohc_buf_init(g_pcap_buf, PCAP_PACKET_MAX_SIZE, true);

    if (add_pcap_global_hdr)
    {
        gen_pcap_global_header(&pcap_pkt);
        add_pcap_global_hdr = false;
    }

    pack_pcap_packet_header(&pcap_pkt, ip_pkt.len, ip_pkt.len);

    if (!rohc_buf_append_buf(&pcap_pkt, ip_pkt))
    {
        assert(0);
    }

    cache_file_write(ctx, CACHE_DUMP_PCAP, &pcap_pkt);
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

static struct rohc_comp_test_context* test_init(const struct rohc_test_config  test_cfg)
{
    rohc_cid_type_t cid_type = test_cfg.cid_type;

    struct rohc_comp_test_context *ctx = NULL;
    char src_addr[32];
    char dst_addr[32];

    uint16_t k;
    uint32_t alloc_size = sizeof(struct rohc_comp_test_context);

    if (test_cfg.strm_num > 1)
    {
        alloc_size += (test_cfg.strm_num - 1) * sizeof(udp_ip_stream_cfg_t);
    }

    ctx = (struct rohc_comp_test_context *)malloc(alloc_size);

    if (ctx == NULL)
    {
        ROHC_LOG_ERROR("%s, fail to allocate rohc comp test memory\n", __FUNCTION__);
        return NULL;
    }

    memset(ctx, 0, sizeof(alloc_size));

    ctx->fp_udp_ip_dump = fopen("udp_ip_dump.bin", "wb");
    ctx->fp_pcap_dump   = fopen("udp_ip.pcap", "wb");
    ctx->fp_rohc_dump   = fopen("rohc_dump.bin", "wb");
    ctx->fp_rohc_pkt_len_dump = fopen("rohc_packet_len_rec.bin", "w");

    cache_file_write(ctx, CACHE_DUMP_INIT, NULL);

    if ((cid_type == ROHC_SMALL_CID) && (test_cfg.strm_num >= 16))
    {
        ROHC_LOG_INFO("adjust to large CID case due to strm num exceeds small cid max");
        cid_type = ROHC_LARGE_CID;
    }

    ctx->comp_idx = rohc_allocate_compressor(test_cfg.cid_type,
                                             test_cfg.strm_num - 1, // max_cid
                                             8,   // sn window size 2^k
                                             8,   // ip id window size 2^k
                                             500, //IR down trans timetou
                                             100); //fo down trans timetou

    for (k = 0; k < test_cfg.strm_num; ++k)
    {
        ctx->cfg[k].src_addr = rohc_hton32(k + 0xC0A80000);
        ctx->cfg[k].dst_addr = rohc_hton32(k + 0xE0F00000);
        ctx->cfg[k].src_port = k + 3000;
        ctx->cfg[k].dst_port = k + 4000;

        if (test_cfg.ip_id_behave == IP_ID_STATIC_IP_ID)
        {
            ctx->cfg[k].ip_id = k + 0x4000;
            ROHC_LOG_INFO("static ip_id case, set ip_id %d(0x%x)\n",
                          ctx->cfg[k].ip_id,
                          ctx->cfg[k].ip_id);
        }

        strncpy(src_addr, inet_ntoa(*(struct in_addr *)(char *)(&ctx->cfg[k].src_addr)), 32);
        strncpy(dst_addr, inet_ntoa(*(struct in_addr *)(char *)(&ctx->cfg[k].dst_addr)), 32);

        ROHC_LOG_INFO("###stream [%d]srcIP %s, DstIp %s, SrcPort %d, dstPort %d\n",
                      k, src_addr, dst_addr, ctx->cfg[k].src_port, ctx->cfg[k].dst_port);

    }

    return ctx;
}

static void test_deinit(struct rohc_comp_test_context *ctx)
{
    if (ctx == NULL)
    {
        return;
    }

    rohc_release_compressor(ctx->comp_idx);

    cache_file_write(ctx, CACHE_DUMP_FLUSH, NULL);
    if (ctx->fp_udp_ip_dump)
    {
        fflush(ctx->fp_udp_ip_dump);
        fclose(ctx->fp_udp_ip_dump);
    }

    if (ctx->fp_rohc_dump)
    {
        fflush(ctx->fp_rohc_dump);
        fclose(ctx->fp_rohc_dump);
    }

    if (ctx->fp_rohc_pkt_len_dump)
    {
        fflush(ctx->fp_rohc_pkt_len_dump);
        fclose(ctx->fp_rohc_pkt_len_dump);
    }

    if (ctx->fp_pcap_dump)
    {
        fflush(ctx->fp_pcap_dump);
        fclose(ctx->fp_pcap_dump);
    }

    free(ctx);

    ROHC_LOG_INFO("%s done\n", __FUNCTION__);
}

static void test_rohc_compress(const struct rohc_test_config  test_cfg)
{
    static uint8_t g_ip_buf[IP_PACKET_SIZE_MAX];
    static uint8_t g_payload_buf[IP_PACKET_PAYLOAD_MAX];
    static uint8_t g_rohc_buf[ROHC_PACKET_SIZE_MAX];

    rohc_buf_t ip_pkt;
    rohc_buf_t rohc_pkt;
    rohc_buf_t rohc_len_rec;

    rohc_comp_packet_info_t rohc_info;
    rohc_status_t ret;

    char rohc_pkt_len_rec_str[32];
    uint32_t i;

    struct rohc_comp_test_context *ctx = test_init(test_cfg);

    if (ctx == NULL)
    {
        ROHC_LOG_ERROR("init test context fail\n");
        return;
    }

    rohc_pkt = rohc_buf_init(g_rohc_buf, ROHC_PACKET_SIZE_MAX, true);

    srand((unsigned int)time(NULL));

    for (i = 0; i < test_cfg.send_round; ++i)
    {
        uint16_t k = 0;
        ROHC_LOG_TRACE("start rohc comp for all ip stream round %d\n", i);

        for (k = 0; k < test_cfg.strm_num; ++k)
        {
            uint16_t payload_len;
            uint16_t ip_tot_len;

            memset(g_payload_buf, 0, IP_PACKET_PAYLOAD_MAX);

            payload_len = gen_udp_ipv4_payload(g_payload_buf,
                                               test_cfg.payload_min,
                                               test_cfg.payload_max,
                                               false,
                                               true);

            if (payload_len >= IP_PACKET_PAYLOAD_MAX)
            {
                ROHC_LOG_WARN("warnning!!!payload length too large %d, max %d\n",
                              payload_len, IP_PACKET_PAYLOAD_MAX);
                continue;
            }

            ip_tot_len = payload_len + sizeof(ipv4_header_t) + sizeof(udp_header_t);
            build_udp_ip_headers(g_ip_buf,
                                 g_payload_buf,
                                 payload_len,
                                 ctx->cfg[k].src_addr,
                                 ctx->cfg[k].dst_addr,
                                 ctx->cfg[k].src_port,
                                 ctx->cfg[k].dst_port,
                                 ctx->cfg[k].ip_id);

            switch (test_cfg.ip_id_behave)
            {
            case IP_ID_SEQUENTIAL_INC:
                ++ctx->cfg[k].ip_id;
                break;
            case IP_ID_SEQUENTIAL_JUMP:
                ctx->cfg[k].ip_id += 1 + (uint16_t)(rand() % 5);
                break;
            case IP_ID_RANDOM:
                ctx->cfg[k].ip_id = (uint16_t)(rand() % 65535);
            case IP_ID_STATIC_IP_ID:
            default:
                break;
            }

            ROHC_LOG_DEBUG("strm[%d] gen ip packet[%d] len(%d)\n", (i + 1), (k + 1), ip_tot_len);

            ip_pkt = rohc_buf_init(g_ip_buf, ip_tot_len, false);

            cache_file_write(ctx, CACHE_DUMP_IP, &ip_pkt);

            pack_pcap_packet(ctx, ip_pkt);

            rohc_buf_clear(&rohc_pkt);
            ret = rohc_compress(ctx->comp_idx, &rohc_pkt, &rohc_info, ip_pkt);

            if (ret != ROHC_STATUS_OK)
            {
                ROHC_LOG_ERROR("rohc compress ret %d fail\n", (uint32_t)ret);
            }

            ROHC_LOG_DEBUG("last rohc pkt info: "
                           "SN (%d), ip_id %d, pktType %d, cid %d, cid type%d, static size %d, dyn size%d\n",
                           rohc_info.SN,
                           rohc_info.ip_id,
                           rohc_info.packet_type,
                           rohc_info.cid,
                           rohc_info.cid_type,
                           rohc_info.dynamic_context_size,
                           rohc_info.static_context_size);

            if (rohc_pkt.len > 8)
            {
                ROHC_LOG_TRACE("dump 8 bytes: 0x%02x%02x%02x%02x%02x%02x%02x%02x\n",
                               rohc_buf_get_value(rohc_pkt, 0),
                               rohc_buf_get_value(rohc_pkt, 1),
                               rohc_buf_get_value(rohc_pkt, 2),
                               rohc_buf_get_value(rohc_pkt, 3),
                               rohc_buf_get_value(rohc_pkt, 4),
                               rohc_buf_get_value(rohc_pkt, 5),
                               rohc_buf_get_value(rohc_pkt, 6),
                               rohc_buf_get_value(rohc_pkt, 7));
            }

            if ((i > test_cfg.sim_pkt_loss_start_pkt) && (i < test_cfg.sim_pkt_loss_end_pkt))
            {
                ROHC_LOG_INFO("strm[%d] simulate packet loss, drop packet[%d]\n", k, i);
                continue;
            }

            cache_file_write(ctx, CACHE_DUMP_ROHC, &rohc_pkt);

            if (snprintf(rohc_pkt_len_rec_str, 7, "%d\n", (uint32_t)rohc_pkt.len) > 0)
            {
                printf("rohc pkt len %d\n", rohc_pkt.len);
                rohc_len_rec = rohc_buf_init((uint8_t *)rohc_pkt_len_rec_str,
                                             strlen(rohc_pkt_len_rec_str),
                                             false);

                cache_file_write(ctx, CACHE_DUMP_ROHC_LEN, &rohc_len_rec);
            }
        }
    }

    test_deinit(ctx);
}

int main(int argc, char *argv[])
{
    struct rohc_test_config  test_cfg = {
        ROHC_SMALL_CID,
        1, 10,              // stream number, packet count
        1, 1024,            //[min, max] payload length
        IP_ID_SEQUENTIAL_INC,
        0, 0,               // (drop start, drop end)
    };

    int option;

    while ((option = getopt(argc, argv, "c:n:r:i:s:e:x:l:h")) != -1)
    {
        switch (option)
        {
        case 'c':
            test_cfg.cid_type = (rohc_cid_type_t)atoi(optarg);
            break;
        case 'n':
            test_cfg.strm_num = (uint8_t)atoi(optarg);
            break;
        case 'r':
            test_cfg.send_round = (uint32_t)atoi(optarg);
            break;
        case 'i':
            test_cfg.ip_id_behave = (IP_ID_BEHAVIOR_E)atoi(optarg);
            break;
        case 's':
            test_cfg.sim_pkt_loss_start_pkt = (uint32_t)atoi(optarg);
            break;
        case 'e':
            test_cfg.sim_pkt_loss_end_pkt = (uint32_t)atoi(optarg);
            break;
        case 'x':
            test_cfg.payload_max = (uint16_t)atoi(optarg);
            break;
        case 'l':
            test_cfg.payload_min = (uint16_t)atoi(optarg);
            break;
        case 'h':
            printf("\t-c [CID type 0-large cid, 1-small cid]\n");
            printf("\t-n [stream number, 1 ~128]\n");
            printf("\t-r [send_round(i.e. packet num) for each stream]\n");
            printf("\t-i [ip-id increase behavior: 0-inc1, 1- inc jump, 2-sid, 3-random]\n");
            printf("\t-s [simulate packet loss count start packet]\n");
            printf("\t-e [simulate packet loss count end packet]\n");
            printf("\t-x [max playload length of udp_ip packet]\n");
            printf("\t-l [min playload length of udp_ip packet]\n");
            return 1;
        }
    }

    ROHC_LOG_INFO("rohc comp test: cid_type %d, strm num %d, round %d ip_id behavior %d,\n"
                  "sim packet loss:(%d, %d), payload length range[%d, %d]\n",
                  test_cfg.cid_type,
                  test_cfg.strm_num,
                  test_cfg.send_round,
                  test_cfg.ip_id_behave,
                  test_cfg.sim_pkt_loss_start_pkt,
                  test_cfg.sim_pkt_loss_end_pkt,
                  test_cfg.payload_min,
                  test_cfg.payload_max);

    test_rohc_compress(test_cfg);

    return 1;
}
